use core::fmt;

use crate::common::{PotiFix, PotiMode};
use crate::config::BTP_MAX_PL_SIZE;
use crate::iface::{Congestion, Context, ContextMeta};
use crate::network::{GnCore, Transport};

use crate::socket::{self, btp::SocketB as BtpBSocket, PollAt};
use crate::time::{Duration, Instant, TAI2004};
use crate::types::Pseudonym;
use crate::wire::{self, ports, GeonetVariant, GnTrafficClass};

use crate::storage::PacketBuffer;
use crate::wire::{EthernetAddress, StationType};

use veloce_asn1::defs::c_a_m__p_d_u__descriptions as cam;
use veloce_asn1::defs::e_t_s_i__i_t_s__c_d_d as cdd;
use veloce_asn1::prelude::rasn::{self, error::DecodeError, types::SequenceOf};

use super::btp::{Indication, RecvError, Request};

/// Error returned by [`Socket::recv`]
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CamError {
    Buffer(RecvError),
    Asn1(DecodeError),
}

impl core::fmt::Display for CamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CamError::Buffer(b) => write!(f, "Buffer: {}", b),
            CamError::Asn1(d) => write!(f, "Asn1: {}", d),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CamError {}

/// Maximum number of CAMs in receive buffer.
const CAM_RX_BUF_NUM: usize = 5;
/// Maximum size of data in receive buffer.
const CAM_RX_BUF_SIZE: usize = CAM_RX_BUF_NUM * BTP_MAX_PL_SIZE;
/// Retransmission delay for a mobile station type.
const CAM_VEH_RETRANSMIT_DELAY: Duration = Duration::from_millis(100);
/// Retransmission delay for an RSU station type.
const CAM_RSU_RETRANSMIT_DELAY: Duration = Duration::from_millis(1000);
/// Retransmission delay for the Low Frequency Container of a CAM message.
const CAM_LF_RETRANSMIT_DELAY: Duration = Duration::from_millis(500);

/// An ETSI CAM type socket.
///
/// A CAM socket executes the Cooperative Awareness protocol,
/// as described in ETSI TS 103 900 V2.1.1 (2023-11).
///
/// The socket implement the CAM messages transmission, provides
/// a list of received CAM accessible with [Socket::recv] and a
/// callback registration mechanism for CAM Rx/Tx event.
///
/// Transmission of CAMs is automatic. Therefore, the socket must be
/// fed periodically with a fresh position and time to ensure
/// correct transmission rate and data freshness.
pub struct Socket<'a> {
    /// BTP layer.
    inner: BtpBSocket<'a>,
    /// Instant at which a new CAM should be transmitted.
    retransmit_at: Instant,
    /// Delay of retransmission.
    retransmit_delay: Duration,
    /// Last instant at which a CAM with a low dynamic container
    /// was successfully transmitted to the lower layer.
    prev_low_dynamic_at: Instant,
    /// Function to call when a CAM message is successfully received.
    rx_callback: Option<Box<dyn FnMut(&[u8], &cam::CAM)>>,
    /// Function to call when a CAM message is successfully transmitted to the lower layer.
    /// Keep in mind some mechanisms, like congestion control, may silently drop the message
    /// at a lower layer before any transmission occur.
    tx_callback: Option<Box<dyn FnMut(&[u8], &cam::CAM)>>,
}

impl fmt::Debug for Socket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket")
            .field("inner", &self.inner)
            .field("retransmit_at", &self.retransmit_at)
            .field("retransmit_delay", &self.retransmit_delay)
            .field("prev_low_dynamic_at", &self.prev_low_dynamic_at)
            .finish_non_exhaustive()
    }
}

impl<'a> Socket<'a> {
    /// Create a CAM socket.
    pub fn new() -> Socket<'a> {
        // Create inner BTP-B socket.
        let inner_rx_buffer = PacketBuffer::new(
            vec![socket::btp::b::RxPacketMetadata::EMPTY; CAM_RX_BUF_NUM],
            vec![0; CAM_RX_BUF_SIZE],
        );

        let inner_tx_buffer = PacketBuffer::new(
            vec![socket::btp::b::TxPacketMetadata::EMPTY],
            vec![0; BTP_MAX_PL_SIZE],
        );
        let inner = socket::btp::SocketB::new(inner_rx_buffer, inner_tx_buffer);

        Socket {
            inner,
            retransmit_at: Instant::ZERO,
            retransmit_delay: CAM_VEH_RETRANSMIT_DELAY,
            prev_low_dynamic_at: Instant::ZERO,
            rx_callback: None,
            tx_callback: None,
        }
    }

    /// Register a callback for a CAM reception event.
    /// First callback parameter contains the CAM message serialized as UPER.
    /// Second callback parameter contains the raw CAM message struct.
    pub fn register_recv_callback(&mut self, rx_cb: impl FnMut(&[u8], &cam::CAM) + 'static) {
        self.rx_callback = Some(Box::new(rx_cb));
    }

    /// Register a callback for a CAM transmission event.
    /// First callback parameter contains the CAM message serialized as UPER.
    /// Second callback parameter contains the raw CAM message struct.
    /// Keep in mind some mechanisms, like congestion control, may silently drop the message
    /// at a lower layer before any transmission occur.
    pub fn register_send_callback(&mut self, tx_cb: impl FnMut(&[u8], &cam::CAM) + 'static) {
        self.tx_callback = Some(Box::new(tx_cb));
    }

    /// Query whether the CAM socket accepts the segment.
    #[must_use]
    pub(crate) fn accepts(
        &self,
        cx: &mut Context,
        srv: &ContextMeta,
        repr: &wire::BtpBRepr,
    ) -> bool {
        self.inner.accepts(cx, srv, repr)
    }

    /// Process a newly received CAM.
    /// Check if the socket must handle the segment with [Socket::accepts] before calling this function.
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        srv: &ContextMeta,
        indication: Indication,
        payload: &[u8],
    ) {
        self.inner.process(cx, srv, indication, payload);

        if !self.inner.can_recv() {
            return;
        }

        let (buf, _ind) = match self.inner.recv() {
            Ok(d) => d,
            Err(e) => {
                net_debug!("Cannot process CAM: {}", e);
                return;
            }
        };

        let decoded = match rasn::uper::decode::<cam::CAM>(buf) {
            Ok(d) => d,
            Err(e) => {
                net_debug!("Cannot process CAM: {}", e);
                return;
            }
        };

        if let Some(rx_cb) = &mut self.rx_callback {
            rx_cb(buf, &decoded);
        };
    }

    pub(crate) fn dispatch<F, E>(
        &mut self,
        cx: &mut Context,
        srv: ContextMeta,
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut Context,
            &mut GnCore,
            &mut Congestion,
            (EthernetAddress, GeonetVariant, &[u8]),
        ) -> Result<(), E>,
    {
        if !self.inner.is_open() {
            match self.inner.bind(ports::CAM) {
                Ok(_) => net_trace!("CAM socket bind"),
                Err(e) => {
                    net_trace!("CAM socket bind error: {}", e);
                    return Ok(());
                }
            }
        }

        let now = srv.core.now;
        if self.retransmit_at > now {
            return Ok(());
        }

        let ego_station_type = srv.core.station_type();
        let ego_position = srv.core.position();
        let now_tai2004 = TAI2004::from_unix_instant(now);
        let diff_now_pos = now_tai2004 - ego_position.timestamp;

        if let PotiMode::NoFix = ego_position.mode {
            net_debug!("CAM cannot be sent: no position fix");
            self.retransmit_at = now + self.retransmit_delay;
            return Ok(());
        };

        if diff_now_pos >= Duration::from_millis(32767) {
            net_debug!(
                "CAM cannot be sent: now={} - fix time={} = {} >= 32767ms",
                now_tai2004.total_millis(),
                ego_position.timestamp.total_millis(),
                diff_now_pos.total_millis()
            );
            self.retransmit_at = now + self.retransmit_delay;
            return Ok(());
        }

        // Fill CAM.
        let cam = self.fill_cam(
            now_tai2004,
            ego_station_type,
            ego_position,
            srv.core.pseudonym(),
        );

        // T_GenCam_Dcc
        let _gen_cam_dcc = srv.congestion_control.controller.inner().tx_interval();

        // TODO: Make retransmit delay dynamic for non-rsu station types.
        // ie: check position, speed and heading vs values in prev cam.
        if ego_station_type == StationType::RoadSideUnit {
            self.retransmit_delay = CAM_RSU_RETRANSMIT_DELAY;
        } else {
            self.retransmit_delay = CAM_VEH_RETRANSMIT_DELAY;
        }

        self.retransmit_at = now + self.retransmit_delay;

        // TODO: FixMe
        let Ok(raw_cam) = rasn::uper::encode(&cam) else {
            net_trace!("CAM content invalid");
            return Ok(());
        };

        let meta = Request {
            transport: Transport::SingleHopBroadcast,
            max_lifetime: Duration::from_millis(1000),
            traffic_class: GnTrafficClass::new(false, 2), // pCamTrafficClass in C2C vehicle profile.
            ..Default::default()
        };

        // TODO: FixMe
        let Ok(_) = self.inner.send_slice(&raw_cam, meta) else {
            net_trace!("CAM slice cannot be sent");
            return Ok(());
        };

        self.inner.dispatch(cx, srv, emit).map(|res| {
            if self.has_low_dynamic_container(&cam) {
                self.prev_low_dynamic_at = now;
            }

            if let Some(tx_cb) = &mut self.tx_callback {
                tx_cb(&raw_cam, &cam);
            };

            res
        })
    }

    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        self.inner.poll_at(cx).min(PollAt::Time(self.retransmit_at))
    }

    /// Fills a CAM message with basic content
    fn fill_cam(
        &self,
        timestamp: TAI2004,
        station_type: StationType,
        fix: PotiFix,
        pseudo: Pseudonym,
    ) -> cam::CAM {
        use cam::*;
        use cdd::*;
        use rasn::types::BitString;
        use wire::geonet::StationType as VeloceStationType;

        let header = ItsPduHeader::new(OrdinalNumber1B(2), MessageId(2), StationId(pseudo.0));

        let alt = cdd::Altitude::new(
            fix.position.altitude_value(),
            fix.confidence.altitude_confidence(),
        );

        let pos_confidence = PositionConfidenceEllipse::new(
            fix.confidence.position.semi_major_axis_length(),
            fix.confidence.position.semi_minor_axis_length(),
            fix.confidence.position.semi_minor_orientation_angle(),
        );
        let ref_pos = ReferencePositionWithConfidence::new(
            fix.position.latitude_value(),
            fix.position.longitude_value(),
            pos_confidence,
            alt,
        );
        let basic_container = BasicContainer::new(station_type.into(), ref_pos);

        // High frequency container.
        let hf_container = match station_type {
            VeloceStationType::RoadSideUnit => HighFrequencyContainer::rsuContainerHighFrequency(
                RSUContainerHighFrequency::new(None),
            ),
            _ => {
                let vehicle_hf = BasicVehicleContainerHighFrequency {
                    heading: Heading {
                        heading_value: fix.motion.heading_value(),
                        heading_confidence: fix.confidence.heading_confidence(),
                    },
                    speed: Speed {
                        speed_value: fix.motion.speed_value(),
                        speed_confidence: fix.confidence.speed_confidence(),
                    },
                    drive_direction: DriveDirection::unavailable,
                    vehicle_length: VehicleLength {
                        vehicle_length_value: VehicleLengthValue(1023),
                        vehicle_length_confidence_indication:
                            VehicleLengthConfidenceIndication::unavailable,
                    },
                    vehicle_width: VehicleWidth(62),
                    longitudinal_acceleration: AccelerationComponent {
                        value: AccelerationValue(161),
                        confidence: AccelerationConfidence(102),
                    },
                    curvature: Curvature {
                        curvature_value: CurvatureValue(1023),
                        curvature_confidence: CurvatureConfidence::unavailable,
                    },
                    curvature_calculation_mode: CurvatureCalculationMode::unavailable,
                    yaw_rate: YawRate {
                        yaw_rate_value: YawRateValue(32767),
                        yaw_rate_confidence: YawRateConfidence::unavailable,
                    },
                    acceleration_control: None,
                    lane_position: None,
                    steering_wheel_angle: None,
                    lateral_acceleration: None,
                    vertical_acceleration: None,
                    performance_class: None,
                    cen_dsrc_tolling_zone: None,
                };

                HighFrequencyContainer::basicVehicleContainerHighFrequency(vehicle_hf)
            }
        };

        // Low frequency container
        let lf_container = match station_type {
            VeloceStationType::RoadSideUnit => None,
            _ if TAI2004::from_unix_instant(self.prev_low_dynamic_at) - timestamp
                >= CAM_LF_RETRANSMIT_DELAY =>
            {
                let ext_lights = BitString::from_slice(&[0u8]);
                let mut path_history = SequenceOf::new();
                path_history.push(PathPoint {
                    path_position: DeltaReferencePosition {
                        delta_latitude: DeltaLatitude(0),
                        delta_longitude: DeltaLongitude(0),
                        delta_altitude: DeltaAltitude(0),
                    },
                    path_delta_time: None,
                });

                let vehicle_lf = BasicVehicleContainerLowFrequency {
                    vehicle_role: VehicleRole::default,
                    exterior_lights: ExteriorLights(ext_lights),
                    path_history: Path(path_history),
                };

                Some(LowFrequencyContainer::basicVehicleContainerLowFrequency(
                    vehicle_lf,
                ))
            }
            _ => None,
        };

        let cam_params = CamParameters::new(basic_container, hf_container, lf_container, None);

        // Generation Delta Time is calculated differently for a RSU station.
        let gen_time = if let VeloceStationType::RoadSideUnit = station_type {
            GenerationDeltaTime((timestamp.total_millis() & 0xffff) as u16)
        } else {
            GenerationDeltaTime((fix.timestamp.total_millis() & 0xffff) as u16)
        };

        let coop_awareness = CamPayload::new(gen_time, cam_params);

        cam::CAM::new(header, coop_awareness)
    }

    fn has_low_dynamic_container(&self, cam: &cam::CAM) -> bool {
        cam.cam.cam_parameters.low_frequency_container.is_some()
            || cam.cam.cam_parameters.special_vehicle_container.is_some()
    }
}
