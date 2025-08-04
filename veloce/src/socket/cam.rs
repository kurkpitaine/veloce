use core::fmt;

use crate::common::{PotiFix, PotiFixError, PotiMode, PotiPathPoint, PotiPositionHistory};
use crate::config::BTP_MAX_PL_SIZE;
use crate::iface::packet::GeonetPacket;
use crate::iface::{Congestion, Context, ContextMeta};
use crate::network::{GnCore, Transport};

#[cfg(feature = "proto-security")]
use crate::security::{
    permission::{Permission, AID},
    ssp::{
        cam::{CamPermission, CamSsp},
        SspTrait,
    },
};
use crate::socket::{self, btp::SocketB as BtpBSocket, PollAt};
use crate::time::{Duration, Instant, TAI2004};
use crate::types::{Heading, Pseudonym, Speed};
use crate::wire::{self, ports, GnTrafficClass};

use crate::storage::PacketBuffer;
use crate::wire::{EthernetAddress, StationType};

use uom::si::angle::degree;
use uom::si::f64::Length;
use uom::si::length::meter;
use uom::si::velocity::meter_per_second;
use veloce_asn1::defs::etsi_messages_r2::cam__pdu__descriptions as cam;
use veloce_asn1::defs::etsi_messages_r2::etsi__its__cdd as cdd;
use veloce_asn1::prelude::rasn::{self, error::DecodeError, types::SequenceOf};

use super::btp::{Indication, RecvError, Request};

/// CAM module error type.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    Buffer(RecvError),
    Asn1(DecodeError),
    Fix(PotiFixError),
    RateLimited,
    Overriden(TxPeriodOverride),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Buffer(b) => write!(f, "Buffer: {}", b),
            Error::Asn1(d) => write!(f, "Asn1: {}", d),
            Error::Fix(e) => write!(f, "GNSS fix: {}", e),
            Error::RateLimited => write!(f, "Rate limited"),
            Error::Overriden(p) => write!(f, "Overriden tx period: {}", p),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Maximum number of CAMs in receive buffer.
const CAM_RX_BUF_NUM: usize = 5;
/// Maximum size of data in receive buffer.
const CAM_RX_BUF_SIZE: usize = CAM_RX_BUF_NUM * BTP_MAX_PL_SIZE;
/// Maximum allowed number of trace points in CAMs. pCamTraceMaxPoints in C2C Vehicle Profile spec.
const CAM_TRACE_MAX_POINTS: usize = 23;
/// The default and maximum value of N_GenCam shall be 3
const CAM_N_GEN_CAM: u8 = 3;
/// Minimum allowed period between two CAM messages.
const CAM_GEN_CAM_MIN: Duration = Duration::from_millis(100);
/// Maximum allowed period between two CAM messages.
const CAM_GEN_CAM_MAX: Duration = Duration::from_millis(1000);
/// CAM generation check period. Shall be equal or less than CAM_GEN_CAM_MIN.
const CAM_CHECK_CAM_GEN: Duration = CAM_GEN_CAM_MIN;
/// Retransmission delay for the Low Frequency Container of a CAM message.
const CAM_LF_RETRANSMIT_DELAY: Duration = Duration::from_millis(500);

/// CAM transmission period override parameters.
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxPeriodOverride {
    /// Transmission period.
    period: Duration,
    /// Number of generations where the period is overridden.
    num_tx: u8,
}

impl fmt::Display for TxPeriodOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "period: {}, num_tx: {}", self.period, self.num_tx)
    }
}

/// Rx/Tx callback type.
type RxTxCallback = Box<dyn FnMut(&[u8], &cam::CAM)>;

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
    /// Last instant at which a CAM was transmitted.
    prev_cam_at: Instant,
    /// Last instant at which a CAM with a low dynamic container
    /// was successfully transmitted to the lower layer.
    prev_low_dynamic_at: Instant,
    /// Previous position. Used to check if the CAM generation trigger conditions are met.
    prev_pos: PotiPathPoint,
    /// Number of "accelerated" CAM generations.
    n_gen_cam: u8,
    /// CAM transmission period override parameters.
    generation_override: Option<TxPeriodOverride>,
    /// Function to call when a CAM message is successfully received.
    rx_callback: Option<RxTxCallback>,
    /// Function to call when a CAM message is successfully transmitted to the lower layer.
    /// Keep in mind some mechanisms, like congestion control, may silently drop the message
    /// at a lower layer before any transmission occur.
    tx_callback: Option<RxTxCallback>,
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

impl<'a> Default for Socket<'a> {
    fn default() -> Self {
        Self::new()
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
            retransmit_delay: CAM_GEN_CAM_MAX,
            prev_low_dynamic_at: Instant::ZERO,
            prev_cam_at: Instant::ZERO,
            prev_pos: PotiPathPoint::default(),
            n_gen_cam: 0,
            generation_override: None,
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

    /// Override the transmission `period` of CAM messages for a number of generations `num_tx`.
    /// Enables ITS applications to increase the CAM generation frequency for a limited time.
    /// This value takes precedence over motion triggering, but not over the DCC rate limiting.
    /// Returns an error if there is already an existing override with a lower period.
    pub fn override_tx_period(
        &mut self,
        core: &GnCore,
        period: Duration,
        num_tx: u8,
    ) -> Result<(), Error> {
        let period = period.clamp(CAM_GEN_CAM_MIN, CAM_GEN_CAM_MAX);

        if let Some(params) = &mut self.generation_override {
            if params.period < period {
                return Err(Error::Overriden(params.to_owned()));
            } else {
                *params = TxPeriodOverride { period, num_tx };
            }
        }

        // Check for transmission.
        let elapsed = core.now - self.prev_cam_at;
        if elapsed > period {
            self.retransmit_at = core.now;
        } else {
            let wait = period - elapsed;
            self.retransmit_at = core.now + wait;
        }

        self.retransmit_delay = period;

        Ok(())
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
                net_warn!("Cannot process CAM: {}", e);
                return;
            }
        };

        let decoded = match rasn::uper::decode::<cam::CAM>(buf) {
            Ok(d) => d,
            Err(e) => {
                net_warn!("Cannot process CAM: {}", e);
                return;
            }
        };

        #[cfg(feature = "proto-security")]
        if srv.core.security.is_some() {
            let authorized = if let Permission::CAM(p) = &_ind.its_aid {
                Self::check_permissions(&decoded, &p.ssp)
            } else {
                net_warn!(
                    "Cannot process CAM - unexpected permission type. Got {:?}",
                    _ind.its_aid
                );
                return;
            };

            if !authorized {
                net_warn!("Cannot process CAM - not authorized");
                return;
            }
        }

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
            (EthernetAddress, GeonetPacket),
        ) -> Result<(), E>,
    {
        if !self.inner.is_open() {
            match self.inner.bind(ports::CAM) {
                Ok(_) => net_trace!("CAM socket bind"),
                Err(e) => {
                    net_error!("CAM socket bind error: {}", e);
                    return Ok(());
                }
            }
        }

        let now = srv.core.now;
        if self.retransmit_at > now {
            return Ok(());
        }

        let ego_station_type = srv.core.station_type();
        let (ego_position, ego_position_history) = srv.core.position_and_history();
        let now_tai2004 = TAI2004::from_unix_instant(now);
        let diff_now_pos = now_tai2004 - ego_position.timestamp;

        if let PotiMode::NoFix | PotiMode::Lost = ego_position.mode {
            net_debug!("CAM cannot be sent: no position fix");
            self.retransmit_at = now + self.retransmit_delay;
            return Ok(());
        };

        if ego_station_type != StationType::RoadSideUnit && !ego_position.confidence_available() {
            net_debug!("CAM cannot be sent: required position confidence values unavailable");
            self.retransmit_at = now + self.retransmit_delay;
            return Ok(());
        }

        let ego_path_point = match PotiPathPoint::try_from(&ego_position) {
            Ok(p) => p,
            Err(e) => {
                net_debug!("CAM cannot be sent: cannot create path point: {}", e);
                return Ok(());
            }
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

        let elapsed = now - self.prev_cam_at;
        let gen_cam_dcc = srv
            .congestion_control
            .controller
            .inner()
            .tx_interval()
            .clamp(CAM_GEN_CAM_MIN, CAM_GEN_CAM_MAX);

        // Rate limited by DCC.
        if elapsed < gen_cam_dcc {
            net_debug!("CAM cannot be sent: DCC rate limited");
            return Ok(());
        }

        // Fill CAM.
        let cam = self.fill_cam(
            now_tai2004,
            ego_station_type,
            ego_position,
            ego_position_history,
            srv.core.pseudonym(),
        );

        if let Some(params) = &mut self.generation_override {
            params.num_tx -= 1;
            self.retransmit_at = now + params.period;

            // Reset parameters if all generations have been sent.
            if params.num_tx == 0 {
                self.generation_override = None;
                self.retransmit_delay = CAM_GEN_CAM_MAX;

                if ego_station_type == StationType::RoadSideUnit {
                    self.retransmit_at = now + self.retransmit_delay;
                } else {
                    self.retransmit_at = now + CAM_CHECK_CAM_GEN;
                }
            }
        } else if ego_station_type == StationType::RoadSideUnit {
            self.retransmit_delay = CAM_GEN_CAM_MAX;
            self.retransmit_at = now + self.retransmit_delay;
        } else {
            self.retransmit_at = now + CAM_CHECK_CAM_GEN;
            let motion_trigger = self.motion_trigger(ego_path_point);

            if motion_trigger || elapsed >= self.retransmit_delay {
                if motion_trigger {
                    self.retransmit_delay =
                        (now - self.prev_cam_at).clamp(CAM_GEN_CAM_MIN, CAM_GEN_CAM_MAX);
                    self.n_gen_cam = CAM_N_GEN_CAM;
                }
            } else {
                net_debug!("CAM cannot be sent: wait time not exceeded");
                return Ok(());
            }
        }

        // TODO: FixMe
        let Ok(raw_cam) = rasn::uper::encode(&cam) else {
            net_error!("CAM content invalid");
            return Ok(());
        };

        #[cfg(feature = "proto-security")]
        let permission = if let Some(sec) = &srv.core.security {
            // Check if we have permission to send this CAM.
            let sign_permissions = match sec.application_permissions() {
                Ok(p) => p,
                Err(e) => {
                    net_error!(
                        "CAM cannot be sent: cannot get application permissions: {}",
                        e
                    );
                    return Ok(());
                }
            };

            let mut cam_ssps: Vec<CamSsp> = sign_permissions
                .into_iter()
                .filter_map(|p| {
                    if p.aid() == AID::CA {
                        let ssp = *p.cam_or_panic();
                        // Filter future versions
                        (ssp.is_v1() || ssp.is_v2()).then_some(ssp)
                    } else {
                        None
                    }
                })
                .collect();

            if cam_ssps.is_empty() {
                net_error!("CAM cannot be sent: unauthorized");
                return Ok(());
            }

            // Sort permissions by descending version value.
            cam_ssps.sort_by(|a, b| b.cmp(a));

            let ssp = if cam_ssps[0].is_v1() {
                CamSsp::new_v1()
            } else {
                CamSsp::new_v2()
            };

            Permission::CAM(ssp.into())
        } else {
            Default::default()
        };

        let meta = Request {
            transport: Transport::SingleHopBroadcast,
            max_lifetime: Duration::from_millis(1000),
            traffic_class: Self::traffic_class(),
            #[cfg(feature = "proto-security")]
            its_aid: permission,
            ..Default::default()
        };

        // TODO: FixMe
        match self.inner.send_slice(&raw_cam, meta) {
            Ok(_) => {
                net_trace!("CAM slice sent");
            }
            Err(e) => {
                net_error!("CAM slice cannot be sent: {}", e);
                return Ok(());
            }
        }

        self.inner.dispatch(cx, srv, emit).inspect(|_| {
            if self.has_low_dynamic_container(&cam) {
                self.prev_low_dynamic_at = now;
            }

            self.prev_cam_at = now;
            self.prev_pos = ego_path_point;

            if self.n_gen_cam > 0 {
                self.n_gen_cam -= 1;

                // n_gen_cam reached 0. Reset retransmit delay to the maximum value.
                if self.n_gen_cam == 0 {
                    self.retransmit_delay = CAM_GEN_CAM_MAX;
                }
            }

            if let Some(tx_cb) = &mut self.tx_callback {
                tx_cb(&raw_cam, &cam);
            };
        })
    }

    pub(crate) fn poll_at(&self, cx: &Context) -> PollAt {
        self.inner.poll_at(cx).min(PollAt::Time(self.retransmit_at))
    }

    /// Get the traffic class for CAM messages.
    #[inline]
    const fn traffic_class() -> GnTrafficClass {
        // C2C Consortium Vehicle C-ITS station profile, requirement RS_BSP_292.
        // pCamTrafficClass = 2.
        GnTrafficClass::new(false, 2)
    }

    /// Check if a CAM generation should be triggered based on the station motion.
    #[inline]
    fn motion_trigger(&self, pos: PotiPathPoint) -> bool {
        let prev_hdg = self.prev_pos.heading;
        let prev_spd = self.prev_pos.speed;
        let fix_hdg = pos.heading;
        let fix_spd = pos.speed;

        if (prev_hdg - fix_hdg).abs() > Heading::new::<degree>(4.0) {
            return true;
        }

        if (prev_spd - fix_spd).abs() > Speed::new::<meter_per_second>(0.5) {
            return true;
        }

        if self.prev_pos.distance_to(&pos).abs() > Length::new::<meter>(4.0) {
            return true;
        }

        false
    }

    /// Fills a CAM message with basic content
    #[inline]
    fn fill_cam(
        &self,
        timestamp: TAI2004,
        station_type: StationType,
        fix: PotiFix,
        history: PotiPositionHistory,
        pseudo: Pseudonym,
    ) -> cam::CAM {
        use cam::*;
        use cdd::*;
        use rasn::types::FixedBitString;
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
                let ext_lights = FixedBitString::default();
                let mut path_history = history
                    .as_etsi_path(&fix)
                    .unwrap_or_else(|_| cdd::Path(SequenceOf::new()));

                // Truncate the path history to the maximum number of points.
                // C2C Consortium Vehicle C-ITS station profile, requirement RS_BSP_512.
                path_history.0.truncate(CAM_TRACE_MAX_POINTS);

                let vehicle_lf = BasicVehicleContainerLowFrequency {
                    vehicle_role: VehicleRole::default,
                    exterior_lights: ExteriorLights(ext_lights),
                    path_history,
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

    /// Check if the CAM contains a low dynamic container.
    fn has_low_dynamic_container(&self, cam: &cam::CAM) -> bool {
        cam.cam.cam_parameters.low_frequency_container.is_some()
            || cam.cam.cam_parameters.special_vehicle_container.is_some()
    }

    #[cfg(feature = "proto-security")]
    /// Check if the CAM content is authorized vs `permission`.
    fn check_permissions(cam: &cam::CAM, permission: &CamSsp) -> bool {
        use veloce_asn1::defs::etsi_messages_r2::etsi__its__cdd::TrafficRule;
        let mut expected = CamSsp::new_v2();

        match &cam.cam.cam_parameters.high_frequency_container {
            cam::HighFrequencyContainer::basicVehicleContainerHighFrequency(hfc) => {
                if hfc.cen_dsrc_tolling_zone.as_ref().is_some() {
                    expected.set_permission(
                        CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU,
                    )
                }
            }
            cam::HighFrequencyContainer::rsuContainerHighFrequency(hfc) => {
                if hfc.protected_communication_zones_rsu.as_ref().is_some() {
                    expected.set_permission(
                        CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU,
                    )
                }
            }
            _ => {}
        }

        if let Some(svc) = &cam.cam.cam_parameters.special_vehicle_container {
            match svc {
                cam::SpecialVehicleContainer::publicTransportContainer(_) => {
                    expected.set_permission(CamPermission::PublicTransport)
                }
                cam::SpecialVehicleContainer::specialTransportContainer(_) => {
                    expected.set_permission(CamPermission::SpecialTransport)
                }
                cam::SpecialVehicleContainer::dangerousGoodsContainer(_) => {
                    expected.set_permission(CamPermission::DangerousGoods)
                }
                cam::SpecialVehicleContainer::roadWorksContainerBasic(rc) => {
                    expected.set_permission(CamPermission::Roadwork);
                    if rc.closed_lanes.as_ref().is_some() {
                        expected.set_permission(CamPermission::ClosedLanes);
                    }
                }
                cam::SpecialVehicleContainer::rescueContainer(_) => {
                    expected.set_permission(CamPermission::Rescue)
                }
                cam::SpecialVehicleContainer::emergencyContainer(ec) => {
                    expected.set_permission(CamPermission::Emergency);
                    if let Some(ep) = ec.emergency_priority.as_ref() {
                        if ep.0.get(0).is_some() {
                            expected.set_permission(CamPermission::RequestForRightOfWay);
                        }
                        if ep.0.get(1).is_some() {
                            expected.set_permission(
                                CamPermission::RequestForFreeCrossingAtATrafficLight,
                            );
                        }
                    }
                }
                cam::SpecialVehicleContainer::safetyCarContainer(scc) => {
                    expected.set_permission(CamPermission::SafetyCar);
                    if scc.speed_limit.as_ref().is_some() {
                        expected.set_permission(CamPermission::SpeedLimit);
                    }

                    match scc.traffic_rule {
                        Some(TrafficRule::noPassing) => {
                            expected.set_permission(CamPermission::NoPassing)
                        }
                        Some(TrafficRule::noPassingForTrucks) => {
                            expected.set_permission(CamPermission::NoPassingForTrucks)
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        permission.contains_permissions_of(&expected)
    }
}
