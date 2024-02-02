#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::{Context, ContextMeta};
use crate::network::{GnCore, Transport};

use crate::socket::{self, btp::SocketB as BtpBSocket, PollAt};
use crate::time::{Duration, Instant};
use crate::types::{tenth_of_microdegree, Pseudonym};
use crate::wire::{self, ports, GnTrafficClass};

use crate::storage::PacketBuffer;
use crate::wire::{EthernetAddress, GeonetRepr, StationType};

use rasn::error::DecodeError;
use veloce_asn1::c_a_m__p_d_u__descriptions as cam;
use veloce_asn1::e_t_s_i__i_t_s__c_d_d as cdd;

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
const CAM_RX_BUF_SIZE: usize = 4096;
/// Retransmission delay for a mobile station type.
const CAM_RETRANSMIT_DELAY: Duration = Duration::from_millis(100);
/// Retransmission delay for an RSU station type.
const CAM_RSU_RETRANSMIT_DELAY: Duration = Duration::from_millis(1000);

/// An ETSI CAM type socket.
///
/// A CAM socket executes the Cooperative Awareness protocol,
/// as described in ETSI TS 103 900 V2.1.1 (2023-11).
///
/// The socket implement the CAM messages transmission, and provides
/// a list of received CAM.
///
/// Transmission of CAMs is automatic. Therefore, the socket must be
/// fed periodically with a fresh position and time to ensure
/// correct transmission rate and data freshness.
#[derive(Debug)]
pub struct Socket<'a> {
    /// BTP layer.
    inner: BtpBSocket<'a>,
    /// Instant at which a new CAM should be transmitted.
    retransmit_at: Instant,
    /// Delay of retransmission.
    retransmit_delay: Duration,
}

impl<'a> Socket<'a> {
    /// Create a CAM socket.
    pub fn new() -> Socket<'a> {
        // Create inner BTP-B socket.
        let inner_rx_buffer = PacketBuffer::new(
            vec![socket::btp::b::RxPacketMetadata::EMPTY; CAM_RX_BUF_NUM],
            vec![0; CAM_RX_BUF_SIZE],
        );

        let inner_tx_buffer =
            PacketBuffer::new(vec![socket::btp::b::TxPacketMetadata::EMPTY], vec![0; 1024]);
        let inner = socket::btp::SocketB::new(inner_rx_buffer, inner_tx_buffer);

        Socket {
            inner,
            retransmit_at: Instant::ZERO,
            retransmit_delay: Duration::ZERO,
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.inner.register_recv_waker(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.inner.register_send_waker(waker)
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        self.inner.can_recv()
    }

    /// Query wether the CAM socket accepts the segment.
    #[must_use]
    pub(crate) fn accepts(&self, cx: &mut Context, repr: &wire::BtpBRepr) -> bool {
        self.inner.accepts(cx, repr)
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(CamError::Buffer(Exhausted))` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<cam::CAM, CamError> {
        let (buf, _ind) = self.inner.recv().map_err(|e| CamError::Buffer(e))?;
        let cam = rasn::uper::decode::<cam::CAM>(buf).map_err(|e| CamError::Asn1(e))?;

        Ok(cam)
    }

    /// Process a newly received CAM.
    /// Check if the socket must handle the segment with [accepts] before calling this function.
    pub(crate) fn process(&mut self, cx: &mut Context, indication: Indication, payload: &[u8]) {
        self.inner.process(cx, indication, payload)
    }

    pub(crate) fn dispatch<F, E>(
        &mut self,
        cx: &mut Context,
        srv: ContextMeta,
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(&mut Context, &mut GnCore, (EthernetAddress, GeonetRepr, &[u8])) -> Result<(), E>,
    {
        if self.retransmit_at > srv.core.now {
            return Ok(());
        }

        if !self.inner.is_open() {
            match self.inner.bind(ports::CAM) {
                Ok(_) => net_trace!("CAM socket bind"),
                Err(e) => {
                    net_trace!("CAM socket bind error: {}", e);
                    return Ok(());
                }
            }
        }

        let ego_station_type = srv.core.station_type();

        // Fill CAM.
        let lat = srv.core.ego_position_vector.latitude;
        let lon = srv.core.ego_position_vector.longitude;
        let cam = self.fill_cam(
            cdd::Latitude(lat.get::<tenth_of_microdegree>() as i32),
            cdd::Longitude(lon.get::<tenth_of_microdegree>() as i32),
            srv.core.pseudonym(),
        );

        if ego_station_type == StationType::RoadSideUnit {
            self.retransmit_delay = CAM_RSU_RETRANSMIT_DELAY;
        } else {
            self.retransmit_delay = CAM_RETRANSMIT_DELAY;
        }

        self.retransmit_at = srv.core.now + self.retransmit_delay;

        let Ok(raw_cam) = rasn::uper::encode(&cam) else {
            net_trace!("CAM content invalid");
            return Ok(());
        };

        let meta = Request {
            transport: Transport::SingleHopBroadcast,
            max_lifetime: Duration::from_millis(1000),
            //pCamTrafficClass in C2C vehicle profile.
            traffic_class: GnTrafficClass::new(false, 2),
            ..Default::default()
        };

        let Ok(_) = self.inner.send_slice(&raw_cam, meta) else {
            net_trace!("CAM slice cannot be sent");
            return Ok(());
        };

        self.inner.dispatch(cx, srv, emit)
    }

    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        self.inner.poll_at(cx).min(PollAt::Time(self.retransmit_at))
    }

    /// Fills a CAM message with basic content
    fn fill_cam(&self, lat: cdd::Latitude, lon: cdd::Longitude, pseudo: Pseudonym) -> cam::CAM {
        use cam::*;
        use cdd::*;
        use rasn::types::SequenceOf;

        let header = ItsPduHeader::new(OrdinalNumber1B(2), MessageId(2), StationId(pseudo.0));

        let station_type = TrafficParticipantType(15);

        let alt = cdd::Altitude::new(AltitudeValue(1000), AltitudeConfidence::unavailable);

        let pos_confidence = PositionConfidenceEllipse::new(
            SemiAxisLength(4095),
            SemiAxisLength(4095),
            Wgs84AngleValue(3601),
        );
        let ref_pos =
            ReferencePositionWithConfidence::new(lat.clone(), lon.clone(), pos_confidence, alt);
        let basic_container = BasicContainer::new(station_type, ref_pos);

        let prot_zone = ProtectedCommunicationZone::new(
            ProtectedZoneType::permanentCenDsrcTolling,
            None,
            lat,
            lon,
            None,
            Some(ProtectedZoneId(0xfe)),
        );

        let mut prot_zones = ProtectedCommunicationZonesRSU(SequenceOf::new());
        prot_zones.0.push(prot_zone);

        let hf_container = HighFrequencyContainer::rsuContainerHighFrequency(
            RSUContainerHighFrequency::new(Some(prot_zones)),
        );

        let cam_params = CamParameters::new(basic_container, hf_container, None, None);
        let gen_time = GenerationDeltaTime(12345);
        let coop_awareness = CamPayload::new(gen_time, cam_params);

        cam::CAM::new(header, coop_awareness)
    }
}
