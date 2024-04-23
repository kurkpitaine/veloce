use core::fmt;

use crate::common::geo_area::GeoArea;
use crate::config::{BTP_MAX_PL_SIZE, GN_DEFAULT_PACKET_LIFETIME};
use crate::iface::{Congestion, Context, ContextMeta};
use crate::network::{GnCore, Transport};

use crate::socket::{self, btp::SocketB as BtpBSocket, PollAt};
use crate::time::{Duration, Instant, TAI2004};
use crate::types::Pseudonym;
use crate::wire::{self, ports, GnTrafficClass};

use crate::storage::PacketBuffer;
use crate::wire::{EthernetAddress, GeonetRepr};

use managed::ManagedSlice;
use veloce_asn1::defs::d_e_n_m__p_d_u__description as denm;
use veloce_asn1::defs::e_t_s_i__i_t_s__c_d_d as cdd;
use veloce_asn1::prelude::rasn::{
    self,
    error::{DecodeError, EncodeError},
};

use super::btp::{Indication, RecvError, Request};

/// Error returned by [`Socket::trigger`], [`Socket::update`] and [`Socket::cancel`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApiError {
    /// No available slot in the originating message table.
    NoFreeSlot,
    /// Event is already expired.
    Expired,
    /// Detection time value is invalid.
    InvalidDetectionTime,
    /// Validity duration value is invalid.
    InvalidValidityDuration,
    /// Repetition duration value is invalid.
    InvalidRepetitionDuration,
    /// Repetition interval value is invalid.
    InvalidRepetitionInterval,
    /// Keep-alive transmission interval value is invalid.
    InvalidKeepAliveTransmissionInterval,
    /// Content has wrong value(s). UPER serialization constraint
    /// check has failed.
    InvalidContent(EncodeError),
    /// Handle is invalid, ie: DENM does not exist in Originating
    /// message table.
    NotFound,
    /// Action Id exists in originating message table.
    ActionIdInOrigMsgtable,
}

impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApiError::NoFreeSlot => write!(f, "No free slot"),
            ApiError::Expired => write!(f, "Expired"),
            ApiError::InvalidDetectionTime => write!(f, "Invalid detection time"),
            ApiError::InvalidValidityDuration => write!(f, "Invalid validity duration"),
            ApiError::InvalidRepetitionDuration => write!(f, "Invalid repetition duration"),
            ApiError::InvalidRepetitionInterval => write!(f, "Invalid repetition interval"),
            ApiError::InvalidKeepAliveTransmissionInterval => {
                write!(f, "Invalid keep-alive transmission interval")
            }
            ApiError::InvalidContent(e) => {
                write!(f, "Invalid content: {}", e)
            }
            ApiError::NotFound => write!(f, "Event not found"),
            ApiError::ActionIdInOrigMsgtable => {
                write!(f, "Action Id exists in originating message table")
            }
        }
    }
}

/// Error returned by [`Socket::recv`]
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DenmError {
    Buffer(RecvError),
    Asn1(DecodeError),
}

impl core::fmt::Display for DenmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DenmError::Buffer(b) => write!(f, "Buffer: {}", b),
            DenmError::Asn1(d) => write!(f, "Asn1: {}", d),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DenmError {}

/// Unique identifier of the DENM, aka Action ID.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ActionId {
    /// Station ID part.
    station_id: u32,
    /// Sequence number part
    seq_num: u16,
}

impl core::fmt::Display for ActionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}-{}]", self.station_id, self.seq_num)
    }
}

impl From<cdd::ActionId> for ActionId {
    fn from(value: cdd::ActionId) -> Self {
        Self {
            station_id: value.originating_station_id.0,
            seq_num: value.sequence_number.0,
        }
    }
}

impl Into<cdd::ActionId> for ActionId {
    fn into(self) -> cdd::ActionId {
        cdd::ActionId {
            originating_station_id: cdd::StationId(self.station_id),
            sequence_number: cdd::SequenceNumber(self.seq_num),
        }
    }
}

/// State for a DENM originated by this station.
#[derive(Debug)]
pub struct OriginatedDenm {
    /// State of the DENM. See [EventState].
    state: EventState,
    /// DENM description. See [Event].
    inner: Event,
}

/// State for a received DENM.
#[derive(Debug)]
pub struct ReceivedDenm {
    /// State of the DENM. See [EventState].
    state: EventState,
    /// ActionID of the received DEMN.
    action_id: ActionId,
    /// Expiration time of the received DENM.
    expires_at: Instant,
    /// Detection time of the received DENM.
    detection_time: TAI2004,
    /// Reference time of the received DENM.
    reference_time: TAI2004,
}

/// State for a DENM across its lifetime. DENM is valid
/// until its state is [EventState::Expired].
#[derive(Debug, PartialEq, Eq)]
enum EventState {
    /// DENM is active.
    Active,
    /// DENM is cancelled.
    Cancelled,
    /// DENM is negated, ie: has been reported as no longer valid by
    /// another station.
    Negated,
    /// DENM is expired. Slot can be recycled.
    Expired,
}

#[derive(Debug)]
struct Event {
    /// Action ID of the DENM. Never changes, even if
    /// [Pseudonym] is changed.
    action_id: ActionId,
    /// Dissemination geographical area.
    geo_area: GeoArea,
    /// Geonetworking Traffic class associated to this DENM.
    traffic_class: GnTrafficClass,
    /// Instant at which the DENM expires.
    expires_at: Instant,
    /// Full DENM message.
    denm_msg: Box<denm::DENM>,
    /// UPER serialized DENM.
    encoded: Vec<u8>,
    /// Next retransmission instant. Optional as retransmission could
    /// end before the event is expired.
    retransmit_at: Option<Instant>,
    /// DENM retransmission metadata (if any).
    retransmission: Option<RetransmissionMeta>,
}

/// Retransmission metadata for a DENM.
#[derive(Debug)]
struct RetransmissionMeta {
    /// Retransmission delay.
    retransmit_delay: Duration,
    /// Instant at which retransmission ends.
    retransmit_end: Instant,
}

/// Utility enum for internal processing.
enum TerminationType {
    /// No termination.
    None,
    /// Termination is a cancellation, is cancel en event
    /// generated by the ego station.
    Cancel,
    /// Termination is a negation, ie: cancel an event which was
    /// generated by another station.
    Negation((ActionId, TAI2004)),
}

impl TerminationType {
    fn as_denm_termination(&self) -> Option<denm::Termination> {
        match self {
            TerminationType::None => None,
            TerminationType::Cancel => Some(denm::Termination::isCancellation),
            TerminationType::Negation(_) => Some(denm::Termination::isNegation),
        }
    }
}

/// A handle to an in-progress DENM transmission.
#[derive(Clone, Copy)]
pub struct EventHandle {
    /// Index of the DENM in the message table.
    idx: usize,
    /// Action ID of the DENM.
    action_id: ActionId,
}

impl EventHandle {
    /// Get the Action ID of the DENM associated to the handle.
    pub fn action_id(&self) -> ActionId {
        self.action_id
    }
}

/// Awareness area of the DENM.
/// See ETSI TS 103 831 V2.1.1 chapters 6.1.3.1 and 6.1.3.2 for details.
#[derive(Default, Debug)]
pub struct EventAwareness {
    /// Awareness distance.
    /// Should be set to [None] if event relevance zone is point based or linear.
    /// If relevance zone is circular, should be set to the radius of the circular
    /// awareness area in which the receiving ITS-S may encounter the event. See
    /// [cdd::StandardLength3b] for possible values.
    distance: Option<cdd::StandardLength3b>,
    /// Awareness traffic direction, ie: the traffic direction along which the
    /// receiving ITS-S may encounter the event. See [cdd::TrafficDirection] for possible values.
    traffic_direction: Option<cdd::TrafficDirection>,
}

/// Parameters regarding a DENM transmission.
#[derive(Debug)]
pub struct EventParameters {
    /// Event detection time. Should be less or equal to now TAI time.
    detection_time: TAI2004,
    /// Event validity duration, rounded as `seconds` in the emitted DENM.
    /// Value should be in 0..=86400 seconds range.
    /// If set to [None], validity is set to a 600 secs duration.
    validity_duration: Option<Duration>,
    /// Event position.
    position: cdd::ReferencePosition,
    /// Event awareness.
    awareness: EventAwareness,
    /// Geonetworking destination area.
    geo_area: GeoArea,
    /// Repetition parameters. If set to [None], the DENM will be transmitted
    /// exactly one time.
    repetition: Option<RepetitionParameters>,
    /// Keep Alive Forwarding. Contains the `transmissionInterval` value,
    /// ie: a retransmission period rounded as `milliseconds` in the emitted DENM.
    /// Should be set to [Some] Duration to enable Keep Alive Forwarding if the
    /// application requires, and in range 1..=10000 milliseconds.
    keep_alive: Option<Duration>,
    /// Geonetworking traffic class.
    traffic_class: GnTrafficClass,
    /// Situation container of the DENM. Ignored in case of cancel or negation.
    situation_container: Option<denm::SituationContainer>,
    /// Location container of the DENM. Ignored in case of cancel or negation.
    location_container: Option<denm::LocationContainer>,
    /// "A la carte" container of the DENM. Ignored in case of cancel or negation.
    alacarte_container: Option<denm::AlacarteContainer>,
}

/// Parameters for DENM retransmission.
#[derive(Debug)]
pub struct RepetitionParameters {
    /// Duration of the repetition.
    /// Shall not be greater than [EventParameters::validity_duration].
    duration: Duration,
    /// Time interval between two consecutive transmissions.
    /// Shall not be greater than [EventParameters::validity_duration].
    interval: Duration,
}

/// Maximum number of DENMs in receive buffer.
const DENM_RX_BUF_NUM: usize = 5;
/// Maximum size of data in receive buffer.
const DENM_RX_BUF_SIZE: usize = DENM_RX_BUF_NUM * BTP_MAX_PL_SIZE;

/// An ETSI DENM type socket.
///
/// A DENM socket executes the Decentralized Event Notification Message protocol,
/// as described in ETSI TS 103 831 V2.1.1 (2022-11).
///
/// The socket implement the DENM messages transmission, provides
/// a list of received DENM accessible with [Socket::recv] and a
/// callback registration mechanism for DENM Rx/Tx event.
pub struct Socket<'a> {
    /// BTP layer.
    inner: BtpBSocket<'a>,
    /// Incrementing sequence number to fill DENM Action ID.
    seq_num: u16,
    /// Originating Message Table.
    orig_msg_table: ManagedSlice<'a, Option<OriginatedDenm>>,
    /// Receiving Message Table.
    recv_msg_table: ManagedSlice<'a, Option<ReceivedDenm>>,
    /// Function to call when a DENM message is successfully received.
    rx_callback: Option<Box<dyn FnMut(&[u8], &denm::DENM)>>,
    /// Function to call when a DENM message is successfully transmitted to the lower layer.
    /// Keep in mind some mechanisms, like congestion control, may silently drop the message
    /// at a lower layer before any transmission occur.
    tx_callback: Option<Box<dyn FnMut(&[u8], &denm::DENM)>>,
}

impl fmt::Debug for Socket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket")
            .field("inner", &self.inner)
            //.field("pseudonym", &self.pseudonym)
            .field("seq_num", &self.seq_num)
            .field("orig_msg_table", &self.orig_msg_table)
            .field("recv_msg_table", &self.recv_msg_table)
            .finish_non_exhaustive()
    }
}

impl<'a> Socket<'a> {
    /// Create a DENM socket.
    pub fn new<Ot, Rt>(orig_table_storage: Ot, recv_table_storage: Rt) -> Socket<'a>
    where
        Ot: Into<ManagedSlice<'a, Option<OriginatedDenm>>>,
        Rt: Into<ManagedSlice<'a, Option<ReceivedDenm>>>,
    {
        // Create inner BTP-B socket.
        let inner_rx_buffer = PacketBuffer::new(
            vec![socket::btp::b::RxPacketMetadata::EMPTY; DENM_RX_BUF_NUM],
            vec![0; DENM_RX_BUF_SIZE],
        );

        let inner_tx_buffer = PacketBuffer::new(
            vec![socket::btp::b::TxPacketMetadata::EMPTY],
            vec![0; BTP_MAX_PL_SIZE],
        );
        let inner = socket::btp::SocketB::new(inner_rx_buffer, inner_tx_buffer);

        Socket {
            inner,
            //pseudonym: Pseudonym(0),
            seq_num: 0,
            orig_msg_table: orig_table_storage.into(),
            recv_msg_table: recv_table_storage.into(),
            rx_callback: None,
            tx_callback: None,
        }
    }

    /// Register a callback for a DENM reception event.
    /// First callback parameter contains the DENM message serialized as UPER.
    /// Second callback parameter contains the raw DENM message struct.
    pub fn register_recv_callback(&mut self, rx_cb: impl FnMut(&[u8], &denm::DENM) + 'static) {
        self.rx_callback = Some(Box::new(rx_cb));
    }

    /// Register a callback for a DENM transmission event.
    /// First callback parameter contains the DENM message serialized as UPER.
    /// Second callback parameter contains the raw DENM message struct.
    /// Keep in mind some mechanisms, like congestion control, may silently drop the message
    /// at a lower layer before any transmission occur.
    pub fn register_send_callback(&mut self, tx_cb: impl FnMut(&[u8], &denm::DENM) + 'static) {
        self.tx_callback = Some(Box::new(tx_cb));
    }

    /*     /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        self.inner.can_recv()
    } */

    /// Trigger a DENM for transmission.
    pub fn trigger(
        &mut self,
        core: &GnCore,
        event: EventParameters,
    ) -> Result<EventHandle, ApiError> {
        let idx = self.find_free_orig_table().ok_or(ApiError::NoFreeSlot)?;
        self.api_inner(core, idx, event, TerminationType::None)
    }

    /// Update a DENM transmission.
    pub fn update(
        &mut self,
        core: &GnCore,
        handle: EventHandle,
        event: EventParameters,
    ) -> Result<EventHandle, ApiError> {
        let evt = self
            .orig_msg_table
            .get(handle.idx)
            .ok_or(ApiError::NotFound)?
            .as_ref()
            .ok_or(ApiError::NotFound)?;

        if evt.inner.action_id != handle.action_id {
            return Err(ApiError::NotFound);
        }

        if evt.state != EventState::Active {
            return Err(ApiError::Expired);
        }

        self.api_inner(core, handle.idx, event, TerminationType::None)
    }

    /// Cancel a DENM transmission.
    pub fn cancel(
        &mut self,
        core: &GnCore,
        handle: EventHandle,
        event: EventParameters,
    ) -> Result<EventHandle, ApiError> {
        let evt = self
            .orig_msg_table
            .get(handle.idx)
            .ok_or(ApiError::NotFound)?
            .as_ref()
            .ok_or(ApiError::NotFound)?;

        if evt.inner.action_id != handle.action_id {
            return Err(ApiError::NotFound);
        }

        if evt.state != EventState::Active {
            return Err(ApiError::Expired);
        }

        self.api_inner(core, handle.idx, event, TerminationType::Cancel)
    }

    /// Negate a DENM transmission.
    pub fn negate(
        &mut self,
        core: &GnCore,
        action_id: ActionId,
        event: EventParameters,
    ) -> Result<EventHandle, ApiError> {
        // ActionId should not be in originating message table.
        if self
            .orig_msg_table
            .iter()
            .flatten()
            .find(|d| d.inner.action_id == action_id)
            .is_some()
        {
            return Err(ApiError::ActionIdInOrigMsgtable);
        }

        let evt = self
            .recv_msg_table
            .iter()
            .flatten()
            .find(|d| d.action_id == action_id)
            .ok_or(ApiError::NotFound)?;

        if evt.state != EventState::Active {
            return Err(ApiError::Expired);
        }
        let ref_time = evt.reference_time;

        // Create handle for event
        let idx = self.find_free_orig_table().ok_or(ApiError::NoFreeSlot)?;
        self.api_inner(
            core,
            idx,
            event,
            TerminationType::Negation((action_id, ref_time)),
        )
    }

    fn api_inner(
        &mut self,
        core: &GnCore,
        idx: usize,
        event: EventParameters,
        termination: TerminationType,
    ) -> Result<EventHandle, ApiError> {
        let now_tai = TAI2004::from_unix_instant(core.now);

        if event.detection_time > now_tai {
            return Err(ApiError::InvalidDetectionTime);
        }

        // Calculate expiration time.
        let validity_duration = event.validity_duration.unwrap_or(Duration::from_secs(600));

        if !(0..=86400).contains(&validity_duration.secs()) {
            return Err(ApiError::InvalidValidityDuration);
        }

        let expires_at = event.detection_time + validity_duration;
        if expires_at > now_tai {
            return Err(ApiError::Expired);
        }

        // Verify repetition parameters validity.
        // As in ETSI TS 103 831 V2.1.1 paragraph 8.2.1.5: for all application request types, the T_Repetition
        // and T_RepetitionDuration shall not be greater than the validityDuration.
        let retransmission = match event.repetition {
            Some(rep) => {
                if rep.duration > validity_duration {
                    return Err(ApiError::InvalidRepetitionDuration);
                }

                if rep.interval > validity_duration {
                    return Err(ApiError::InvalidRepetitionInterval);
                }

                Some(RetransmissionMeta {
                    retransmit_delay: rep.interval,
                    retransmit_end: core.now + rep.duration,
                })
            }
            _ => None,
        };

        // Same for transmission interval.
        let transmission_interval = match event.keep_alive {
            Some(keep_alive) => match keep_alive.total_millis() {
                1..=10000 if keep_alive <= validity_duration => Some(
                    cdd::DeltaTimeMilliSecondPositive(keep_alive.total_millis() as u16),
                ),
                _ => return Err(ApiError::InvalidKeepAliveTransmissionInterval),
            },
            None => None,
        };

        // Assign unused actionId value.
        let (action_id, reference_time) = if let TerminationType::Negation((id, rt)) = termination {
            (id, rt)
        } else {
            (self.next_action_id(core.pseudonym), now_tai)
        };

        // Set DENM fields.
        let management_container = denm::ManagementContainer::new(
            action_id.into(),
            event.detection_time.into(),
            reference_time.into(),
            termination.as_denm_termination(),
            event.position,
            event.awareness.distance,
            event.awareness.traffic_direction,
            cdd::DeltaTimeSecond(validity_duration.secs() as u32),
            transmission_interval,
            core.station_type().into(),
        );

        let denm_msg = Box::new(denm::DENM {
            header: cdd::ItsPduHeader {
                protocol_version: cdd::OrdinalNumber1B(2),
                message_id: cdd::MessageId(1),
                station_id: cdd::StationId(core.pseudonym.0),
            },
            denm: denm::DenmPayload {
                management: management_container,
                situation: if let TerminationType::None = termination {
                    event.situation_container
                } else {
                    None
                },
                location: if let TerminationType::None = termination {
                    event.location_container
                } else {
                    None
                },
                alacarte: if let TerminationType::None = termination {
                    event.alacarte_container
                } else {
                    None
                },
            },
        });

        // Serialize as UPER to check fields.
        let encoded = match rasn::uper::encode(&denm_msg) {
            Ok(enc) => enc,
            Err(e) => {
                return Err(ApiError::InvalidContent(e));
            }
        };

        self.orig_msg_table[idx] = Some(OriginatedDenm {
            state: match termination {
                TerminationType::None => EventState::Active,
                TerminationType::Cancel => EventState::Cancelled,
                TerminationType::Negation(_) => EventState::Negated,
            },
            inner: Event {
                action_id,
                geo_area: event.geo_area,
                traffic_class: event.traffic_class,
                expires_at: expires_at.as_unix_instant(),
                denm_msg,
                encoded,
                retransmit_at: Some(Instant::ZERO),
                retransmission,
            },
        });

        Ok(EventHandle { idx, action_id })
    }

    /// Query wether the DENM socket accepts the segment.
    #[must_use]
    pub(crate) fn accepts(
        &self,
        cx: &mut Context,
        srv: &ContextMeta,
        repr: &wire::BtpBRepr,
    ) -> bool {
        self.inner.accepts(cx, srv, repr)
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(DenmError::Buffer(Exhausted))` if the receive buffer is empty.
    fn recv_inner(&mut self) -> Result<denm::DENM, DenmError> {
        let (buf, _ind) = self.inner.recv().map_err(|e| DenmError::Buffer(e))?;
        let decoded = rasn::uper::decode::<denm::DENM>(buf).map_err(|e| DenmError::Asn1(e))?;

        Ok(decoded)
    }

    /// Process a newly received DENM.
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

        let decoded = match self.recv_inner() {
            Ok(d) => d,
            Err(e) => {
                net_debug!("Cannot process DENM: {}", e);
                return;
            }
        };

        let now = srv.core.now;
        let detection_time = TAI2004::from(decoded.denm.management.detection_time.clone());
        let reference_time = TAI2004::from(decoded.denm.management.reference_time.clone());
        let expires_at = detection_time.as_unix_instant()
            + Duration::from_secs(decoded.denm.management.validity_duration.0.into());
        let action_id = ActionId::from(decoded.denm.management.action_id.clone());

        if expires_at < now {
            net_debug!(
                "Cannot process DENM {} - expired: {} < {}",
                action_id,
                now,
                expires_at
            );
            return;
        }

        let handle_opt = self
            .recv_msg_table
            .iter()
            .position(|item| item.as_ref().is_some_and(|e| e.action_id == action_id));

        match handle_opt {
            Some(idx) => {
                // Safety: we checked above idx contains Some(ReceivedDenm{}).
                let entry = self.recv_msg_table[idx].as_mut().unwrap();
                if reference_time <= entry.reference_time || detection_time <= entry.detection_time
                {
                    net_debug!(
                        "Cannot process DENM {} - older or repeated message",
                        action_id
                    );
                    return;
                }

                // Update message table entry.
                entry.expires_at = expires_at;
                entry.reference_time = reference_time;
                entry.detection_time = detection_time;
                entry.state = if decoded.denm.management.termination.is_some() {
                    EventState::Cancelled
                } else {
                    EventState::Active
                };

                if let Some(rx_cb) = &mut self.rx_callback {
                    rx_cb(payload, &decoded);
                };
            }
            None if decoded.denm.management.termination.is_none() => {
                let Some(slot) = self.find_free_recv_table() else {
                    net_debug!(
                        "Cannot process DENM {} - no free slot in received message table",
                        action_id
                    );
                    return;
                };

                // Create entry in received message table
                self.recv_msg_table[slot] = Some(ReceivedDenm {
                    state: EventState::Active,
                    action_id,
                    expires_at,
                    detection_time,
                    reference_time,
                });

                if let Some(rx_cb) = &mut self.rx_callback {
                    rx_cb(payload, &decoded);
                };
            }
            _ => {
                net_debug!("Cannot process DENM {} - terminated", action_id);
                return;
            }
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
            (EthernetAddress, GeonetRepr, &[u8]),
        ) -> Result<(), E>,
    {
        if !self.inner.is_open() {
            match self.inner.bind(ports::DENM) {
                Ok(_) => net_trace!("DENM socket bind"),
                Err(e) => {
                    net_trace!("DENM socket bind error: {}", e);
                    return Ok(());
                }
            }
        }

        let now = srv.core.now;
        let pseudonym = srv.core.pseudonym;

        for d in self.orig_msg_table.iter_mut().flatten() {
            if d.state == EventState::Expired {
                // Expired event.
                continue;
            }

            let event = &mut d.inner;

            if event.expires_at <= now {
                // Event is expired. Set state to Expired for slot recycling.
                net_trace!("DENM {} expired", event.action_id);
                d.state = EventState::Expired;
                continue;
            }

            // if event.action_id.station_id != pseudonym.0 {
            if event.denm_msg.header.station_id.0 != pseudonym.0 {
                // Pseudonym should be changed in DENM message.
                let station_id = cdd::StationId(pseudonym.0);
                event.denm_msg.header.station_id = station_id.clone();
                event
                    .denm_msg
                    .denm
                    .management
                    .action_id
                    .originating_station_id = station_id;

                // Re-encode
                let encoded = match rasn::uper::encode(&event.denm_msg) {
                    Ok(enc) => enc,
                    Err(e) => {
                        net_debug!("DENM {} content is invalid: {}", event.action_id, e);
                        continue;
                    }
                };

                // event.action_id.station_id = pseudonym.0;
                event.encoded = encoded;
            }

            if event.retransmit_at.is_some_and(|at| at > now) {
                // Wait for next transmission.
                continue;
            }

            // According to C2C on packet lifetime:
            // The vehicle C-ITS station shall set the LifeTime field of all GBC packets to the minimum value
            // of ValidityDuration and RepetitionDuration, where ValidityDuration and RepetitionDuration are
            // defined in [C2CCC tc Docs]. The value of the LifeTime field shall not exceed the
            // itsGnMaxPacketLifetime, as specified in Annex H to [EN 302 636-4-1].
            // It is not really clear if we should reject DENMs with a ValidityDuration > itsGnMaxPacketLifetime...
            // As a fallback, we fill with the default packet lifetime.
            let meta = Request {
                transport: Transport::Broadcast(event.geo_area),
                max_lifetime: GN_DEFAULT_PACKET_LIFETIME,
                traffic_class: event.traffic_class,
                ..Default::default()
            };

            let Ok(_) = self.inner.send_slice(&event.encoded, meta) else {
                net_trace!("DENM slice cannot be sent");
                return Ok(());
            };

            self.inner.dispatch(cx, srv, emit).map(|res| {
                if let Some(tx_cb) = &mut self.tx_callback {
                    tx_cb(&event.encoded, &event.denm_msg);
                };

                res
            })?;

            // Schedule for next retransmission.
            match &event.retransmission {
                Some(r) if r.retransmit_end > now => {
                    event.retransmit_at = Some(now + r.retransmit_delay);
                }
                _ => event.retransmit_at = None,
            }

            return Ok(());
        }

        // Nothing to dispatch
        Ok(())
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        self.orig_msg_table
            .iter()
            .flatten()
            .filter_map(|d| match (&d.state, &d.inner.retransmit_at) {
                (EventState::Active | EventState::Cancelled | EventState::Negated, Some(at)) => {
                    Some(PollAt::Time(*at))
                }
                (_, _) => None,
            })
            .min()
            .unwrap_or(PollAt::Ingress)
    }

    /// Returns the next Action Id value to assign to a new DENM.
    /// This function increments the [Socket::seq_num] value.
    fn next_action_id(&mut self, pseudo: Pseudonym) -> ActionId {
        let sn = self.seq_num;
        self.seq_num = self.seq_num.wrapping_add(1);

        ActionId {
            station_id: pseudo.0,
            seq_num: sn,
        }
    }

    /// Finds a free slot in the originating message table of the socket.
    fn find_free_orig_table(&mut self) -> Option<usize> {
        for (i, q) in self.orig_msg_table.iter().enumerate() {
            match q {
                None => return Some(i),
                Some(d) if d.state == EventState::Expired => return Some(i),
                Some(_) => {}
            }
        }

        match &mut self.orig_msg_table {
            ManagedSlice::Borrowed(_) => None,
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(queries) => {
                queries.push(None);
                let index = queries.len() - 1;
                Some(index)
            }
        }
    }

    /// Finds a free slot in the receiving message table of the socket.
    fn find_free_recv_table(&mut self) -> Option<usize> {
        for (i, q) in self.recv_msg_table.iter().enumerate() {
            match q {
                None => return Some(i),
                Some(d) if d.state == EventState::Expired => return Some(i),
                Some(_) => {}
            }
        }

        match &mut self.recv_msg_table {
            ManagedSlice::Borrowed(_) => None,
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(queries) => {
                queries.push(None);
                let index = queries.len() - 1;
                Some(index)
            }
        }
    }
}
