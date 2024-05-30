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
use veloce_asn1::defs::d_e_n_m__p_d_u__descriptions as denm;
use veloce_asn1::defs::e_t_s_i__i_t_s__c_d_d as cdd;
use veloce_asn1::prelude::rasn::{self, error::EncodeError};

use super::btp::{Indication, Request};

/// Default validity duration for a DENM message.
const DEFAULT_VALIDITY: Duration = Duration::from_secs(600);

/// Return value for the [Socket::poll] function.
#[derive(Debug, PartialEq)]
pub struct PollEvent(Option<PollDispatchEvent>, Option<PollProcessEvent>);

impl PollEvent {
    /// Get a reference on the outbound event, if any.
    pub fn poll_out_evt(&self) -> &Option<PollDispatchEvent> {
        &self.0
    }

    /// Get a reference on the inbound event, if any.
    pub fn poll_in_evt(&self) -> &Option<PollProcessEvent> {
        &self.1
    }
}

/// Return value for the [Socket::poll] function.
/// Repetitions are filtered by the socket.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollDispatchEvent {
    /// DENM socket sent a previously unknown DENM.
    SentNew(ActionId),
    /// DENM socket sent an update for a known DENM.
    SentUpdate(ActionId),
    /// DENM socket sent a cancellation for a known DENM.
    SentCancel(ActionId),
    /// DENM socket sent a negation for a known DENM.
    SentNegation(ActionId),
}

/// Return value for the [Socket::poll] function.
/// Repetitions are filtered by the socket.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollProcessEvent {
    /// DENM socket received a previously unknown DENM.
    RecvNew(PollProcessInfo),
    /// DENM socket received an update for a known DENM.
    RecvUpdate(PollProcessInfo),
    /// DENM socket received a cancellation for a known DENM.
    RecvCancel(PollProcessInfo),
    /// DENM socket received a negation for a known DENM.
    RecvNegation(PollProcessInfo),
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)] // unused depending on which sockets are enabled
pub struct PollProcessInfo {
    /// Action Id of the DENM.
    action_id: ActionId,
    /// Full DENM message.
    msg: denm::DENM,
}

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

/// Unique identifier of the DENM, aka Action ID.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[derive(Default, Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Copy)]
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
/// The socket sends/receive DENM autonomously.
/// You must query the last processing event with `.poll()` after every call to
/// `Interface::poll()
pub struct Socket<'a> {
    /// BTP layer.
    inner: BtpBSocket<'a>,
    /// Incrementing sequence number to fill DENM Action ID.
    seq_num: u16,
    /// Originating Message Table.
    orig_msg_table: ManagedSlice<'a, Option<OriginatedDenm>>,
    /// Receiving Message Table.
    recv_msg_table: ManagedSlice<'a, Option<ReceivedDenm>>,
    /// Function to call when a DENM message is successfully received by the DENM socket,
    /// ie: whose content is valid and not expired, including repeated messages.
    rx_callback: Option<Box<dyn FnMut(&[u8], &denm::DENM)>>,
    /// Function to call when a DENM message is successfully transmitted to the lower layer,
    /// including repeated messages. Keep in mind some mechanisms, like congestion control,
    /// may silently drop the message at a lower layer before any transmission occur.
    tx_callback: Option<Box<dyn FnMut(&[u8], &denm::DENM)>>,
    /// Dispatch event to return when polling this socket.
    dispatch_event: Option<PollDispatchEvent>,
    /// Process event to return when polling this socket.
    process_event: Option<PollProcessEvent>,
}

impl fmt::Debug for Socket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket")
            .field("inner", &self.inner)
            .field("seq_num", &self.seq_num)
            .field("orig_msg_table", &self.orig_msg_table)
            .field("recv_msg_table", &self.recv_msg_table)
            .field("dispatch_event", &self.dispatch_event)
            .field("process_event", &self.process_event)
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
            seq_num: 0,
            orig_msg_table: orig_table_storage.into(),
            recv_msg_table: recv_table_storage.into(),
            rx_callback: None,
            tx_callback: None,
            dispatch_event: None,
            process_event: None,
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

    /// Trigger a DENM for transmission.
    pub fn trigger(
        &mut self,
        core: &GnCore,
        event: EventParameters,
    ) -> Result<EventHandle, ApiError> {
        let idx = self.find_free_orig_table().ok_or(ApiError::NoFreeSlot)?;
        let handle = self.api_inner(core, idx, event, TerminationType::None)?;

        self.dispatch_event = Some(PollDispatchEvent::SentNew(handle.action_id));
        Ok(handle)
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

        let handle = self.api_inner(core, handle.idx, event, TerminationType::None)?;

        self.dispatch_event = Some(PollDispatchEvent::SentUpdate(handle.action_id));
        Ok(handle)
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

        let handle = self.api_inner(core, handle.idx, event, TerminationType::Cancel)?;

        self.dispatch_event = Some(PollDispatchEvent::SentCancel(handle.action_id));
        Ok(handle)
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
        let handle = self.api_inner(
            core,
            idx,
            event,
            TerminationType::Negation((action_id, ref_time)),
        )?;

        self.dispatch_event = Some(PollDispatchEvent::SentNegation(handle.action_id));
        Ok(handle)
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
        let validity_duration = event.validity_duration.unwrap_or(DEFAULT_VALIDITY);

        if !(0..=86400).contains(&validity_duration.secs()) {
            return Err(ApiError::InvalidValidityDuration);
        }

        let expires_at = event.detection_time + validity_duration;
        if expires_at < now_tai {
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

    /// Query whether the DENM socket accepts the segment.
    #[must_use]
    pub(crate) fn accepts(
        &self,
        cx: &mut Context,
        srv: &ContextMeta,
        repr: &wire::BtpBRepr,
    ) -> bool {
        self.inner.accepts(cx, srv, repr)
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
        // Make sure there is no event in case of failure in processing.
        self.process_event = None;
        self.inner.process(cx, srv, indication, payload);

        if !self.inner.can_recv() {
            return;
        }

        let (buf, _ind) = match self.inner.recv() {
            Ok(d) => d,
            Err(e) => {
                net_debug!("Cannot process DENM: {}", e);
                return;
            }
        };

        let decoded = match rasn::uper::decode::<denm::DENM>(buf) {
            Ok(d) => d,
            Err(e) => {
                net_debug!("Cannot process DENM: {}", e);
                return;
            }
        };

        let now = srv.core.now;
        let termination = decoded.denm.management.termination.clone();
        let detection_time = TAI2004::from(decoded.denm.management.detection_time.clone());
        let reference_time = TAI2004::from(decoded.denm.management.reference_time.clone());
        let expires_at = detection_time.as_unix_instant()
            + Duration::from_secs(decoded.denm.management.validity_duration.0.into());
        let action_id = ActionId::from(decoded.denm.management.action_id.clone());

        if expires_at < now {
            net_debug!(
                "Cannot process DENM {} - expired: {} < {}",
                action_id,
                expires_at,
                now
            );
            return;
        }

        let handle_opt = self
            .recv_msg_table
            .iter()
            .position(|item| item.as_ref().is_some_and(|e| e.action_id == action_id));

        if let Some(rx_cb) = &mut self.rx_callback {
            rx_cb(buf, &decoded);
        };

        let info = PollProcessInfo {
            action_id,
            msg: decoded,
        };

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
                entry.state = if let Some(term) = termination {
                    self.process_event = Some(match term {
                        denm::Termination::isCancellation => PollProcessEvent::RecvCancel(info),
                        denm::Termination::isNegation => PollProcessEvent::RecvNegation(info),
                    });
                    EventState::Cancelled
                } else {
                    self.process_event = Some(PollProcessEvent::RecvUpdate(info));
                    EventState::Active
                };
            }
            None if termination.is_none() => {
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

                self.process_event = Some(PollProcessEvent::RecvNew(info));
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

            if event.expires_at < now {
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

                event.encoded = encoded;
            }

            match event.retransmit_at {
                Some(at) if at > now => continue,
                Some(_) => {}
                None => continue,
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
        self.dispatch_event = None;
        Ok(())
    }

    /// Query the socket for events.
    pub fn poll(&mut self, timestamp: Instant) -> PollEvent {
        for elem in self.recv_msg_table.iter_mut().flatten() {
            if elem.expires_at < timestamp {
                elem.state = EventState::Expired;
            }
        }

        PollEvent(self.dispatch_event.take(), self.process_event.take())
    }

    /// Return the instant at which the socket should be polled at.
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

#[cfg(feature = "ipc")]
mod ipc {
    use crate::{
        common::geo_area::{Circle, Ellipse, GeoPosition, Rectangle, Shape},
        types::{Distance, Latitude, Longitude},
    };

    use super::*;
    use uom::si::{angle::degree, f32::Angle, length::meter};
    use veloce_ipc::denm::{self as ipc_denm};

    /// Error type returned by the IPC interface.
    pub enum IpcError {
        /// Some content is wrong or missing.
        Malformed,
        /// Awareness distance is invalid.
        InvalidAwarenessDistance,
        /// Awareness traffic direction is invalid.
        InvalidAwarenessTrafficDirection,
        /// Situation container is invalid. Cannot decode it.
        InvalidSituationContainer,
        /// Location container is invalid. Cannot decode it.
        InvalidLocationContainer,
        /// A la carte container is invalid. Cannot decode it.
        InvalidAlacarteContainer,
    }

    impl TryFrom<ipc_denm::ApiParameters> for EventParameters {
        type Error = IpcError;

        fn try_from(value: ipc_denm::ApiParameters) -> Result<Self, Self::Error> {
            let detec_instant = Instant::from_millis_const(value.detection_time as i64);

            // Situation container
            let situation_container = if let Some(situation_container_uper) =
                value.situation_container
            {
                let dec = rasn::uper::decode::<denm::SituationContainer>(&situation_container_uper)
                    .map_err(|_| IpcError::InvalidSituationContainer)?;
                Some(dec)
            } else {
                None
            };

            // Location container
            let location_container = if let Some(location_container_uper) = value.location_container
            {
                let dec = rasn::uper::decode::<denm::LocationContainer>(&location_container_uper)
                    .map_err(|_| IpcError::InvalidLocationContainer)?;
                Some(dec)
            } else {
                None
            };

            // A la carte container
            let alacarte_container = if let Some(alacarte_container_uper) = value.alacarte_container
            {
                let dec = rasn::uper::decode::<denm::AlacarteContainer>(&alacarte_container_uper)
                    .map_err(|_| IpcError::InvalidAlacarteContainer)?;
                Some(dec)
            } else {
                None
            };

            let geo_area = value.geo_area.ok_or(IpcError::Malformed)?;

            let position = value.position.ok_or(IpcError::Malformed)?;
            let pos_confidence = position
                .position_confidence_ellipse
                .ok_or(IpcError::Malformed)?;
            let alt = position.altitude.ok_or(IpcError::Malformed)?;

            let altitude = cdd::Altitude {
                altitude_value: alt.altitude.map_or(cdd::AltitudeValue(800001), |a| {
                    cdd::AltitudeValue(a.max(-100000).min(800000))
                }),
                altitude_confidence: alt.confidence.map_or(
                    cdd::AltitudeConfidence::unavailable,
                    |alt| match alt {
                        val if val > 20000 => cdd::AltitudeConfidence::outOfRange,
                        val if val > 10000 => cdd::AltitudeConfidence::alt_200_00,
                        val if val > 5000 => cdd::AltitudeConfidence::alt_100_00,
                        val if val > 2000 => cdd::AltitudeConfidence::alt_050_00,
                        val if val > 1000 => cdd::AltitudeConfidence::alt_020_00,
                        val if val > 500 => cdd::AltitudeConfidence::alt_010_00,
                        val if val > 200 => cdd::AltitudeConfidence::alt_005_00,
                        val if val > 100 => cdd::AltitudeConfidence::alt_002_00,
                        val if val > 50 => cdd::AltitudeConfidence::alt_001_00,
                        val if val > 20 => cdd::AltitudeConfidence::alt_000_50,
                        val if val > 10 => cdd::AltitudeConfidence::alt_000_20,
                        val if val > 5 => cdd::AltitudeConfidence::alt_000_10,
                        val if val > 2 => cdd::AltitudeConfidence::alt_000_05,
                        val if val > 1 => cdd::AltitudeConfidence::alt_000_02,
                        _ => cdd::AltitudeConfidence::alt_000_01,
                    },
                ),
            };

            let position_confidence_ellipse = cdd::PosConfidenceEllipse {
                semi_major_confidence: pos_confidence
                    .semi_major_confidence
                    .map_or(cdd::SemiAxisLength(4095), |m| {
                        cdd::SemiAxisLength(m.min(4094) as u16)
                    }),
                semi_minor_confidence: pos_confidence
                    .semi_minor_confidence
                    .map_or(cdd::SemiAxisLength(4095), |m| {
                        cdd::SemiAxisLength(m.min(4094) as u16)
                    }),
                semi_major_orientation: pos_confidence
                    .semi_major_orientation
                    .map_or(cdd::HeadingValue(3601), |m| {
                        cdd::HeadingValue((m % 3600) as u16)
                    }),
            };

            let position = cdd::ReferencePosition {
                latitude: cdd::Latitude((position.latitude * 10_000_000.0) as i32),
                longitude: cdd::Longitude((position.longitude * 10_000_000.0) as i32),
                position_confidence_ellipse,
                altitude,
            };

            let awareness_distance = if let Some(ad) = value.awareness_distance {
                match ipc_denm::EtsiStandardLength3b::try_from(ad)
                    .map_err(|_| IpcError::InvalidAwarenessDistance)?
                {
                    ipc_denm::EtsiStandardLength3b::LessThan50m => {
                        Some(cdd::StandardLength3b::lessThan50m)
                    }
                    ipc_denm::EtsiStandardLength3b::LessThan100m => {
                        Some(cdd::StandardLength3b::lessThan100m)
                    }
                    ipc_denm::EtsiStandardLength3b::LessThan200m => {
                        Some(cdd::StandardLength3b::lessThan200m)
                    }
                    ipc_denm::EtsiStandardLength3b::LessThan500m => {
                        Some(cdd::StandardLength3b::lessThan500m)
                    }
                    ipc_denm::EtsiStandardLength3b::LessThan1000m => {
                        Some(cdd::StandardLength3b::lessThan1000m)
                    }
                    ipc_denm::EtsiStandardLength3b::LessThan5km => {
                        Some(cdd::StandardLength3b::lessThan5km)
                    }
                    ipc_denm::EtsiStandardLength3b::LessThan10km => {
                        Some(cdd::StandardLength3b::lessThan10km)
                    }
                    ipc_denm::EtsiStandardLength3b::Over10km => {
                        Some(cdd::StandardLength3b::over10km)
                    }
                }
            } else {
                None
            };

            let awareness_traffic_direction = if let Some(td) = value.awareness_traffic_direction {
                match ipc_denm::EtsiTrafficDirection::try_from(td).map_err(|_| IpcError::InvalidAwarenessTrafficDirection)? {
                    ipc_denm::EtsiTrafficDirection::AllTrafficDirections => Some(cdd::TrafficDirection::allTrafficDirections),
                    ipc_denm::EtsiTrafficDirection::SameAsReferenceDirectionUpstreamOfReferencePosition => Some(cdd::TrafficDirection::sameAsReferenceDirection_upstreamOfReferencePosition),
                    ipc_denm::EtsiTrafficDirection::SameAsReferenceDirectionDownstreamOfReferencePosition => Some(cdd::TrafficDirection::sameAsReferenceDirection_downstreamOfReferencePosition),
                    ipc_denm::EtsiTrafficDirection::OppositeToReferenceDirection => Some(cdd::TrafficDirection::allTrafficDirections),
                }
            } else {
                None
            };

            let awareness = EventAwareness {
                distance: awareness_distance,
                traffic_direction: awareness_traffic_direction,
            };

            let repetition = value.repetition.map(|r| RepetitionParameters {
                duration: Duration::from_millis(r.duration.into()),
                interval: Duration::from_millis(r.interval.into()),
            });

            Ok(Self {
                detection_time: TAI2004::from_unix_instant(detec_instant),
                validity_duration: value
                    .validity_duration
                    .map(|d| Duration::from_secs(d.into())),
                position,
                awareness,
                geo_area: GeoArea::try_from(geo_area)?,
                repetition,
                keep_alive: value.keep_alive.map(|k| Duration::from_millis(k.into())),
                traffic_class: GnTrafficClass::from_byte(&(value.traffic_class as u8)),
                situation_container,
                location_container,
                alacarte_container,
            })
        }
    }

    impl TryFrom<ipc_denm::GeoArea> for GeoArea {
        type Error = IpcError;

        fn try_from(value: ipc_denm::GeoArea) -> Result<Self, Self::Error> {
            let shp = value.shape.ok_or(IpcError::Malformed)?;
            let shape = match shp {
                ipc_denm::geo_area::Shape::Circle(c) => Shape::Circle(Circle {
                    radius: Distance::new::<meter>(c.radius as f32),
                }),
                ipc_denm::geo_area::Shape::Rectangle(r) => Shape::Rectangle(Rectangle {
                    a: Distance::new::<meter>(r.distance_a as f32),
                    b: Distance::new::<meter>(r.distance_b as f32),
                }),
                ipc_denm::geo_area::Shape::Ellipse(e) => Shape::Ellipse(Ellipse {
                    a: Distance::new::<meter>(e.distance_a as f32),
                    b: Distance::new::<meter>(e.distance_b as f32),
                }),
            };

            Ok(GeoArea {
                shape,
                position: GeoPosition {
                    latitude: Latitude::new::<degree>(value.latitude as f32),
                    longitude: Longitude::new::<degree>(value.longitude as f32),
                },
                angle: Angle::new::<degree>(value.angle as f32),
            })
        }
    }

    impl TryFrom<ipc_denm::Handle> for EventHandle {
        type Error = IpcError;

        fn try_from(value: ipc_denm::Handle) -> Result<Self, Self::Error> {
            let action_id = value.action_id.ok_or(IpcError::Malformed)?;

            Ok(Self {
                idx: value.idx as usize,
                action_id: ActionId {
                    station_id: action_id.station_id,
                    seq_num: action_id.sequence_number as u16,
                },
            })
        }
    }

    impl Into<ipc_denm::Handle> for EventHandle {
        fn into(self) -> ipc_denm::Handle {
            ipc_denm::Handle {
                idx: self.idx as u64,
                action_id: Some(ipc_denm::ActionId {
                    station_id: self.action_id.station_id,
                    sequence_number: self.action_id.seq_num.into(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use uom::si::angle::degree;
    use uom::si::f32::Angle;
    use uom::si::length::meter;

    use super::*;

    // =========================================================================================//
    // Helper functions

    struct TestSocket {
        pub socket: Socket<'static>,
        pub iface: Interface,
        pub core: GnCore,
    }

    fn recv(
        s: &mut TestSocket,
        timestamp: Instant,
        (indication, denm_repr): (Indication, denm::DENM),
    ) {
        s.core.now = timestamp;

        net_trace!("recv: {:?}", denm_repr);

        let payload = rasn::uper::encode(&denm_repr).unwrap();

        let srv = ContextMeta {
            core: &mut s.core,
            ls: &mut s.iface.location_service,
            congestion_control: &mut s.iface.congestion_control,
            ls_buffer: &mut s.iface.ls_buffer,
            uc_forwarding_buffer: &mut s.iface.uc_forwarding_buffer,
            bc_forwarding_buffer: &mut s.iface.bc_forwarding_buffer,
            cb_forwarding_buffer: &mut s.iface.cb_forwarding_buffer,
        };

        s.socket
            .process(&mut s.iface.inner, &srv, indication, &payload)
    }

    fn send(s: &mut TestSocket, timestamp: Instant) -> Option<denm::DENM> {
        s.core.now = timestamp;

        let mut res = None;

        let srv = ContextMeta {
            core: &mut s.core,
            ls: &mut s.iface.location_service,
            congestion_control: &mut s.iface.congestion_control,
            ls_buffer: &mut s.iface.ls_buffer,
            uc_forwarding_buffer: &mut s.iface.uc_forwarding_buffer,
            bc_forwarding_buffer: &mut s.iface.bc_forwarding_buffer,
            cb_forwarding_buffer: &mut s.iface.cb_forwarding_buffer,
        };

        while s.socket.poll_at(&mut s.iface.inner) <= PollAt::Time(timestamp) {
            s.socket
                .dispatch(
                    &mut s.iface.inner,
                    srv,
                    |_, _core, _, (_eth_repr, gn_repr, buf)| {
                        // Geonet parameters verification.
                        let GeonetRepr::Broadcast(gn_inner) = gn_repr else {
                            panic!("Should be geo-broadcast");
                        };

                        assert_eq!(
                            gn_inner.common_header.header_type,
                            GeonetPacketType::GeoBroadcastCircle
                        );
                        assert_eq!(
                            gn_inner.extended_header.distance_a,
                            Distance::new::<meter>(100.0)
                        );
                        assert_eq!(
                            gn_inner.extended_header.distance_b,
                            Distance::new::<meter>(0.0)
                        );

                        assert_eq!(
                            gn_inner.extended_header.latitude,
                            Latitude::new::<degree>(48.2764384)
                        );
                        assert_eq!(
                            gn_inner.extended_header.longitude,
                            Latitude::new::<degree>(-3.5519532)
                        );

                        // BTP parameters verification.
                        let btp_hdr = btp::type_b::Header::new_unchecked(buf);
                        let btp_repr = btp::type_b::Repr::parse(&btp_hdr).unwrap();

                        assert_eq!(btp_repr.dst_port, btp::ports::DENM);
                        assert_eq!(btp_repr.dst_port_info, 0);

                        // Deserialize emitted DENM.
                        let decoded: denm::DENM =
                            rasn::uper::decode(&buf[btp::type_b::HEADER_LEN..]).unwrap();

                        res = Some(decoded);

                        Ok::<_, ()>(())
                    },
                )
                .ok();

            break;
        }

        res
    }

    fn check_fields(
        pseudo: Pseudonym,
        params: &EventParameters,
        action_id: &ActionId,
        msg: &denm::DENM,
    ) {
        // DENM Content check.
        assert_eq!(msg.header.station_id.0, pseudo.0);
        assert_eq!(msg.header.message_id, cdd::MessageId(1));
        assert_eq!(msg.header.protocol_version, cdd::OrdinalNumber1B(2));

        // Container check
        assert_eq!(msg.denm.location, params.location_container);
        assert_eq!(msg.denm.situation, params.situation_container);
        assert_eq!(msg.denm.alacarte, params.alacarte_container);

        // Action Id matching.
        assert_eq!(
            msg.denm.management.action_id.originating_station_id.0,
            action_id.station_id
        );
        assert_eq!(
            msg.denm.management.action_id.sequence_number.0,
            action_id.seq_num
        );

        // Detection time
        assert_eq!(
            msg.denm.management.detection_time,
            params.detection_time.into()
        );

        // Validity duration
        assert_eq!(
            msg.denm.management.validity_duration,
            params
                .validity_duration
                .map_or(cdd::DeltaTimeSecond(600), |vd| cdd::DeltaTimeSecond(
                    vd.secs() as u32
                ))
        );

        // Event position
        assert_eq!(msg.denm.management.event_position, params.position);

        // Keep alive
        assert_eq!(
            msg.denm.management.transmission_interval,
            params
                .keep_alive
                .map(|kl| cdd::DeltaTimeMilliSecondPositive(kl.total_millis() as u16))
        );

        // Awareness distance.
        assert_eq!(
            msg.denm.management.awareness_distance,
            params.awareness.distance
        );

        // Awareness traffic direction.
        assert_eq!(
            msg.denm.management.awareness_traffic_direction,
            params.awareness.traffic_direction
        );
    }

    // =========================================================================================//
    // Constants
    use crate::common::geo_area::{self, Circle, GeoPosition};
    use crate::common::{
        PotiConfidence, PotiFix, PotiMode, PotiMotion, PotiPosition, PotiPositionConfidence,
    };
    use crate::iface::Interface;
    use crate::types::{Distance, Latitude, Longitude};

    fn station_pos_fix(timestamp: Instant) -> PotiFix {
        PotiFix {
            mode: PotiMode::Fix2d,
            timestamp: TAI2004::from_unix_instant(timestamp),
            position: PotiPosition {
                latitude: Some(Latitude::new::<degree>(48.2764384)),
                longitude: Some(Longitude::new::<degree>(-3.5519532)),
                altitude: None,
            },
            motion: PotiMotion {
                speed: None,
                vertical_speed: None,
                heading: None,
            },
            confidence: PotiConfidence {
                position: PotiPositionConfidence {
                    semi_major: None,
                    semi_minor: None,
                    semi_major_orientation: None,
                },
                altitude: None,
                speed: None,
                heading: None,
            },
        }
    }

    fn geo_area() -> GeoArea {
        GeoArea {
            shape: geo_area::Shape::Circle(Circle {
                radius: Distance::new::<meter>(100.0),
            }),
            position: GeoPosition {
                latitude: Latitude::new::<degree>(48.2764384),
                longitude: Longitude::new::<degree>(-3.5519532),
            },
            angle: Angle::new::<degree>(0.0),
        }
    }

    fn evt_pos() -> cdd::ReferencePosition {
        cdd::ReferencePosition {
            latitude: cdd::Latitude(482764384),
            longitude: cdd::Longitude(-35519532),
            position_confidence_ellipse: cdd::PosConfidenceEllipse {
                semi_major_confidence: cdd::SemiAxisLength(4095),
                semi_minor_confidence: cdd::SemiAxisLength(4095),
                semi_major_orientation: cdd::HeadingValue(3601),
            },
            altitude: cdd::Altitude {
                altitude_value: cdd::AltitudeValue(800001),
                altitude_confidence: cdd::AltitudeConfidence::unavailable,
            },
        }
    }

    fn situation_container() -> denm::SituationContainer {
        denm::SituationContainer::new(
            cdd::InformationQuality(7),
            cdd::CauseCodeV2::new(cdd::CauseCodeChoice::accident2(cdd::AccidentSubCauseCode(
                0,
            ))),
            None,
            None,
        )
    }

    fn new_ind() -> Indication {
        Indication {
            transport: Transport::Broadcast(geo_area()),
            ali_id: (),
            its_aid: (),
            cert_id: (),
            rem_lifetime: Duration::from_secs(1),
            rem_hop_limit: 9,
            traffic_class: GnTrafficClass::new(false, 10),
        }
    }

    fn evt_params(timestamp: Instant) -> EventParameters {
        EventParameters {
            detection_time: TAI2004::from_unix_instant(timestamp),
            validity_duration: Some(Duration::from_secs(300)),
            position: evt_pos(),
            awareness: EventAwareness {
                distance: None,
                traffic_direction: Some(cdd::TrafficDirection::allTrafficDirections),
            },
            geo_area: geo_area(),
            repetition: Some(RepetitionParameters {
                duration: Duration::from_secs(300),
                interval: Duration::from_millis(500),
            }),
            keep_alive: None,
            traffic_class: GnTrafficClass(10),
            situation_container: None,
            location_container: None,
            alacarte_container: None,
        }
    }

    fn denm_evt(timestamp: Instant) -> denm::DENM {
        let now_tai = TAI2004::from_unix_instant(timestamp);
        let management = denm::ManagementContainer::new(
            cdd::ActionId {
                originating_station_id: cdd::StationId(2912),
                sequence_number: cdd::SequenceNumber(0),
            },
            now_tai.into(),
            now_tai.into(),
            None,
            evt_pos(),
            None,
            None,
            cdd::DeltaTimeSecond(DEFAULT_VALIDITY.secs() as u32),
            None,
            cdd::StationType(15),
        );

        denm::DENM {
            header: cdd::ItsPduHeader {
                protocol_version: cdd::OrdinalNumber1B(2),
                message_id: cdd::MessageId(1),
                station_id: cdd::StationId(2912),
            },
            denm: denm::DenmPayload {
                management,
                situation: None,
                location: None,
                alacarte: None,
            },
        }
    }

    use crate::phy::Medium;
    use crate::tests::setup;
    use crate::wire::{btp, GeonetPacketType};

    fn socket(medium: Medium) -> TestSocket {
        let now = Instant::now();
        let (core, iface, _, _) = setup(medium);
        let mut s = Socket::new(vec![], vec![]);
        let poll_ev = s.poll(now);
        assert!(poll_ev.0.is_none());
        assert!(poll_ev.1.is_none());

        TestSocket {
            socket: s,
            iface,
            core,
        }
    }

    #[test]
    fn test_api_invalid_params() {
        let mut s = socket(Medium::Ethernet);

        let now = Instant::now();
        s.core.now = now;

        // Invalid detection time
        let params = evt_params(now + Duration::from_secs(1));
        assert!(matches!(
            s.socket.trigger(&s.core, params),
            Err(ApiError::InvalidDetectionTime)
        ));

        // Invalid validity duration
        let mut params = evt_params(now - Duration::from_secs(1));
        params.validity_duration = Some(Duration::from_secs(86401));
        assert!(matches!(
            s.socket.trigger(&s.core, params),
            Err(ApiError::InvalidValidityDuration)
        ));

        // Expired event
        let params = evt_params(Instant::ZERO);
        assert!(matches!(
            s.socket.trigger(&s.core, params),
            Err(ApiError::Expired)
        ));

        // Invalid repetition duration
        let mut params = evt_params(now - Duration::from_secs(1));
        params.repetition = Some(RepetitionParameters {
            duration: params
                .validity_duration
                .map_or(Duration::from_secs(10000), |d| d + Duration::from_secs(1)),
            interval: Duration::from_millis(500),
        });
        assert!(matches!(
            s.socket.trigger(&s.core, params),
            Err(ApiError::InvalidRepetitionDuration)
        ));

        // Invalid repetition interval
        let mut params = evt_params(now - Duration::from_secs(1));
        params.repetition = Some(RepetitionParameters {
            duration: params.validity_duration.unwrap_or(DEFAULT_VALIDITY),
            interval: Duration::from_secs(10000),
        });
        assert!(matches!(
            s.socket.trigger(&s.core, params),
            Err(ApiError::InvalidRepetitionInterval)
        ));

        // Invalid keep-alive transmission interval
        let mut params = evt_params(now - Duration::from_secs(1));
        params.keep_alive = Some(Duration::from_secs(10001));
        assert!(matches!(
            s.socket.trigger(&s.core, params),
            Err(ApiError::InvalidKeepAliveTransmissionInterval)
        ));

        let mut params = evt_params(now - Duration::from_secs(1));
        params.keep_alive =
            Some(params.validity_duration.unwrap_or(DEFAULT_VALIDITY) + Duration::from_secs(1));
        assert!(matches!(
            s.socket.trigger(&s.core, params),
            Err(ApiError::InvalidKeepAliveTransmissionInterval)
        ));
    }

    #[test]
    fn test_trigger() {
        let mut s = socket(Medium::Ethernet);

        let mut now = Instant::now();
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let mut params = evt_params(now);
        params.repetition = None;
        let handle = s.socket.trigger(&s.core, params.clone()).unwrap();

        assert_eq!(handle.action_id.station_id, s.core.pseudonym.0);
        assert_eq!(handle.action_id.seq_num, 0);

        // Something should have been sent.
        let msg = send(&mut s, now).unwrap();

        // Check fields of the sent DENM.
        check_fields(s.core.pseudonym, &params, &handle.action_id, &msg);

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_in_evt().is_none());

        let PollDispatchEvent::SentNew(evt_out_id) = evt.poll_out_evt().as_ref().unwrap() else {
            panic!("Poll event should be PollDispatchEvent::SentNew");
        };

        assert_eq!(handle.action_id, *evt_out_id);

        // Jump at the expiration of the event to check there is no retransmission.
        now += params.validity_duration.unwrap_or(DEFAULT_VALIDITY);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        assert!(send(&mut s, now).is_none());
    }

    #[test]
    fn test_repetition() {
        let mut s = socket(Medium::Ethernet);

        let mut now = Instant::now();
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let params = evt_params(now);
        let handle = s.socket.trigger(&s.core, params.clone()).unwrap();

        let repet = params.repetition.unwrap();
        let repet_ends_at = now + repet.duration;
        let mut first_tx = true;

        while now <= repet_ends_at {
            // Something should have been sent.
            let msg = send(&mut s, now).unwrap();

            // Check fields of the sent DENM.
            check_fields(s.core.pseudonym, &params, &handle.action_id, &msg);

            // Poll the socket for event.
            let evt = s.socket.poll(now);
            assert!(evt.poll_in_evt().is_none());

            // No event should have been returned for the retransmissions.
            if first_tx {
                assert!(evt.poll_out_evt().is_some());
                first_tx = false;
            } else {
                assert!(evt.poll_out_evt().is_none());
            }

            now += repet.interval;
            s.core.now = now;
            s.core.set_position(station_pos_fix(now));
        }

        // Should not have any retransmission now
        assert!(send(&mut s, now).is_none());
    }

    #[test]
    fn test_update() {
        let mut s = socket(Medium::Ethernet);

        let mut now = Instant::now();
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let mut params = evt_params(now);
        params.repetition = None;
        let handle = s.socket.trigger(&s.core, params).unwrap();

        // Something should have been sent.
        let _msg = send(&mut s, now).unwrap();

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_in_evt().is_none());
        assert!(evt.poll_out_evt().is_some());

        // Jump 10 secs in the future and update the DENM.
        now += Duration::from_secs(10);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let mut params = evt_params(now);
        params.repetition = None;
        params.situation_container = Some(situation_container());
        let handle = s.socket.update(&s.core, handle, params.clone()).unwrap();

        // Something should have been sent.
        let msg = send(&mut s, now).unwrap();

        // Check fields of the updated DENM.
        check_fields(s.core.pseudonym, &params, &handle.action_id, &msg);

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_in_evt().is_none());

        let PollDispatchEvent::SentUpdate(evt_out_id) = evt.poll_out_evt().as_ref().unwrap() else {
            panic!("Poll event should be PollDispatchEvent::SentUpdate");
        };

        assert_eq!(handle.action_id, *evt_out_id);

        // Jump at the expiration of the event to check there is no retransmission.
        now += params.validity_duration.unwrap_or(DEFAULT_VALIDITY);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        assert!(send(&mut s, now).is_none());

        // Try to update a non-existent event
        let mut fake_handle = EventHandle {
            idx: 255,
            action_id: handle.action_id,
        };
        assert!(matches!(
            s.socket.update(&s.core, fake_handle, params.clone()),
            Err(ApiError::NotFound)
        ));

        fake_handle.idx = handle.idx;
        fake_handle.action_id.station_id = 2912;
        assert!(matches!(
            s.socket.update(&s.core, fake_handle, params.clone()),
            Err(ApiError::NotFound)
        ));

        // Jump past the expiration of the event to check api rejects us.
        now += Duration::from_secs(1);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        assert!(send(&mut s, now).is_none());
        assert!(matches!(
            s.socket.update(&s.core, handle, params.clone()),
            Err(ApiError::Expired)
        ));
    }

    #[test]
    fn test_cancel() {
        let mut s = socket(Medium::Ethernet);

        let mut now = Instant::now();
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let mut params = evt_params(now);
        params.repetition = None;
        let handle = s.socket.trigger(&s.core, params).unwrap();

        // Something should have been sent.
        let _msg = send(&mut s, now).unwrap();

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_in_evt().is_none());
        assert!(evt.poll_out_evt().is_some());

        // Jump 10 secs in the future and cancel the DENM.
        now += Duration::from_secs(10);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let mut params = evt_params(now);
        params.repetition = None;
        let handle = s.socket.cancel(&s.core, handle, params.clone()).unwrap();

        // Something should have been sent.
        let msg = send(&mut s, now).unwrap();

        // Check fields of the cancelled DENM.
        check_fields(s.core.pseudonym, &params, &handle.action_id, &msg);

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_in_evt().is_none());

        let PollDispatchEvent::SentCancel(evt_out_id) = evt.poll_out_evt().as_ref().unwrap() else {
            panic!("Poll event should be PollDispatchEvent::SentCancel");
        };

        assert_eq!(handle.action_id, *evt_out_id);

        // Jump at the expiration of the event to check there is no retransmission.
        now += params.validity_duration.unwrap_or(DEFAULT_VALIDITY);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        assert!(send(&mut s, now).is_none());

        // Try to cancel a non-existent event
        let mut fake_handle = EventHandle {
            idx: 255,
            action_id: handle.action_id,
        };
        assert!(matches!(
            s.socket.cancel(&s.core, fake_handle, params.clone()),
            Err(ApiError::NotFound)
        ));

        fake_handle.idx = handle.idx;
        fake_handle.action_id.station_id = 2912;
        assert!(matches!(
            s.socket.cancel(&s.core, fake_handle, params.clone()),
            Err(ApiError::NotFound)
        ));

        // Try to cancel a second time to check api rejects us.
        assert!(send(&mut s, now).is_none());
        assert!(matches!(
            s.socket.cancel(&s.core, handle, params.clone()),
            Err(ApiError::Expired)
        ));
    }

    #[test]
    fn test_receive() {
        let mut s = socket(Medium::Ethernet);

        let mut now = Instant::now();
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let denm_evt = denm_evt(now);

        recv(&mut s, now, (new_ind(), denm_evt.clone()));

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_out_evt().is_none());

        let PollProcessEvent::RecvNew(evt_in_info) = evt.poll_in_evt().as_ref().unwrap() else {
            panic!("Poll event should be PollProcessEvent::RecvNew");
        };

        // Check what we received matches.
        assert_eq!(evt_in_info.msg, denm_evt);
        assert_eq!(
            evt_in_info.action_id.station_id,
            denm_evt.denm.management.action_id.originating_station_id.0
        );
        assert_eq!(
            evt_in_info.action_id.seq_num,
            denm_evt.denm.management.action_id.sequence_number.0
        );

        // Check repetitions are filtered.
        now += Duration::from_secs(1);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        recv(&mut s, now, (new_ind(), denm_evt.clone()));

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_out_evt().is_none());
        assert!(evt.poll_in_evt().is_none());

        // Check update.
        now += Duration::from_secs(1);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        let mut denm_evt = denm_evt.clone();
        denm_evt.denm.management.detection_time.0 += 1500;
        denm_evt.denm.management.reference_time.0 += 1500;

        recv(&mut s, now, (new_ind(), denm_evt.clone()));

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_out_evt().is_none());

        let PollProcessEvent::RecvUpdate(evt_in_info) = evt.poll_in_evt().as_ref().unwrap() else {
            panic!("Poll event should be PollProcessEvent::RecvUpdate");
        };

        // Check what we received matches.
        assert_eq!(evt_in_info.msg, denm_evt);
        assert_eq!(
            evt_in_info.action_id.station_id,
            denm_evt.denm.management.action_id.originating_station_id.0
        );
        assert_eq!(
            evt_in_info.action_id.seq_num,
            denm_evt.denm.management.action_id.sequence_number.0
        );

        // Check cancellation.
        now += Duration::from_secs(1);
        s.core.now = now;
        s.core.set_position(station_pos_fix(now));

        denm_evt.denm.management.detection_time.0 += 500;
        denm_evt.denm.management.reference_time.0 += 500;
        denm_evt.denm.management.termination = Some(denm::Termination::isCancellation);

        recv(&mut s, now, (new_ind(), denm_evt.clone()));

        // Poll the socket for event.
        let evt = s.socket.poll(now);
        assert!(evt.poll_out_evt().is_none());

        let PollProcessEvent::RecvCancel(evt_in_info) = evt.poll_in_evt().as_ref().unwrap() else {
            panic!("Poll event should be PollProcessEvent::RecvCancel");
        };

        // Check what we received matches.
        assert_eq!(evt_in_info.msg, denm_evt);
        assert_eq!(
            evt_in_info.action_id.station_id,
            denm_evt.denm.management.action_id.originating_station_id.0
        );
        assert_eq!(
            evt_in_info.action_id.seq_num,
            denm_evt.denm.management.action_id.sequence_number.0
        );
    }
}
