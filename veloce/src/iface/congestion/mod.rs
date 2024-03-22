use heapless::FnvIndexMap;

use crate::{
    common::{PacketBuffer, PacketBufferMeta},
    config::{DCC_QUEUE_ENTRY_COUNT, DCC_QUEUE_SIZE},
    phy::ChannelBusyRatio,
    time::{Duration, Instant},
    wire::{ieee80211::AccessCategory, EthernetAddress, GeonetRepr},
};

use super::GeonetPacket;

pub(super) mod limeric;
pub(super) mod no_control;

pub(super) use self::{Error as CongestionError, Success as CongestionSuccess};

pub(super) trait RateController {
    /// Run the Rate Control algorithm once.
    fn run(&mut self, timestamp: Instant, cbr: ChannelBusyRatio);
    /// Return the instant the Rate Control algorithm should be run at.
    fn run_at(&self) -> Instant;
    /// Return wether Rate Control algorithm allows for transmission.
    fn can_tx(&self, timestamp: Instant) -> bool;
    /// Get next instant where transmission is allowed,
    /// for corresponding priority queue. If `prio` is none, it
    /// returns the minimal waiting time between all the queues.
    fn tx_at(&self, prio: Option<AccessCategory>) -> Instant;
    /// Get current interval between transmissions.
    fn tx_interval(&self) -> Duration;
    /// Notify DCC algorithm for transmission activity,
    /// at `tx_at` time instant, and for over-the-air
    /// transmission `duration`.
    fn notify(&mut self, tx_at: Instant, duration: Duration);
}

/// Dcc queued data type.
#[derive(Debug)]
pub(super) struct QueuedPacket {
    /// Destination hardware address.
    pub dst_hw_addr: EthernetAddress,
    /// Geonet packet data.
    pub packet: GeonetRepr,
}

impl PacketBufferMeta for QueuedPacket {
    fn size(&self) -> usize {
        self.packet.size()
    }

    fn lifetime(&self) -> Duration {
        self.packet.lifetime()
    }
}

type DccQueue = PacketBuffer<QueuedPacket, DCC_QUEUE_ENTRY_COUNT, DCC_QUEUE_SIZE>;

/// _Decentralized Congestion Control_ controller.
#[derive(Debug)]
pub(super) struct Congestion {
    /// Rate control algorithm.
    pub controller: AnyController,
    /// DCC queues. One queue for each priority category.
    pub queues: FnvIndexMap<AccessCategory, DccQueue, 4>,
}

impl Congestion {
    /// Constructs a _Decentralized Congestion Control_ controller.
    pub fn new(controller: AnyController) -> Self {
        let mut queues = FnvIndexMap::new();
        queues
            .insert(AccessCategory::Background, DccQueue::new())
            .expect("Cannot insert AccessCategory::Background DCC queue");
        queues
            .insert(AccessCategory::BestEffort, DccQueue::new())
            .expect("Cannot insert AccessCategory::BestEffort DCC queue");
        queues
            .insert(AccessCategory::Video, DccQueue::new())
            .expect("Cannot insert AccessCategory::Video DCC queue");
        queues
            .insert(AccessCategory::Voice, DccQueue::new())
            .expect("Cannot insert AccessCategory::Voice DCC queue");

        Congestion { controller, queues }
    }

    pub fn dispatch(
        &mut self,
        packet: &GeonetPacket,
        dst_hw_addr: EthernetAddress,
        timestamp: Instant,
    ) -> Result<Success, Error> {
        // Short circuit if no controller.
        if let AnyController::None(_) = self.controller {
            return Ok(Success::ImmediateTx);
        }

        let gn_repr = packet.geonet_repr();
        let cat = gn_repr.traffic_class().access_category();

        // is there any packet enqueued with equal or higher priority?
        let has_pkt = self
            .queues
            .iter()
            .filter(|e| *e.0 >= cat && !e.1.is_empty())
            .count()
            > 0;

        // Check for immediate transmission
        if !has_pkt && self.controller.inner().tx_at(Some(cat)) <= timestamp {
            return Ok(Success::ImmediateTx);
        }

        // Enqueue packet
        let Some(queue) = self.queues.get_mut(&cat) else {
            return Err(Error::NoMatchingQueue);
        };

        let pkt = QueuedPacket {
            dst_hw_addr,
            packet: gn_repr,
        };

        // Special treatment for empty payload.
        let payload = match packet.payload().into_option() {
            Some(pl) => pl,
            None => &[],
        };

        queue
            .enqueue(pkt, payload, timestamp)
            .map_err(|_| Error::BufferError)?;

        Ok(Success::Enqueued)
    }

    /// Return the minimum time the DCC service should be polled at.
    pub fn poll_at(&self) -> Option<Instant> {
        match &self.controller {
            AnyController::None(_) => None,
            AnyController::Limeric(lim) => {
                let tx_at = lim.tx_at(None);
                Some(lim.run_at().min(tx_at))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// DCC success result.
pub(super) enum Success {
    /// Packet should be transmitted immediately.
    ImmediateTx,
    /// Packet should be enqueued.
    Enqueued,
}

/// DCC error type.
pub(super) enum Error {
    /// The hardware device transmit buffer is full. Try again later.
    Exhausted,
    /// No existing queue for the requested traffic class.
    NoMatchingQueue,
    /// Generic buffer error, ie: the packet
    /// is too big to fit in the buffer.
    BufferError,
}

/// Transmit Rate Control controller algorithm.
#[derive(Debug)]
pub(super) enum AnyController {
    /// No rate controller.
    None(no_control::NoControl),
    /// Limeric algorithm.
    Limeric(limeric::Limeric),
}

impl AnyController {
    /// Create a new congestion controller.
    /// `AnyController::new()` selects by default no congestion controller.
    ///
    /// Users can also select a congestion controller manually by [`super::Interface::set_congestion_control()`]
    /// method at run-time.
    #[allow(unreachable_code)]
    #[inline]
    pub fn new() -> Self {
        AnyController::None(no_control::NoControl)
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut dyn RateController {
        match self {
            AnyController::None(n) => n,
            AnyController::Limeric(l) => l,
        }
    }

    #[inline]
    pub fn inner(&self) -> &dyn RateController {
        match self {
            AnyController::None(n) => n,
            AnyController::Limeric(l) => l,
        }
    }
}
