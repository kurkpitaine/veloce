use heapless::FnvIndexMap;

use crate::{
    common::{PacketBuffer, PacketBufferMeta},
    config::{DCC_QUEUE_ENTRY_COUNT, DCC_QUEUE_SIZE},
    time::{Duration, Instant},
    wire::{ieee80211::AccessCategory, EthernetAddress, GeonetRepr},
};

use super::GeonetPacket;

mod limeric;
pub use limeric::{
    DualAlphaParameters as LimericDualAlphaParameters, Limeric as LimericTrc,
    Parameters as LimericParameters,
};

pub(crate) use self::{Error as DccError, Success as DccSuccess};

pub trait RateControl {
    /// Run the Rate Control algorithm once.
    fn run(&mut self, timestamp: Instant);
    /// Return the instant the Rate Control algorithm should be run at.
    fn run_at(&self) -> Instant;
}

pub trait RateThrottle {
    /// Return wether Rate Control algorithm allows for transmission.
    fn can_tx(&self, timestamp: Instant) -> bool;
    /// Get next instant where transmission is allowed,
    /// for corresponding priority queue. If `prio` is none, it
    /// returns the minimal waiting time between all the queues.
    fn tx_at(&self, prio: Option<AccessCategory>) -> Instant;

    /// Get current interval between transmissions.
    fn tx_interval(&self) -> Duration;
}

pub trait RateFeedback {
    /// Notify DCC algorithm for transmission activity,
    /// at `tx_at` time instant, and for over-the-air
    /// transmission `duration`.
    fn notify(&mut self, tx_at: Instant, duration: Duration);
}

/// Dcc queued data type.
#[derive(Debug)]
pub struct QueuedPacket {
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
pub struct Dcc {
    /// Rate control algorithm.
    pub rate_controller: Controller,
    /// DCC queues. One queue for each priority category.
    pub queues: FnvIndexMap<AccessCategory, DccQueue, 4>,
}

impl Dcc {
    /// Constructs a _Decentralized Congestion Control_ controller.
    pub fn new(rate_controller: Controller) -> Self {
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

        Dcc {
            rate_controller,
            queues,
        }
    }

    pub(crate) fn dispatch(
        &mut self,
        packet: &GeonetPacket,
        dst_hw_addr: EthernetAddress,
        timestamp: Instant,
    ) -> Result<Success, Error> {
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
        if !has_pkt && self.rate_controller.tx_at(Some(cat)) <= timestamp {
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
    pub(crate) fn poll_at(&self) -> Instant {
        let tx_at = self.rate_controller.tx_at(None);
        self.rate_controller.run_at().min(tx_at)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// DCC success result.
pub(crate) enum Success {
    /// Packet should be transmitted immediately.
    ImmediateTx,
    /// Packet should be enqueued.
    Enqueued,
}

/// DCC error type.
pub(crate) enum Error {
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
pub enum Controller {
    /// Limeric algorithm.
    Limeric(LimericTrc),
}

impl RateControl for Controller {
    fn run(&mut self, timestamp: Instant) {
        match self {
            Controller::Limeric(l) => l.run(timestamp),
        }
    }

    fn run_at(&self) -> Instant {
        match self {
            Controller::Limeric(l) => l.run_at(),
        }
    }
}

impl RateFeedback for Controller {
    fn notify(&mut self, tx_at: Instant, duration: Duration) {
        match self {
            Controller::Limeric(l) => l.notify(tx_at, duration),
        }
    }
}

impl RateThrottle for Controller {
    fn can_tx(&self, timestamp: Instant) -> bool {
        match self {
            Controller::Limeric(l) => l.can_tx(timestamp),
        }
    }

    fn tx_at(&self, prio: Option<AccessCategory>) -> Instant {
        match self {
            Controller::Limeric(l) => l.tx_at(prio),
        }
    }

    fn tx_interval(&self) -> Duration {
        match self {
            Controller::Limeric(l) => l.tx_interval(),
        }
    }
}
