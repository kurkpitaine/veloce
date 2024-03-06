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

/// DCC dissemination profile.
/// Matched to Geonetworking TrafficClass.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum DccProfile {
    DP0,
    DP1,
    DP2,
    DP3,
}

impl Into<AccessCategory> for DccProfile {
    fn into(self) -> AccessCategory {
        match self {
            DccProfile::DP0 => AccessCategory::Voice,
            DccProfile::DP1 => AccessCategory::Video,
            DccProfile::DP2 => AccessCategory::BestEffort,
            DccProfile::DP3 => AccessCategory::Background,
        }
    }
}

pub trait RateThrottle {
    /// Get delay until next transmission is allowed.
    fn delay(&self, timestamp: Instant) -> Duration;

    /// Get current interval between transmissions.
    fn interval(&self) -> Duration;
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
    dst_hw_addr: EthernetAddress,
    /// Geonet packet data.
    packet: GeonetRepr,
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
pub struct Dcc<TRC: RateThrottle + RateFeedback> {
    /// Rate control algorithm.
    rate_controller: TRC,
    /// DCC queues. One queue for each priority category.
    queues: FnvIndexMap<AccessCategory, DccQueue, 4>,
}

impl<TRC: RateThrottle + RateFeedback> Dcc<TRC> {
    /// Constructs a _Decentralized Congestion Control_ controller.
    pub fn new(rate_controller: TRC) -> Self {
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
        if !has_pkt && self.rate_controller.delay(timestamp) == Duration::ZERO {
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
    /// No existing queue for the requested traffic class.
    NoMatchingQueue,
    /// Generic buffer error, ie: the packet
    /// is too big to fit in the buffer.
    BufferError,
}
