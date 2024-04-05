use heapless::{FnvIndexMap, Vec};

use crate::{
    common::{PacketBuffer, PacketBufferMeta},
    config::{
        DCC_QUEUE_ENTRY_COUNT, DCC_QUEUE_SIZE, GN_CBR_G_TRIGGER_INTERVAL, GN_LOC_TABLE_ENTRY_COUNT,
    },
    phy::ChannelBusyRatio,
    time::{Duration, Instant},
    wire::{ieee80211::AccessCategory, EthernetAddress, GeonetRepr},
};

use super::{location_table::LocationTable, GeonetPacket};

pub(crate) mod limeric;
pub(crate) mod no_control;

pub(crate) use self::{Error as CongestionError, Success as CongestionSuccess};

pub(crate) trait RateController {
    /// Run the Rate Control algorithm once.
    fn run(&mut self, timestamp: Instant);
    /// Return the instant the Rate Control algorithm should be run at.
    fn run_at(&self) -> Instant;
    /// Return wether Rate Control algorithm allows for transmission.
    fn can_tx(&self, timestamp: Instant) -> bool;
    /// Get next instant where transmission is allowed,
    /// for corresponding priority queue. If `prio` is none, it
    /// returns the minimal waiting time between all the queues.
    fn tx_allowed_at(&self, prio: Option<AccessCategory>) -> Instant;
    /// Get allowed duration between transmissions.
    fn tx_interval(&self) -> Duration;
    /// Notify DCC algorithm for transmission activity,
    /// at `tx_at` time instant, and for over-the-air
    /// transmission `duration`.
    fn notify_tx(&mut self, tx_at: Instant, duration: Duration);
    /// Update CBR value.
    fn update_cbr(&mut self, timestamp: Instant, cbr: ChannelBusyRatio);
    /// Returns the local CBR value.
    fn local_cbr(&self) -> ChannelBusyRatio;
    /// Returns the CBR target value.
    fn target_cbr(&self) -> ChannelBusyRatio;
}

/// Dcc queued data type.
#[derive(Debug)]
pub(crate) struct QueuedPacket {
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
pub(crate) struct Congestion {
    /// Rate control algorithm.
    pub controller: AnyController,
    /// DCC queues. One queue for each priority category.
    pub queues: FnvIndexMap<AccessCategory, DccQueue, 4>,
    /// Instant at which queues should be checked for sending packets.
    /// Optional as queues could be empty.
    pub egress_at: Option<Instant>,
    /// Global channel busy ratio, calculated from [LocationTable] entries.
    global_cbr: ChannelBusyRatio,
    /// Previous local channel busy ratio.
    prev_local_cbr: ChannelBusyRatio,
    /// Instant at which `global_cbr` value should be (re)computed.
    compute_global_cbr_at: Instant,
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

        Congestion {
            controller,
            queues,
            egress_at: None,
            global_cbr: ChannelBusyRatio::from_ratio(0.0),
            prev_local_cbr: ChannelBusyRatio::from_ratio(0.0),
            compute_global_cbr_at: Instant::ZERO,
        }
    }

    /// Returns the local Channel Busy Ratio value.
    pub fn local_cbr(&self) -> ChannelBusyRatio {
        self.controller.inner().local_cbr()
    }

    /// Returns the global Channel Busy Ratio value.
    pub fn global_cbr(&self) -> ChannelBusyRatio {
        self.global_cbr
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
        if !has_pkt && self.controller.inner().tx_allowed_at(Some(cat)) <= timestamp {
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

        // Schedule for egress.
        if self.egress_at.is_none() {
            self.egress_at = Some(timestamp + self.controller.inner().tx_interval());
        }

        Ok(Success::Enqueued)
    }

    /// Computes the Global CBR value, as defined in ETSI TS 102 636-4-2 V1.3.1
    /// and schedule for next computing instant.
    pub(super) fn compute_global_cbr(
        &mut self,
        location_table: &LocationTable,
        timestamp: Instant,
    ) {
        if self.compute_global_cbr_at < timestamp {
            return;
        }

        let cbr_values = location_table.local_one_hop_cbr_values(timestamp);
        let target_cbr = self.controller.inner().target_cbr();

        // Step 1 and 3: Calculate the average of CBR_R_0_Hop and CBR_R_1_Hop.
        let (cbr_r_0_hop, cbr_r_1_hop) = {
            let (sum_r_0, sum_r_1) = cbr_values.iter().fold((0.0, 0.0), |acc, e| {
                (acc.0 + e.0.as_ratio(), acc.1 + e.1.as_ratio())
            });
            (
                sum_r_0 / cbr_values.len() as f32,
                sum_r_1 / cbr_values.len() as f32,
            )
        };

        // Split in two vecs.
        let (mut r_0_values, mut r_1_values): (
            Vec<ChannelBusyRatio, GN_LOC_TABLE_ENTRY_COUNT>,
            Vec<ChannelBusyRatio, GN_LOC_TABLE_ENTRY_COUNT>,
        ) = cbr_values.into_iter().unzip();

        // Sort values in reverse order.
        // Safety: we never push NAN in location table.
        r_0_values.sort_unstable_by(|a, b| b.as_ratio().partial_cmp(&a.as_ratio()).unwrap());
        r_1_values.sort_unstable_by(|a, b| b.as_ratio().partial_cmp(&a.as_ratio()).unwrap());

        // Step 2
        let cbr_l_1_hop = if r_0_values.len() > 1 {
            if cbr_r_0_hop > target_cbr.as_ratio() {
                r_0_values[0].as_ratio()
            } else {
                r_0_values[1].as_ratio()
            }
        } else {
            0.0
        };

        // Step 4
        let cbr_l_2_hop = if r_1_values.len() > 1 {
            if cbr_r_1_hop > target_cbr.as_ratio() {
                r_1_values[0].as_ratio()
            } else {
                r_1_values[1].as_ratio()
            }
        } else {
            0.0
        };

        let computed_cbr = [self.prev_local_cbr.as_ratio(), cbr_l_1_hop, cbr_l_2_hop]
            .into_iter()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap(); // Safety: we have 3 values inside the slice.

        self.global_cbr = ChannelBusyRatio::from_ratio(computed_cbr);
        self.prev_local_cbr = self.controller.inner().local_cbr();

        // Re-schedule for next computation.
        self.compute_global_cbr_at = timestamp + GN_CBR_G_TRIGGER_INTERVAL;
    }

    /// Return the minimum time the congestion control service should be polled at.
    pub fn poll_at(&self) -> Option<Instant> {
        let ctrl_run_at = Some(self.controller.inner().run_at());
        let egress_at = self.egress_at;
        let cbrg_at = Some(self.compute_global_cbr_at);

        let instant = [ctrl_run_at, egress_at, cbrg_at];
        instant.into_iter().flatten().min()
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
pub(crate) enum AnyController {
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
