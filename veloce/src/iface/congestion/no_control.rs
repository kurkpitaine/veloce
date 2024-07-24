use crate::{
    phy::ChannelBusyRatio,
    time::{Duration, Instant},
    wire::ieee80211::AccessCategory,
};

use super::RateController;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NoControl;

impl RateController for NoControl {
    fn run(&mut self, _timestamp: Instant) {}

    fn run_at(&self) -> Instant {
        Instant::from_micros_const(i64::MAX)
    }

    fn tx_allowed_at(&self, _prio: Option<AccessCategory>) -> Instant {
        Instant::ZERO
    }

    fn tx_interval(&self) -> Duration {
        Duration::ZERO
    }

    fn notify_tx(&mut self, _tx_at: Instant, _duration: Duration) {}

    fn update_cbr(&mut self, _timestamp: Instant, _cbr: ChannelBusyRatio) {}

    fn target_cbr(&self) -> ChannelBusyRatio {
        ChannelBusyRatio::from_ratio(0.0)
    }

    fn local_cbr(&self) -> ChannelBusyRatio {
        ChannelBusyRatio::from_ratio(0.0)
    }
}
