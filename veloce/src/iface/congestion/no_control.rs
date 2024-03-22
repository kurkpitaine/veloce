use crate::{
    phy::ChannelBusyRatio,
    time::{Duration, Instant},
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

    fn can_tx(&self, _timestamp: Instant) -> bool {
        true
    }

    fn tx_at(&self, _prio: Option<crate::wire::ieee80211::AccessCategory>) -> Instant {
        Instant::ZERO
    }

    fn tx_interval(&self) -> Duration {
        Duration::ZERO
    }

    fn notify(&mut self, _tx_at: Instant, _duration: Duration) {}

    fn update_cbr(&mut self, _timestamp: Instant, _cbr: ChannelBusyRatio) {}
}
