use crate::{common::PotiFix, time::Instant};

use super::PrivacyControllerTrait;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct ThresholdStrategy {
    /// Whether the strategy has been triggered at startup.
    startup_triggered: bool,
    /// Number of allowed signatures before triggering a certificate change.
    limit: u32,
    /// Number of signatures emitted.
    num_sigs: u32,
}

impl ThresholdStrategy {
    /// Create a new [ThresholdStrategy] with the given `limit`.
    pub fn new(limit: u32) -> Self {
        Self {
            startup_triggered: false,
            limit,
            num_sigs: 0,
        }
    }

    /// Query whether the strategy is complete.
    pub fn is_complete(&self) -> bool {
        self.num_sigs >= self.limit
    }
}

impl PrivacyControllerTrait for ThresholdStrategy {
    fn run(&mut self, _timestamp: Instant) -> bool {
        if self.startup_triggered {
            self.is_complete()
        } else {
            self.startup_triggered = true;
            true
        }
    }

    fn run_at(&self) -> Option<Instant> {
        if self.startup_triggered {
            None
        } else {
            Some(Instant::ZERO)
        }
    }

    fn notify_position(&mut self, _position: PotiFix, _timestamp: Instant) {}

    fn notify_signature(&mut self) {
        self.num_sigs += 1;
    }

    fn reset(&mut self, _now: Instant) {
        self.num_sigs = 0;
    }
}
