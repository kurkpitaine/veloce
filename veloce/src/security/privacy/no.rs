use crate::{common::PotiFix, time::Instant};

use super::PrivacyControllerTrait;

/// A no strategy privacy controller.
/// This strategy does not make certificate rotations.
/// It only triggers a change at construction to load the certificate.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct NoStrategy(bool);

impl NoStrategy {
    pub(crate) fn new() -> Self {
        Self(false)
    }
}

impl PrivacyControllerTrait for NoStrategy {
    fn run(&mut self, _timestamp: Instant) -> bool {
        if self.0 {
            false
        } else {
            self.0 = true;
            true
        }
    }

    fn run_at(&self) -> Option<Instant> {
        if self.0 {
            None
        } else {
            Some(Instant::ZERO)
        }
    }

    fn notify_position(&mut self, _position: PotiFix, _timestamp: Instant) {}

    fn notify_signature(&mut self) {}

    fn reset(&mut self, _now: Instant) {}
}
