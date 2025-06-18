use crate::{
    common::PotiFix,
    security::privacy::{c2c::C2CStrategy, no::NoStrategy, threshold::ThresholdStrategy},
    time::Instant,
};

pub(crate) mod c2c;
pub(crate) mod no;
pub(crate) mod threshold;

pub(crate) trait PrivacyControllerTrait {
    /// Run the strategy state machine with the current position and timestamp.
    /// Returns true if the strategy state machine has changed it's internal state,
    /// which should be lead to a change in the signature private key + AT certificate.
    fn run(&mut self, timestamp: Instant) -> bool;
    /// Return the instant the strategy might be run at.
    fn run_at(&self) -> Option<Instant>;
    /// Indicate a newly acquired GNSS position to the strategy state machine.
    fn notify_position(&mut self, position: PotiFix, timestamp: Instant);
    /// Indicate to the strategy state machine that a signature has been emitted.
    fn notify_signature(&mut self);
    /// Reset the strategy state machine. Depending on the strategy, this may
    /// significate a total reset of the strategy state machine, or just a reset
    /// to the beginning of the current internal state.
    fn reset(&mut self, now: Instant);
}

/// Privacy strategy deals with maintaining the ITS station anonymous on the field.
/// It implements rules for AT certificates rotation ensuring ITS station stays anonymous.
/// Several strategies are available, each one with its own rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PrivacyStrategy {
    /// No strategy is used, which means the AT certificate is always the same and never changes.
    NoStrategy,
    /// Threshold strategy is based on the number of signatures emitted with an AT certificate.
    /// When the number of signatures reaches a certain threshold, the strategy switches to
    /// the next AT certificate available in the trust chain, in a round-robin fashion.
    Threshold(u32),
    /// Car2Car is based on the C2C Consortium Vehicle C-ITS station profile, covering
    /// requirements RS_BSP_520 to RS_BSP_525. Takes an u64 as a seed for selecting random
    /// distance values.
    Car2Car(u64),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum PrivacyController {
    /// No strategy is used, which means the AT certificate is always the same and never changes.
    None(NoStrategy),
    /// Threshold strategy is based on the number of signatures emitted with an AT certificate.
    Threshold(ThresholdStrategy),
    /// Car2Car is based on the C2C Consortium Vehicle C-ITS station profile.
    Car2Car(C2CStrategy),
}

impl PrivacyController {
    pub fn new(strategy: PrivacyStrategy) -> Self {
        match strategy {
            PrivacyStrategy::NoStrategy => PrivacyController::None(NoStrategy::new()),
            PrivacyStrategy::Threshold(t) => {
                PrivacyController::Threshold(ThresholdStrategy::new(t))
            }
            PrivacyStrategy::Car2Car(seed) => PrivacyController::Car2Car(C2CStrategy::new(seed)),
        }
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut dyn PrivacyControllerTrait {
        match self {
            PrivacyController::None(n) => n,
            PrivacyController::Threshold(t) => t,
            PrivacyController::Car2Car(c) => c,
        }
    }

    #[inline]
    pub fn inner(&self) -> &dyn PrivacyControllerTrait {
        match self {
            PrivacyController::None(n) => n,
            PrivacyController::Threshold(t) => t,
            PrivacyController::Car2Car(c) => c,
        }
    }
}
