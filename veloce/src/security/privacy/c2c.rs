use core::ops::RangeBounds;

use uom::si::{f64::Length, length::meter};

use crate::{
    common::{PotiFix, PotiPathPoint},
    rand::Rand,
    security::privacy::PrivacyControllerTrait,
    time::{Duration, Instant},
};

/// WaitForGnss Grace Period. Duration of the grace period before the first step of the C2C strategy.
/// `pSecRestartDelay` in C2C Consortium Vehicle C-ITS station profile.
static C2C_STARTUP_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// Travelled distance based generic state. Works like an accumulator from a stream of
/// [PotiPathPoint] values.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct TravelledDistanceState {
    /// Position at which traveled_distance was calculated.
    position: PotiPathPoint,
    /// Accumulated traveled distance.
    traveled_distance: Length,
    /// Distance at which this state transitions to the next state.
    transition_distance: Length,
}

impl TravelledDistanceState {
    /// Create a new [TravelledDistanceState] with the given `position`.
    /// Transition distance is set to a random value
    pub fn new(position: PotiPathPoint, transition_distance: Length) -> Self {
        Self {
            position,
            traveled_distance: Length::new::<meter>(0.0),
            transition_distance,
        }
    }

    /// Travels to the given `position`, accumulating the traveled distance.
    /// Replaces the current position with the given one.
    pub fn travel_to(&mut self, position: PotiPathPoint) {
        self.traveled_distance += self.position.distance_to(&position);
        self.position = position;
    }

    /// Get the remaining distance to travel.
    pub fn remaining_distance(&self) -> Length {
        self.transition_distance - self.traveled_distance
    }

    /// Query whether the state is complete.
    pub fn is_complete(&self) -> bool {
        self.traveled_distance >= self.transition_distance
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum State {
    /// Startup state. To trigger the first certificate change at Veloce startup.
    Startup,
    /// WaitForGnss state. C2CStrategy has been created, but the strategy has not been run yet.
    WaitForGnss,
    /// Grace Period state. Contains the instant at which the grace period ends,
    /// and switches to the next state.
    GracePeriod(Instant, Duration),
    /// Initial state.
    Initial(TravelledDistanceState),
    /// Step 1 state.
    Step1(TravelledDistanceState),
    /// Step 2 state.
    Step2(Instant, Duration),
    /// Step 3 state.
    Step3(TravelledDistanceState),
    /// Cruise state.
    Cruise(TravelledDistanceState),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct C2CStrategy {
    /// Current C2C Strategy state.
    state: State,
    /// Current position.
    maybe_point: Option<PotiPathPoint>,
    /// Random number generator.
    rand: Rand,
}

impl C2CStrategy {
    /// Create a new C2C Privacy Strategy.
    pub fn new(seed: u64) -> Self {
        Self {
            state: State::Startup,
            maybe_point: None,
            rand: Rand::new(seed),
        }
    }

    /// Set the current position in the strategy.
    fn set_position(&mut self, position: PotiFix, timestamp: Instant) {
        let stationary = position.is_stationary().unwrap_or(false);
        let maybe_point = Self::fix_to_path_point(&position);

        match (&mut self.state, maybe_point) {
            (State::WaitForGnss, _) if position.is_mode_3d() => {
                net_debug!(
                    "WaitForGnss ended at {}, transitioning to Grace Period",
                    timestamp
                );
                self.maybe_point = maybe_point;
                self.state = State::GracePeriod(
                    timestamp + C2C_STARTUP_GRACE_PERIOD,
                    C2C_STARTUP_GRACE_PERIOD,
                );
            }
            (State::Initial(st), Some(point)) => {
                if !stationary {
                    self.maybe_point = maybe_point;
                    st.travel_to(point);
                } else {
                    net_trace!("Initial state - skipping stationary position");
                }
            }
            (State::Step1(st), Some(point)) => {
                if !stationary {
                    self.maybe_point = maybe_point;
                    st.travel_to(point);
                } else {
                    net_trace!("Step 1 state - skipping stationary position");
                }
            }
            (State::Step3(st), Some(point)) => {
                if !stationary {
                    self.maybe_point = maybe_point;
                    st.travel_to(point);
                } else {
                    net_trace!("Step 3 state - skipping stationary position");
                }
            }
            (State::Cruise(st), Some(point)) => {
                if !stationary {
                    self.maybe_point = maybe_point;
                    st.travel_to(point);
                } else {
                    net_trace!("Cruise state - skipping stationary position");
                }
            }
            _ => {}
        }
    }

    /// Run the C2C Privacy Strategy with the newly provided position and timestamp.
    fn run_inner(&mut self, timestamp: Instant) -> bool {
        let change = match (&mut self.state, self.maybe_point) {
            (State::Startup, _) => {
                net_trace!("Startup state ended - transitioning to WaitForGnss");
                self.state = State::WaitForGnss;
                true
            }
            (State::WaitForGnss, _) => {
                net_trace!("WaitForGnss state - waiting for 3D position fix");
                false
            }
            (State::GracePeriod(end, _), Some(point)) if timestamp >= *end => {
                net_debug!(
                    "Grace Period state ended at {}, transitioning to Initial state",
                    end
                );
                let transition_distance = self.random_meters(800..1500);
                self.state =
                    State::Initial(TravelledDistanceState::new(point, transition_distance));

                true
            }
            (State::GracePeriod(end, _), None) if timestamp >= *end => {
                net_error!("Cannot transition to Initial state: no position");
                false
            }
            (State::GracePeriod(end, _), _) => {
                net_trace!("Grace Period state ends in {} secs", timestamp - *end);
                false
            }
            (State::Initial(st), Some(point)) => {
                if st.is_complete() {
                    net_debug!("Initial state completed, transitioning to Step 1 state");
                    self.state = State::Step1(TravelledDistanceState::new(
                        point,
                        Length::new::<meter>(800.0),
                    ));
                    true
                } else {
                    net_trace!(
                        "Initial state remaining distance: {} meters",
                        st.remaining_distance().get::<meter>()
                    );
                    false
                }
            }
            (State::Initial(_), None) => {
                net_error!("Cannot run Initial state: no position");
                false
            }
            (State::Step1(st), Some(_)) => {
                if st.is_complete() {
                    net_debug!("Step 1 state completed, transitioning to Step 2 state");

                    let transition_duration = self.random_seconds(120..360);
                    self.state = State::Step2(timestamp + transition_duration, transition_duration);
                    true
                } else {
                    net_trace!(
                        "Step 1 State remaining distance: {} meters",
                        st.remaining_distance().get::<meter>()
                    );
                    false
                }
            }
            (State::Step1(_), None) => {
                net_error!("Cannot run Step 1 state: no position");
                false
            }
            (State::Step2(end, _), Some(point)) if timestamp >= *end => {
                net_debug!(
                    "Step 2 state ended at {}, transitioning to Step 3 state",
                    end
                );
                let transition_distance = self.random_meters(10000..20000);

                self.state = State::Step3(TravelledDistanceState::new(point, transition_distance));
                true
            }
            (State::Step2(end, _), None) if timestamp >= *end => {
                net_error!("Cannot transition to Step 3 state: no position");
                false
            }
            (State::Step2(end, _), _) => {
                net_trace!("Step 2 state ends in {} secs", timestamp - *end);
                false
            }
            (State::Step3(st), Some(point)) => {
                if st.is_complete() {
                    net_debug!("Step 3 state completed, transitioning to Cruise state");

                    let transition_distance = self.random_meters(25000..35000);
                    self.state =
                        State::Cruise(TravelledDistanceState::new(point, transition_distance));
                    true
                } else {
                    net_trace!(
                        "Step 3 state remaining distance: {} meters",
                        st.remaining_distance().get::<meter>()
                    );
                    false
                }
            }
            (State::Step3(_), None) => {
                net_error!("Cannot run Step 3 state: no position");
                false
            }
            (State::Cruise(st), Some(point)) => {
                if st.is_complete() {
                    net_debug!("Cruise state completed, transitioning to a new Cruise state");

                    let transition_distance = self.random_meters(25000..35000);
                    self.state =
                        State::Cruise(TravelledDistanceState::new(point, transition_distance));
                    true
                } else {
                    net_trace!(
                        "Cruise state remaining distance: {} meters",
                        st.remaining_distance().get::<meter>()
                    );
                    false
                }
            }
            (State::Cruise(_), None) => {
                net_error!("Cannot run Cruise state: no position");
                false
            }
        };

        change
    }

    /// Get a random distance value in `range` meters.
    #[inline]
    fn random_meters<R: RangeBounds<u32>>(&mut self, range: R) -> Length {
        Length::new::<meter>(self.rand.rand_range(range).into())
    }

    /// Get a random duration value in `range` seconds.
    #[inline]
    fn random_seconds<R: RangeBounds<u32>>(&mut self, range: R) -> Duration {
        Duration::from_secs(self.rand.rand_range(range).into())
    }

    #[inline]
    fn fix_to_path_point(fix: &PotiFix) -> Option<PotiPathPoint> {
        PotiPathPoint::try_from(fix).ok()
    }
}

impl PrivacyControllerTrait for C2CStrategy {
    fn run(&mut self, timestamp: Instant) -> bool {
        self.run_inner(timestamp)
    }

    fn run_at(&self) -> Option<Instant> {
        match self.state {
            State::Startup => Some(Instant::ZERO),
            State::GracePeriod(at, _) => Some(at),
            State::Step2(at, _) => Some(at),
            _ => None,
        }
    }

    fn notify_position(&mut self, position: PotiFix, timestamp: Instant) {
        self.set_position(position, timestamp);
    }

    fn notify_signature(&mut self) {}

    fn reset(&mut self, now: Instant) {
        net_debug!("Resetting current C2C privacy strategy state");
        match &mut self.state {
            State::Startup => self.state = State::Startup,
            State::WaitForGnss => self.state = State::WaitForGnss,
            State::GracePeriod(_, d) => self.state = State::GracePeriod(now + *d, *d),
            State::Initial(st) => st.traveled_distance = Length::new::<meter>(0.0),
            State::Step1(st) => st.traveled_distance = Length::new::<meter>(0.0),
            State::Step2(_, d) => self.state = State::Step2(now + *d, *d),
            State::Step3(st) => st.traveled_distance = Length::new::<meter>(0.0),
            State::Cruise(st) => st.traveled_distance = Length::new::<meter>(0.0),
        }
    }
}
