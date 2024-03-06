use heapless::HistoryBuffer;

use crate::time::Duration;
use crate::time::Instant;

use super::RateFeedback;
use super::RateThrottle;

/// Limerick needs at least two CBR measurements on a duration of 200ms.
const CBR_HISTORY_SIZE: usize = 2;

/// Minimum time interval between two consecutive transmissions.
const MIN_INTERVAL: Duration = Duration::from_millis(25);
/// Maximum time interval between two consecutive transmissions.
const MAX_INTERVAL: Duration = Duration::from_secs(1);

/// Parameter values of adaptive approach,
/// as defined in ETSI TS 102 687 v1.2.1, Table 3.
#[derive(Debug)]
pub struct Parameters {
    pub alpha: f32,
    pub beta: f32,
    pub delta_min: f32,
    pub delta_max: f32,
    pub g_minus_max: f32,
    pub g_plus_max: f32,
    pub cbr_target: f32,
    pub cbr_interval: Duration,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            alpha: 0.016,
            beta: 0.0012,
            delta_min: 0.0006,
            delta_max: 0.03,
            g_minus_max: -0.00025,
            g_plus_max: 0.0005,
            cbr_target: 0.68,
            cbr_interval: Duration::from_millis(100),
        }
    }
}

/// The dual-alpha convergence as defined in the publication
/// ["Strengths and Weaknesses of the ETSI Adaptive DCC Algorithm: A Proposal for Improvement"](http://dx.doi.org/10.1109/LCOMM.2019.2906178)
#[derive(Debug)]
pub struct DualAlphaParameters {
    pub alpha_high: f32,
    pub threshold: f32,
}

impl Default for DualAlphaParameters {
    fn default() -> Self {
        Self {
            alpha_high: 0.1,
            threshold: 0.00001,
        }
    }
}

#[derive(Debug)]
pub struct Limeric {
    /// Instant where last transmission occurred.
    last_tx_at: Instant,
    /// Last transmission over-the-air duration.
    last_tx_duration: Duration,
    /// Interval between transmissions.
    interval: Duration,
    /// Limerick algorithm duty cycle.
    duty_cycle: f32,
    /// Current channel load.
    channel_load: f32,
    /// History of CBR values.
    cbr_hist: HistoryBuffer<f32, CBR_HISTORY_SIZE>,
    /// Limerick algorithm parameters.
    params: Parameters,
    /// Optional parameters for Dual Alpha improvement.
    dual_alpha_params: Option<DualAlphaParameters>,
    /// Instant at which reschedule the Limerick algorithm execution.
    reschedule_at: Instant,
}

impl Limeric {
    /// Constructs a new Limerick with provided `params`.
    pub fn new(params: Parameters) -> Self {
        Limeric {
            last_tx_at: Instant::ZERO,
            last_tx_duration: Duration::ZERO,
            interval: MIN_INTERVAL,
            duty_cycle: 0.5 * (params.delta_min + params.delta_max),
            channel_load: 0.0,
            cbr_hist: HistoryBuffer::new(),
            params,
            dual_alpha_params: None,
            reschedule_at: Instant::ZERO,
        }
    }

    /// Enable the Dual Alpha DCC with the provided `dual_alpha_params`.
    pub fn enable_dual_alpha(&mut self, dual_alpha_params: DualAlphaParameters) {
        self.dual_alpha_params = Some(dual_alpha_params);
    }

    /// Add a CBR value inside the CBR history.
    pub fn update_cbr(&mut self, value: f32) {
        let full = self.cbr_hist.is_full();
        self.cbr_hist.write(value);

        if !full {
            self.channel_load = self.cbr_hist_average();
        }
    }

    pub fn poll(&mut self, timestamp: Instant) {
        self.channel_load = self.cbr_hist_average();
        self.duty_cycle = self.calculate_duty_cycle();
        self.reschedule_at = self.schedule_next(timestamp);
        self.update_interval(timestamp);
    }

    /// Schedule for next work.
    pub fn schedule_next(&self, timestamp: Instant) -> Instant {
        let interval = self.params.cbr_interval * 2;
        let next = timestamp + interval;
        let bias = Duration::from_micros(next.total_micros() as u64 % interval.total_micros());

        if bias > self.params.cbr_interval {
            next + interval - bias
        } else {
            next - bias
        }
    }

    /// Recalculate current transmission interval.
    pub fn update_interval(&mut self, timestamp: Instant) {
        let delay = self.last_tx_at + self.interval - timestamp;
        if self.duty_cycle > 0.0 {
            if delay > Duration::from_micros(0) {
                // Apply equation B.2 of TS 102 687 v1.2.1 if gate is closed at the moment
                let interval = (self.last_tx_at.total_micros() as f32 / self.duty_cycle)
                    * ((delay.total_micros() / self.interval.total_micros()) as f32);
                let interval = timestamp - self.last_tx_at + Duration::from_micros(interval as u64);
                self.interval = interval.min(MIN_INTERVAL).max(MAX_INTERVAL);
            } else {
                // use equation B.1 otherwise
                let interval = self.last_tx_at.total_micros() as f32 / self.duty_cycle;
                self.interval = Duration::from_micros(interval as u64)
                    .min(MIN_INTERVAL)
                    .max(MAX_INTERVAL);
            }
        } else {
            // bail out with maximum interval if duty cycle is not positive
            self.interval = MAX_INTERVAL;
        }
    }

    /// Computes the duty cycle value for the Limerick algorithm.
    /// Return value is clamped between 0.0 and 1.0.
    fn calculate_duty_cycle(&self) -> f32 {
        let cbr_delta = self.params.cbr_target - self.channel_load;

        let delta_offset = if cbr_delta > 0.0 {
            (self.params.beta * cbr_delta).min(self.params.g_plus_max)
        } else {
            (self.params.beta * cbr_delta).max(self.params.g_minus_max)
        };

        let mut delta = (1.0 - self.params.alpha) * self.duty_cycle + delta_offset;
        delta = delta.max(self.params.delta_min).min(self.params.delta_max);

        let delta = match &self.dual_alpha_params {
            Some(alpha_params) if self.duty_cycle - delta > alpha_params.threshold => {
                let tmp_delta = (1.0 - alpha_params.alpha_high) * self.duty_cycle + delta_offset;
                tmp_delta
                    .max(self.params.delta_min)
                    .min(self.params.delta_max)
            }
            _ => delta,
        };

        delta.clamp(0.0, 1.0)
    }

    /// Returns the smoothed CBR for step n, ie: equation (1) in
    /// Limerick publication.
    fn smoothed_cbr(&self) -> f32 {
        if self.cbr_hist.is_full() {
            0.5 * self.cbr_hist_average() + 0.5 * self.channel_load
        } else {
            self.channel_load
        }
    }

    /// Computes the mean value of the data inside `cbr_hist`.
    fn cbr_hist_average(&self) -> f32 {
        let sum: f32 = self.cbr_hist.iter().sum();
        let count = self.cbr_hist.len() as f32;
        sum / count
    }
}

impl RateFeedback for Limeric {
    fn notify(&mut self, tx_at: Instant, duration: Duration) {
        let interval = duration.total_micros() as f32 / self.duty_cycle;
        let interval = Duration::from_micros(interval as u64);
        self.interval = interval.min(MIN_INTERVAL).max(MAX_INTERVAL);
        self.last_tx_at = tx_at;
        self.last_tx_duration = duration;
    }
}
impl RateThrottle for Limeric {
    fn delay(&self, timestamp: Instant) -> Duration {
        if timestamp > self.last_tx_at + self.interval {
            Duration::ZERO
        } else {
            self.last_tx_at + self.interval - timestamp
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }
}
