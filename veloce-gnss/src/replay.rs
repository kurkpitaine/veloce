use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    iter::{Cycle, Peekable},
    path::Path,
    vec::IntoIter,
};

use chrono::{NaiveTime, TimeDelta, Utc};
use nmea::{
    sentences::{
        AamData, BwcData, BwwData, DbkData, DbsData, GgaData, GllData, GnsData, GstData, GsvData,
        HdtData, MdaData, MtwData, MwvData, TtmData, WncData, ZfoData, ZtgData,
    },
    Nmea, ParseResult, SentenceType,
};
use uom::si::f64::{Angle, Velocity};
use uom::si::{angle::degree, f64::Length, length::meter};

use veloce::{
    time::{Duration, Instant},
    types::meter_per_second,
};

use crate::{FixMode, GpsInfo};

/// Newtype pattern for NMEA sentences because clone is not implemented for [ParseResult].
#[derive(Debug)]
struct NmeaSentenceWrapper(ParseResult);

impl NmeaSentenceWrapper {
    /// Get a reference on the timestamp of the sentence, if any.
    pub fn timestamp(&self) -> Option<&NaiveTime> {
        match &self.0 {
            ParseResult::BWC(a) => a.fix_time.as_ref(),
            ParseResult::GBS(a) => a.time.as_ref(),
            ParseResult::GGA(a) => a.fix_time.as_ref(),
            ParseResult::GLL(a) => a.fix_time.as_ref(),
            ParseResult::GNS(a) => a.fix_time.as_ref(),
            ParseResult::RMC(a) => a.fix_time.as_ref(),
            ParseResult::ZDA(a) => a.utc_time.as_ref(),
            ParseResult::ZFO(a) => a.fix_time.as_ref(),
            ParseResult::ZTG(a) => a.fix_time.as_ref(),
            _ => None,
        }
    }
}

impl Clone for NmeaSentenceWrapper {
    fn clone(&self) -> Self {
        let res = match &self.0 {
            ParseResult::AAM(a) => ParseResult::AAM(AamData { ..*a }),
            ParseResult::ALM(a) => ParseResult::ALM(*a),
            ParseResult::APA(a) => ParseResult::APA(a.clone()),
            ParseResult::BOD(a) => ParseResult::BOD(*a),
            ParseResult::BWC(a) => ParseResult::BWC(BwcData { ..*a }),
            ParseResult::BWW(a) => ParseResult::BWW(BwwData { ..*a }),
            ParseResult::DBK(a) => ParseResult::DBK(DbkData { ..*a }),
            ParseResult::DBS(a) => ParseResult::DBS(DbsData { ..*a }),
            ParseResult::DPT(a) => ParseResult::DPT(*a),
            ParseResult::GBS(a) => ParseResult::GBS(*a),
            ParseResult::GGA(a) => ParseResult::GGA(GgaData { ..*a }),
            ParseResult::GLL(a) => ParseResult::GLL(GllData { ..*a }),
            ParseResult::GNS(a) => ParseResult::GNS(GnsData { ..*a }),
            ParseResult::GSA(a) => ParseResult::GSA(a.clone()),
            ParseResult::GST(a) => ParseResult::GST(GstData { ..*a }),
            ParseResult::GSV(a) => ParseResult::GSV({
                GsvData {
                    sats_info: a.sats_info.clone(),
                    ..*a
                }
            }),
            ParseResult::HDT(a) => ParseResult::HDT(HdtData { ..*a }),
            ParseResult::MDA(a) => ParseResult::MDA(MdaData { ..*a }),
            ParseResult::MTW(a) => ParseResult::MTW(MtwData { ..*a }),
            ParseResult::MWV(a) => ParseResult::MWV(MwvData { ..*a }),
            ParseResult::RMC(a) => ParseResult::RMC(*a),
            ParseResult::TTM(a) => ParseResult::TTM(TtmData {
                target_name: a.target_name.clone(),
                ..*a
            }),
            ParseResult::TXT(a) => ParseResult::TXT(*a),
            ParseResult::VHW(a) => ParseResult::VHW(a.clone()),
            ParseResult::VTG(a) => ParseResult::VTG(*a),
            ParseResult::WNC(a) => ParseResult::WNC(WncData { ..*a }),
            ParseResult::ZDA(a) => ParseResult::ZDA(a.clone()),
            ParseResult::ZFO(a) => ParseResult::ZFO(ZfoData { ..*a }),
            ParseResult::ZTG(a) => ParseResult::ZTG(ZtgData { ..*a }),
            ParseResult::PGRMZ(a) => ParseResult::PGRMZ(*a),
            ParseResult::Unsupported(a) => ParseResult::Unsupported(*a),
        };

        NmeaSentenceWrapper(res)
    }
}

#[derive(Debug)]
pub enum ReplayError<'a> {
    /// IO error.
    Io(io::Error),
    /// NMEA error.
    Nmea(nmea::Error<'a>),
}

pub type ReplayResult<'a, T> = Result<T, ReplayError<'a>>;

/// Re-player of NMEA sentences.
#[derive(Debug)]
pub struct Replay {
    /// Never ending iterator over filtered NMEA sentences from file.
    cycle: Peekable<Cycle<IntoIter<(NmeaSentenceWrapper, String)>>>,
    /// Gps position.
    position: GpsInfo,
    /// NMEA data temp cache. Used for building [Self::position].
    cache: Nmea,
    /// Rewind delay, ie: delay before rewinding to the beginning of the sequence.
    rewind_delay: Duration,
    /// Instant at which the re-player should be polled at.
    next_sentence_at: Instant,
}

impl Replay {
    /// Constructs a new [Replay] which will read from the given `file`. [Replay] will rewind
    /// to the beginning of the sequence when end of file is reached and start another playing.
    /// Repetitions will be delayed by `rewind_delay` .
    /// Only sentences of type `GGA` and `RMC` will be processed, others will be ignored.
    ///
    /// # Panics
    /// This function panics if NMEA sentences are invalid.
    pub fn new(file: &Path, rewind_delay: Duration) -> ReplayResult<Replay> {
        let file = File::open(file).map_err(ReplayError::Io)?;
        let reader = BufReader::new(file);

        let sentences = reader
            .lines()
            .map(|l| l.unwrap())
            .filter_map(|line| {
                // Ignore GPGSA sentences, NMEA parser is bugged.
                if line.starts_with("$GPGSA") {
                    return None;
                }
                Some((NmeaSentenceWrapper(nmea::parse_str(&line).unwrap()), line))
            })
            .collect::<Vec<_>>();

        Ok(Self {
            cycle: sentences.into_iter().cycle().peekable(),
            position: Default::default(),
            cache: Nmea::create_for_navigation(&[SentenceType::RMC, SentenceType::GGA]).unwrap(),
            rewind_delay,
            next_sentence_at: Instant::ZERO,
        })
    }

    /// Fetch the position.
    pub fn fetch_position(&self) -> GpsInfo {
        self.position
    }

    /// Processes a GPS sentence present in the replay file.
    ///
    /// This function returns a boolean value indicating whether a new position is available or not.
    pub fn poll(&mut self, timestamp: Instant) -> bool {
        if timestamp < self.next_sentence_at {
            return false;
        }

        // First we call next() to get the value.
        let (current, current_str) = self.cycle.next().unwrap_or_else(|| unreachable!());
        let current_tst_opt = current.timestamp().cloned();

        let ready = self.update_cache(&current_str);

        // Then we call peek() to see when the next sentence will have to be processed.
        let (next, _) = self.cycle.peek().unwrap_or_else(|| unreachable!());
        match (next.timestamp(), current_tst_opt) {
            (Some(next_tst), Some(current_tst)) => {
                let delta = *next_tst - current_tst;

                if delta >= TimeDelta::zero() {
                    self.next_sentence_at =
                        timestamp + Duration::from_millis(delta.num_milliseconds().unsigned_abs());
                } else {
                    // Rewind to the beginning of the sequence.
                    self.cache =
                        Nmea::create_for_navigation(&[SentenceType::RMC, SentenceType::GGA])
                            .unwrap();
                    self.next_sentence_at = timestamp + self.rewind_delay;
                }
            }
            _ => {
                // Schedule for immediate polling.
                self.next_sentence_at = timestamp;
            }
        }

        ready
    }

    /// Return the instant at which the re-player should be polled.
    pub fn poll_at(&self) -> Instant {
        self.next_sentence_at
    }

    /// Return the duration to wait until the next call to [Self::poll].
    pub fn poll_delay(&self, timestamp: Instant) -> Duration {
        self.next_sentence_at - timestamp
    }

    fn update_cache(&mut self, sentence: &str) -> bool {
        match self.cache.parse_for_fix(sentence) {
            Ok(_) => {
                self.position.fix.time = Some(Utc::now());

                let mode = match (
                    self.cache.latitude(),
                    self.cache.longitude(),
                    self.cache.altitude(),
                ) {
                    (Some(_), Some(_), Some(_)) => FixMode::Fix3d,
                    (Some(_), Some(_), None) => FixMode::Fix2d,
                    _ => FixMode::NoFix,
                };

                self.position.fix.mode = mode;
                self.position.fix.latitude = self.cache.latitude.map(Angle::new::<degree>);
                self.position.fix.longitude = self.cache.longitude.map(Angle::new::<degree>);
                self.position.fix.altitude = self
                    .cache
                    .altitude
                    .map(|alt| Length::new::<meter>(alt.into()));

                self.position.fix.track = self
                    .cache
                    .true_course
                    .map(|track| Angle::new::<degree>(track.into()));

                self.position.fix.speed = self
                    .cache
                    .speed_over_ground
                    .map(|speed| Velocity::new::<meter_per_second>(speed.into()));

                // Fake confidence values sine NMEA parser does not provide them.
                self.position.confidence = Some(crate::Confidence {
                    semi_major_axis: Length::new::<meter>(10.0),
                    semi_minor_axis: Length::new::<meter>(10.0),
                    semi_major_orientation: Angle::new::<degree>(0.0),
                });

                self.position.fix.epv = Some(Length::new::<meter>(10.0));
                self.position.fix.eps = Some(Velocity::new::<meter_per_second>(10.0));
                self.position.fix.epd = Some(Angle::new::<degree>(3.0));

                true
            }
            Err(_) => false,
        }
    }
}
