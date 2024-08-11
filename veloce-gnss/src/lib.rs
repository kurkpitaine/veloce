use std::time::Duration;

use chrono::{DateTime, Utc};
use log::{error, trace};
use uom::si::{
    angle::degree,
    f32::{Angle, Length, Ratio, Velocity},
    ratio::ratio,
};

use veloce::{
    common::{PotiConfidence, PotiFix, PotiMode, PotiMotion, PotiPosition, PotiPositionConfidence},
    time::{Instant, TAI2004},
    types::{LatitudeTrait, LongitudeTrait},
};

#[cfg(feature = "gpsd")]
mod gpsd;
#[cfg(feature = "gpsd")]
pub use gpsd::Gpsd;

#[cfg(feature = "replay")]
mod replay;
#[cfg(feature = "replay")]
pub use replay::Replay;

/// Accumulated GPS data. Most of the nested fields are optional,
/// due to GPSs not sending all the relevant data at once.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct GpsInfo {
    /// Position fix data.
    fix: Fix,
    /// Position fix confidence values.
    confidence: Option<Confidence>,
    /// NMEA GPGST frame.
    gst: Gst,
}

impl GpsInfo {
    /// Update the confidence values stored inside [GpsInfo], using the GST content.
    /// Some GPS chips don't fill all the necessary data inside the GST frame,
    /// or don't send a GST frame at all. Anyway, this function tries to fill the
    /// `confidence` field with what is available in [GpsInfo].
    pub fn self_confidence(&mut self) {
        if let Some((maj_dev, min_dev, maj_orient)) = self.gst.ellipse_deviation_values() {
            trace!("GST ellipse data available");
            self.confidence = Some(Confidence {
                semi_major_axis: maj_dev,
                semi_minor_axis: min_dev,
                semi_major_orientation: maj_orient,
            });
        } else if let Some((lat_err_dev, lon_err_dev)) = self.gst.error_deviation_values() {
            trace!("GST ellipse data unavailable - using GST error data");
            let semi_major_orientation = if lat_err_dev > lon_err_dev {
                Angle::new::<degree>(0.0)
            } else {
                Angle::new::<degree>(90.0)
            };

            // Estimation: ellipse major and minor axises are roughly 2 times the
            // respective lat/lon errors.
            self.confidence = Some(Confidence {
                semi_major_axis: Ratio::new::<ratio>(2.0) * lon_err_dev,
                semi_minor_axis: Ratio::new::<ratio>(2.0) * lat_err_dev,
                semi_major_orientation,
            });
        } else if self.fix.time.is_some_and(|fix_time| {
            (-29..30).contains(&Utc::now().signed_duration_since(fix_time).num_seconds())
        }) {
            match (self.fix.epx, self.fix.epy, self.fix.eph) {
                (Some(epx), Some(epy), _) => {
                    trace!("GST data unavailable - using fix 'epx' and 'epy'");

                    let semi_major_orientation = if epx > epy {
                        Angle::new::<degree>(0.0)
                    } else {
                        Angle::new::<degree>(90.0)
                    };

                    // Estimation: ellipse major and minor axises are roughly half of the
                    // epx and epy.
                    self.confidence = Some(Confidence {
                        semi_major_axis: Ratio::new::<ratio>(0.5) * epx,
                        semi_minor_axis: Ratio::new::<ratio>(0.5) * epy,
                        semi_major_orientation,
                    });
                }
                (None, None, Some(eph)) => {
                    trace!("GST data unavailable - using fix 'eph'");

                    self.confidence = Some(Confidence {
                        semi_major_axis: eph,
                        semi_minor_axis: eph,
                        semi_major_orientation: Angle::new::<degree>(0.0),
                    });
                }
                _ => {
                    error!("no GST and no fix 'epx' or 'epy' or 'eph' - confidence unavailable");
                    return;
                }
            }
        } else {
            error!("no GST and fix too old - confidence unavailable");
        }
    }
}

impl TryInto<PotiFix> for GpsInfo {
    type Error = ();

    fn try_into(self) -> Result<PotiFix, Self::Error> {
        match self.fix.time_and_position_values() {
            Some((time, lat, lon))
                if lat.is_valid_latitude_value() && lon.is_valid_longitude_value() =>
            {
                let pos_confidence = self.confidence.map_or(
                    PotiPositionConfidence {
                        semi_major: None,
                        semi_minor: None,
                        semi_major_orientation: None,
                    },
                    |c| PotiPositionConfidence {
                        semi_major: Some(c.semi_major_axis),
                        semi_minor: Some(c.semi_minor_axis),
                        semi_major_orientation: Some(c.semi_major_orientation),
                    },
                );

                return Ok(PotiFix {
                    mode: self.fix.mode.into(),
                    timestamp: TAI2004::from_unix_instant(Instant::from_micros_const(
                        time.timestamp_micros(),
                    )),
                    position: PotiPosition {
                        latitude: Some(lat),
                        longitude: Some(lon),
                        altitude: self.fix.altitude,
                    },
                    motion: PotiMotion {
                        speed: self.fix.speed,
                        vertical_speed: self.fix.climb,
                        heading: self.fix.track,
                    },
                    confidence: PotiConfidence {
                        position: pos_confidence,
                        altitude: self.fix.epv,
                        speed: self.fix.eps,
                        heading: self.fix.epd,
                    },
                });
            }
            Some(_) => {
                error!("latitude or longitude out of bounds");
                return Err(());
            }
            None => {
                error!("no time or position in GpsInfo");
                return Err(());
            }
        }
    }
}

/// A GPS fix.
/// Mostly the same as `struct gps_fix_t` from GPSD, with
/// less fields.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    /// Mode of fix.
    pub mode: FixMode,
    /// UTC time of update.
    pub time: Option<DateTime<Utc>>,
    /// Estimated timestamp error (95% confidence).
    /// Present if time is present.
    pub ept: Option<Duration>,
    /// Latitude: +/- signifies North/South. Present
    /// when mode is 2d or 3d.
    pub latitude: Option<Angle>,
    /// Latitude error estimate, 95% confidence. Present
    /// if mode is 2d or 3d and DOPs can be calculated from the
    /// satellite view.
    pub epy: Option<Length>,
    /// Longitude: +/- signifies East/West. Present
    /// when mode is 2d or 3d.
    pub longitude: Option<Angle>,
    /// Longitude error estimate, 95% confidence.
    /// Present if mode is 2d or 3d and DOPs can be calculated from
    /// the satellite view.
    pub epx: Option<Length>,
    /// Estimated horizontal Position (2D) Error.
    /// Also known as Estimated Position Error (epe).
    pub eph: Option<Length>,
    /// Altitude height above ellipsoid (ellipsoid is unspecified,
    /// but probably WGS84).
    pub altitude: Option<Length>,
    /// Estimated vertical error, 95% confidence.
    /// Present if mode is 3d and DOPs can be calculated from the
    /// satellite view.
    pub epv: Option<Length>,
    /// Course over ground, degrees from true north.
    pub track: Option<Angle>,
    /// Direction error estimate, 95% confidence.
    pub epd: Option<Angle>,
    /// Velocity over ground.
    pub speed: Option<Velocity>,
    /// Velocity error estimate, 95% confidence.
    pub eps: Option<Velocity>,
    /// Climb (positive) or sink (negative) rate, aka Vertical speed.
    pub climb: Option<Velocity>,
    /// Climb/sink error estimate, 95% confidence.
    pub epc: Option<Velocity>,
}

impl Fix {
    /// Return whether this [Fix] has time and position values, ie:
    /// `time`, `latitude` and `longitude` values set.
    pub fn time_and_position_values(&self) -> Option<(DateTime<Utc>, Angle, Angle)> {
        match (self.time, self.latitude, self.longitude) {
            (Some(time), Some(lat), Some(lon)) => Some((time, lat, lon)),
            _ => None,
        }
    }

    /// Return whether this [Fix] has minimal position and kinematics values, ie:
    /// `time`, `latitude`, `longitude`, `speed` and `track` values set.
    pub fn time_position_and_kinematics_values(
        &self,
    ) -> Option<(DateTime<Utc>, Angle, Angle, Velocity /* , Angle */)> {
        match (
            self.time,
            self.latitude,
            self.longitude,
            self.speed,
            /* self.track, */
        ) {
            (Some(time), Some(lat), Some(lon), Some(spd) /* , Some(trk) */) => {
                Some((time, lat, lon, spd /* , trk */))
            }
            _ => None,
        }
    }
}

/// Position Confidence, ie: accuracy of [Fix] information.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Confidence {
    /// Standard deviation of semi-major axis of error ellipse.
    pub semi_major_axis: Length,
    /// Standard deviation of semi-minor axis of error ellipse.
    pub semi_minor_axis: Length,
    /// Orientation of semi-major axis of error ellipse,
    /// angle from true north.
    pub semi_major_orientation: Angle,
}

/// Pseudorange noise report.
/// Same as `struct gst_t` from GPSD, Rusted.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Gst {
    /// UTC time of measurement.
    pub time: Option<DateTime<Utc>>,
    /// Value of the standard deviation of the range inputs to the navigation
    /// process (range inputs include pseudoranges and DGPS corrections).
    pub rms_deviation: Option<f32>,
    /// Standard deviation of semi-major axis of error ellipse.
    pub major_deviation: Option<Length>,
    /// Standard deviation of semi-minor axis of error ellipse.
    pub minor_deviation: Option<Length>,
    /// Orientation of semi-major axis of error ellipse, angle from true
    /// north.
    pub major_orientation: Option<Angle>,
    /// Standard deviation of latitude error.
    pub lat_err_deviation: Option<Length>,
    /// Standard deviation of longitude error.
    pub lon_err_deviation: Option<Length>,
    /// Standard deviation of altitude error.
    pub alt_err_deviation: Option<Length>,
}

impl Gst {
    /// Return this [Gst] ellipse deviation values, works only if
    /// `major_deviation`, `minor_deviation` and `major_orientation` values set.
    pub fn ellipse_deviation_values(&self) -> Option<(Length, Length, Angle)> {
        match (
            self.major_deviation,
            self.minor_deviation,
            self.major_orientation,
        ) {
            (Some(maj_dev), Some(min_dev), Some(maj_orient)) => {
                Some((maj_dev, min_dev, maj_orient))
            }
            _ => None,
        }
    }

    /// Return this [Gst] error deviation values, works only if
    /// `lat_err_deviation` and `lon_err_deviation` values set.
    pub fn error_deviation_values(&self) -> Option<(Length, Length)> {
        match (self.lat_err_deviation, self.lon_err_deviation) {
            (Some(lat_err_deviation), Some(lon_err_deviation)) => {
                Some((lat_err_deviation, lon_err_deviation))
            }
            _ => None,
        }
    }
}

/// Type of GPS fix.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum FixMode {
    /// Not yet updated.
    #[default]
    NotUpdated,
    /// No fix at all.
    NoFix,
    /// Two dimensional fix, 2D.
    Fix2d,
    /// Three dimensional fix, 3D (i.e. with altitude).
    Fix3d,
}

#[cfg(feature = "gpsd")]
impl From<gpsd_proto::Mode> for FixMode {
    fn from(value: gpsd_proto::Mode) -> Self {
        match value {
            gpsd_proto::Mode::NoFix => FixMode::NoFix,
            gpsd_proto::Mode::Fix2d => FixMode::Fix2d,
            gpsd_proto::Mode::Fix3d => FixMode::Fix3d,
            _ => FixMode::NoFix,
        }
    }
}

#[cfg(feature = "gpsd")]
impl Into<PotiMode> for FixMode {
    fn into(self) -> PotiMode {
        match self {
            FixMode::NotUpdated | FixMode::NoFix => PotiMode::NoFix,
            FixMode::Fix2d => PotiMode::Fix2d,
            FixMode::Fix3d => PotiMode::Fix3d,
        }
    }
}
