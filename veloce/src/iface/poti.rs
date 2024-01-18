//! This module contains the implementation of the Poti module as defined in ETSI EN 302 890-2 V2.1.1.
//! Only the positioning part is implemented, timing is considered out of scope in Veloce Poti implementation.

use uom::si::angle::degree;
use uom::si::f32::Length;
use uom::si::length::meter;
use uom::si::velocity::meter_per_second;

use crate::{
    time::TAI2004,
    types::{Heading, Latitude, Longitude, Speed},
};

#[cfg(feature = "gpsd")]
use gpsd_proto::{Mode, Tpv, UnifiedResponse};

/// Position and Timing aka `Poti`.
pub struct Poti {
    /// Current position fix.
    pub fix: Fix,
}

/// A GNSS fix.
#[derive(Default, Debug, Clone, Copy)]
pub struct Fix {
    /// Timestamp at which the `position`, `motion` and `confidence` values where received.
    pub timestamp: TAI2004,
    /// Position value.
    pub position: Position,
    /// Motion values at `position`.
    pub motion: Motion,
    /// Confidence of `position` and `motion` values.
    pub confidence: Confidence,
}

/// Position category dimensions.
/// Describes a position, as 3D point (x,y,z) in a WGS84 coordinates system.
#[derive(Default, Debug, Clone, Copy)]
pub struct Position {
    /// Latitude of the position.
    pub latitude: Latitude,
    /// Longitude of the position.
    pub longitude: Longitude,
    /// Altitude of the position.
    pub altitude: Option<Length>,
}

/// Motion category dimensions.
/// Describes the motion at a given position.
#[derive(Default, Debug, Clone, Copy)]
pub struct Motion {
    /// Speed value at the position.
    pub speed: Option<Speed>,
    /// Speed value at the position.
    pub vertical_speed: Option<Speed>,
    /// Speed value at the position.
    pub heading: Option<Heading>,
}

/// Confidence category dimensions.
#[derive(Default, Debug, Clone, Copy)]
pub struct Confidence {
    /// Confidence of the position.
    pub position: PositionConfidence,
    /// Confidence of the altitude.
    pub altitude: Option<Length>,
    /// Confidence of the speed.
    pub speed: Option<Speed>,
    /// Confidence of the heading.
    pub heading: Option<Heading>,
}

/// Horizontal position confidence.
/// Describes the confidence ellipse of a `position`.
#[derive(Default, Debug, Clone, Copy)]
pub struct PositionConfidence {
    /// Semi major axis confidence.
    pub semi_major: Option<Length>,
    /// Semi minor axis confidence.
    pub semi_minor: Option<Length>,
    /// Semi major orientation confidence.
    pub semi_major_orientation: Option<Heading>,
}

impl Poti {
    /// Create a Poti instance with default values.
    pub fn new() -> Self {
        Poti {
            fix: Default::default(),
        }
    }

    /// Dispatches `data` received from GPSD.
    /// Note: only processes TPV messages containing a 2D or 3D fix.
    #[cfg(feature = "gpsd")]
    pub fn gpsd_dispatch(&mut self, data: UnifiedResponse, timestamp: TAI2004) {
        match data {
            UnifiedResponse::Tpv(fix) if !matches!(fix.mode, Mode::NoFix) => {
                self.fix = Fix::from_gpsd_tpv(fix, timestamp);
            }
            _ => return,
        }
    }
}

impl Fix {
    #[cfg(feature = "gpsd")]
    pub(super) fn from_gpsd_tpv(fix: Tpv, timestamp: TAI2004) -> Self {
        Fix {
            timestamp,
            position: Position {
                // Safety: Mode::Fix2d and Mode::Fix3d ensures we have lat parameter.
                latitude: Latitude::new::<degree>(fix.lat.unwrap() as f32),
                // Safety: Mode::Fix2d and Mode::Fix3d ensures we have lon parameter.
                longitude: Longitude::new::<degree>(fix.lon.unwrap() as f32),
                altitude: fix.alt.and_then(|alt| Some(Length::new::<meter>(alt))),
            },
            motion: Motion {
                speed: fix
                    .speed
                    .and_then(|spd| Some(Speed::new::<meter_per_second>(spd))),
                vertical_speed: fix
                    .climb
                    .and_then(|clb| Some(Speed::new::<meter_per_second>(clb))),
                heading: fix.track.and_then(|trk| Some(Heading::new::<degree>(trk))),
            },
            confidence: Confidence {
                position: PositionConfidence {
                    semi_major: fix.epx.and_then(|epx| Some(Length::new::<meter>(epx))),
                    semi_minor: fix.epx.and_then(|epy| Some(Length::new::<meter>(epy))),
                    semi_major_orientation: fix
                        .track
                        .and_then(|trk| Some(Heading::new::<degree>(trk))),
                },
                altitude: fix.epv.and_then(|epv| Some(Length::new::<meter>(epv))),
                speed: fix
                    .eps
                    .and_then(|eps| Some(Speed::new::<meter_per_second>(eps))),
                heading: fix.epd.and_then(|epd| Some(Heading::new::<degree>(epd))),
            },
        }
    }
}
