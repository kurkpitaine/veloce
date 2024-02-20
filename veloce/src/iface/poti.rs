//! This module contains the implementation of the Poti module as defined in ETSI EN 302 890-2 V2.1.1.
//! Only the positioning part is implemented, timing is considered out of scope in Veloce Poti implementation.

use uom::si::f32::Length;

use crate::{
    time::TAI2004,
    types::{Heading, Latitude, Longitude, Speed},
};

/// Position and Timing aka `Poti`.
pub struct Poti {
    /// Current position fix.
    pub fix: Fix,
}

impl Poti {
    /// Create a Poti instance with default values.
    pub fn new() -> Self {
        Poti {
            fix: Default::default(),
        }
    }

    /// Push a new [Fix] to the [Poti] module.
    pub fn push_fix(&mut self, fix: Fix) {
        self.fix = fix;
    }
}

/// A Poti GNSS fix.
#[derive(Default, Debug, Clone, Copy)]
pub struct Fix {
    /// Fix mode.
    pub mode: Mode,
    /// Timestamp at which the `position`, `motion` and `confidence` values where received.
    pub timestamp: TAI2004,
    /// Position value.
    pub position: Position,
    /// Motion values at `position`.
    pub motion: Motion,
    /// Confidence of `position` and `motion` values.
    pub confidence: Confidence,
}

/// Type of GPS fix.
#[derive(Default, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Mode {
    /// No fix at all.
    #[default]
    NoFix,
    /// Two dimensional fix, 2D.
    Fix2d,
    /// Three dimensional fix, 3D (i.e. with altitude).
    Fix3d,
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
