//! This module contains the implementation of the Poti module as defined in ETSI EN 302 890-2 V2.1.1.
//! Only the positioning part is implemented, timing is considered out of scope in Veloce Poti implementation.

use uom::si::f32::Length;

use crate::{
    time::TAI2004,
    types::{Heading, Latitude, Longitude, Speed},
};

/// Position and Timing aka `Poti`.
#[derive(Debug)]
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
    pub latitude: Option<Latitude>,
    /// Longitude of the position.
    pub longitude: Option<Longitude>,
    /// Altitude of the position.
    pub altitude: Option<Length>,
}

impl Position {
    /// Return the latitude as a [Latitude](veloce_asn1::e_t_s_i__i_t_s__c_d_d::Latitude).
    #[cfg(feature = "asn1")]
    pub fn latitude_value(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::Latitude {
        use crate::types::tenth_of_microdegree;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::Latitude;

        self.latitude.map_or(Latitude(900_000_001), |lat| {
            let val = lat.get::<tenth_of_microdegree>() as i32;
            Latitude(val)
        })
    }

    /// Return the longitude as a [Longitude](veloce_asn1::e_t_s_i__i_t_s__c_d_d::Longitude).
    #[cfg(feature = "asn1")]
    pub fn longitude_value(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::Longitude {
        use crate::types::tenth_of_microdegree;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::Longitude;

        self.longitude.map_or(Longitude(1_800_000_001), |lon| {
            let val = lon.get::<tenth_of_microdegree>() as i32;
            Longitude(val)
        })
    }

    /// Return the altitude as a [AltitudeValue](veloce_asn1::e_t_s_i__i_t_s__c_d_d::AltitudeValue).
    #[cfg(feature = "asn1")]
    pub fn altitude_value(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::AltitudeValue {
        use uom::si::length::centimeter;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::AltitudeValue;

        self.altitude.map_or(AltitudeValue(800_001), |alt| {
            let val = alt.get::<centimeter>() as i32;
            AltitudeValue(val.clamp(-100_000, 800_000))
        })
    }
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

impl Motion {
    /// Return the speed as a [SpeedValue](veloce_asn1::e_t_s_i__i_t_s__c_d_d::SpeedValue).
    #[cfg(feature = "asn1")]
    pub fn speed_value(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::SpeedValue {
        use uom::si::velocity::centimeter_per_second;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::SpeedValue;

        self.speed.map_or(SpeedValue(16383), |spd| {
            let val = spd.get::<centimeter_per_second>() as u16;
            SpeedValue(val.clamp(0, 16382))
        })
    }

    /// Return the heading as a [HeadingValue](veloce_asn1::e_t_s_i__i_t_s__c_d_d::HeadingValue).
    #[cfg(feature = "asn1")]
    pub fn heading_value(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::HeadingValue {
        use crate::types::decidegree;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::HeadingValue;

        self.heading.map_or(HeadingValue(3601), |axis| {
            let val = axis.get::<decidegree>() as u16;
            HeadingValue(val.clamp(0, 3599))
        })
    }
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

impl Confidence {
    /// Return altitude confidence as a [AltitudeConfidence](veloce_asn1::e_t_s_i__i_t_s__c_d_d::AltitudeConfidence).
    #[cfg(feature = "asn1")]
    pub fn altitude_confidence(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::AltitudeConfidence {
        use uom::si::length::meter;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::AltitudeConfidence;

        self.altitude
            .map_or(AltitudeConfidence::unavailable, |alt| {
                match alt.get::<meter>() {
                    val if val > 200.0 => AltitudeConfidence::outOfRange,
                    val if val > 100.0 => AltitudeConfidence::alt_200_00,
                    val if val > 50.0 => AltitudeConfidence::alt_100_00,
                    val if val > 20.0 => AltitudeConfidence::alt_050_00,
                    val if val > 10.0 => AltitudeConfidence::alt_020_00,
                    val if val > 5.0 => AltitudeConfidence::alt_010_00,
                    val if val > 2.0 => AltitudeConfidence::alt_005_00,
                    val if val > 1.0 => AltitudeConfidence::alt_002_00,
                    val if val > 0.5 => AltitudeConfidence::alt_001_00,
                    val if val > 0.2 => AltitudeConfidence::alt_000_50,
                    val if val > 0.1 => AltitudeConfidence::alt_000_20,
                    val if val > 0.05 => AltitudeConfidence::alt_000_10,
                    val if val > 0.02 => AltitudeConfidence::alt_000_05,
                    val if val > 0.01 => AltitudeConfidence::alt_000_02,
                    val if val >= 0.0 => AltitudeConfidence::alt_000_01,
                    _ => AltitudeConfidence::unavailable,
                }
            })
    }

    /// Return the speed confidence as a [SpeedConfidence](veloce_asn1::e_t_s_i__i_t_s__c_d_d::SpeedConfidence).
    #[cfg(feature = "asn1")]
    pub fn speed_confidence(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::SpeedConfidence {
        use uom::si::velocity::centimeter_per_second;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::SpeedConfidence;

        self.speed.map_or(SpeedConfidence(127), |spd| {
            let val = spd.get::<centimeter_per_second>() as u8;
            SpeedConfidence(val.clamp(1, 126))
        })
    }

    /// Return the heading confidence as a [HeadingConfidence](veloce_asn1::e_t_s_i__i_t_s__c_d_d::HeadingConfidence).
    #[cfg(feature = "asn1")]
    pub fn heading_confidence(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::HeadingConfidence {
        use crate::types::decidegree;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::HeadingConfidence;

        self.heading.map_or(HeadingConfidence(127), |hdg| {
            let val = hdg.get::<decidegree>() as u8;
            HeadingConfidence(val.clamp(1, 126))
        })
    }
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

impl PositionConfidence {
    /// Return the semi major axis confidence as a [SemiAxisLength](veloce_asn1::e_t_s_i__i_t_s__c_d_d::SemiAxisLength).
    #[cfg(feature = "asn1")]
    pub fn semi_major_axis_length(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::SemiAxisLength {
        use uom::si::length::centimeter;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::SemiAxisLength;

        self.semi_major.map_or(SemiAxisLength(4095), |axis| {
            let val = axis.get::<centimeter>() as u16;
            SemiAxisLength(val.clamp(1, 4094))
        })
    }

    /// Return the semi major axis confidence as a [SemiAxisLength](veloce_asn1::e_t_s_i__i_t_s__c_d_d::SemiAxisLength).
    #[cfg(feature = "asn1")]
    pub fn semi_minor_axis_length(&self) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::SemiAxisLength {
        use uom::si::length::centimeter;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::SemiAxisLength;

        self.semi_minor.map_or(SemiAxisLength(4095), |axis| {
            let val = axis.get::<centimeter>() as u16;
            SemiAxisLength(val.clamp(1, 4094))
        })
    }

    /// Return the semi major axis confidence as a [Wgs84AngleValue](veloce_asn1::e_t_s_i__i_t_s__c_d_d::Wgs84AngleValue).
    #[cfg(feature = "asn1")]
    pub fn semi_minor_orientation_angle(
        &self,
    ) -> veloce_asn1::e_t_s_i__i_t_s__c_d_d::Wgs84AngleValue {
        use crate::types::decidegree;
        use veloce_asn1::e_t_s_i__i_t_s__c_d_d::Wgs84AngleValue;

        self.semi_major_orientation
            .map_or(Wgs84AngleValue(3601), |axis| {
                let val = axis.get::<decidegree>() as u16;
                Wgs84AngleValue(val.clamp(0, 3599))
            })
    }
}
