#![allow(clippy::excessive_precision)]

pub use uom::si::angle::{degree, radian};
pub use uom::si::f64::Angle;
use uom::si::f64::*;
pub use uom::si::length::meter;
pub use uom::si::velocity::centimeter_per_second;
pub use uom::si::velocity::kilometer_per_hour;
pub use uom::si::velocity::meter_per_second;

unit! {
   system: uom::si;
   quantity: uom::si::angle;

   @decidegree: 1.745_329_251_994_329_5_E-3; "d°", "decidegree", "decidegrees";
   @tenth_of_microdegree: 1.745_329_251_994_329_5_E-9; "0.1µ°", "tenth of microdegree", "tenth of microdegrees";
}

pub type Latitude = Angle;

pub trait LatitudeTrait {
    fn is_valid_latitude_value(&self) -> bool;
}

impl LatitudeTrait for Latitude {
    fn is_valid_latitude_value(&self) -> bool {
        let raw_lat = self.get::<tenth_of_microdegree>();
        (-900_000_000.0..=900_000_000.0).contains(&raw_lat)
    }
}

pub type Longitude = Angle;

pub trait LongitudeTrait {
    fn is_valid_longitude_value(&self) -> bool;
}

impl LongitudeTrait for Longitude {
    fn is_valid_longitude_value(&self) -> bool {
        let raw_lon = self.get::<tenth_of_microdegree>();
        (-1_800_000_000.0..=1_800_000_000.0).contains(&raw_lon)
    }
}

pub type Heading = Angle;

pub trait HeadingTrait {
    fn is_valid_heading_value(&self) -> bool;
}

impl HeadingTrait for Heading {
    fn is_valid_heading_value(&self) -> bool {
        let raw_hdg = self.get::<decidegree>();
        raw_hdg.is_sign_positive() && raw_hdg <= 3600.0
    }
}

pub type Speed = Velocity;

pub trait SpeedTrait {
    fn is_valid_speed_value(&self) -> bool;
}

impl SpeedTrait for Speed {
    fn is_valid_speed_value(&self) -> bool {
        let raw_spd = self.get::<centimeter_per_second>();
        (-16384.0..=16383.0).contains(&raw_spd)
    }
}

pub type Distance = Length;

pub trait DistanceTrait {
    fn is_valid_distance_value(&self) -> bool;
}

impl DistanceTrait for Distance {
    fn is_valid_distance_value(&self) -> bool {
        let raw_dist = self.get::<meter>();
        raw_dist.is_sign_positive() && raw_dist <= 65535.0
    }
}

pub trait AngleTrait {
    fn is_valid_angle_value(&self) -> bool;
}

impl AngleTrait for Angle {
    fn is_valid_angle_value(&self) -> bool {
        let raw_angle = self.get::<degree>();
        raw_angle.is_sign_positive() && raw_angle < 360.0
    }
}

/// Pseudonym of the station.
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub struct Pseudonym(pub u32);

#[cfg(feature = "asn1")]
use veloce_asn1::defs::etsi_messages_r2::etsi__its__cdd::StationId;

#[cfg(feature = "asn1")]
impl From<StationId> for Pseudonym {
    fn from(value: StationId) -> Self {
        Self(value.0)
    }
}

/// Radio signal power. Inner representation is stored as twice the value
/// in dBm units, so it allows precision of 0.5 dBm.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Default)]
pub struct Power(i32);

impl Power {
    /// Build a new [Power] from a dBm value stored in a [i32].
    pub const fn from_dbm_i32(val: i32) -> Self {
        Power(val * 2)
    }

    /// Build a new [Power] from a half dBm value stored in a [i32].
    pub const fn from_half_dbm_i32(val: i32) -> Self {
        Power(val)
    }

    /// Build a new [Power] from a dBm value stored in a [f64].
    /// Values are ceiled to the nearest round value.
    pub fn from_dbm_f64(val: f64) -> Self {
        let val = val * 2.0;
        Power(val.ceil() as i32)
    }

    /// Return the [Power] value as an [i32] in dBm units.
    pub const fn as_dbm_i32(&self) -> i32 {
        self.0 / 2
    }

    /// Return the [Power] value as an [i16] in dBm units.
    pub const fn as_dbm_i16(&self) -> i16 {
        (self.0 / 2) as i16
    }

    /// Return the [Power] value as an [f64] in dBm units.
    pub fn as_dbm_f64(&self) -> f64 {
        self.0 as f64 / 2.0
    }

    /// Return the [Power] value as an [i32] in 0.5 dBm units.
    pub const fn as_half_dbm_i32(&self) -> i32 {
        self.0
    }

    /// Return the [Power] value as an [f64] in 0.5 dBm units.
    pub fn as_half_dbm_f64(&self) -> f64 {
        self.0 as f64
    }

    /// Return the [Power] value as an [i16] in 0.5 dBm units.
    pub const fn as_half_dbm_i16(&self) -> i16 {
        self.0 as i16
    }
}
