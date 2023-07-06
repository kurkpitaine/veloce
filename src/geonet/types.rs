pub use uom::si::angle::degree;
pub use uom::si::f32::Angle;
use uom::si::f32::*;
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
        if raw_lat < -900_000_000.0 || raw_lat > 900_000_000.0 {
            false
        } else {
            true
        }
    }
}

pub type Longitude = Angle;

pub trait LongitudeTrait {
    fn is_valid_longitude_value(&self) -> bool;
}

impl LongitudeTrait for Longitude {
    fn is_valid_longitude_value(&self) -> bool {
        let raw_lat = self.get::<tenth_of_microdegree>();
        if raw_lat < -1_800_000_000.0 || raw_lat > 1_800_000_000.0 {
            false
        } else {
            true
        }
    }
}

pub type Heading = Angle;

pub trait HeadingTrait {
    fn is_valid_heading_value(&self) -> bool;
}

impl HeadingTrait for Heading {
    fn is_valid_heading_value(&self) -> bool {
        let raw_hdg = self.get::<decidegree>();
        if raw_hdg.is_sign_negative() || raw_hdg > 3600.0 {
            false
        } else {
            true
        }
    }
}

pub type Speed = Velocity;

pub trait SpeedTrait {
    fn is_valid_speed_value(&self) -> bool;
}

impl SpeedTrait for Speed {
    fn is_valid_speed_value(&self) -> bool {
        let raw_spd = self.get::<centimeter_per_second>();
        if raw_spd < -16384.0 || raw_spd > 16383.0 {
            false
        } else {
            true
        }
    }
}

pub type Distance = Length;

pub trait DistanceTrait {
    fn is_valid_distance_value(&self) -> bool;
}

impl DistanceTrait for Distance {
    fn is_valid_distance_value(&self) -> bool {
        let raw_dist = self.get::<meter>();
        if raw_dist.is_sign_negative() || raw_dist > 65535.0 {
            false
        } else {
            true
        }
    }
}

pub trait AngleTrait {
    fn is_valid_angle_value(&self) -> bool;
}

impl AngleTrait for Angle {
    fn is_valid_angle_value(&self) -> bool {
        let raw_angle = self.get::<degree>();
        if raw_angle.is_sign_negative() || raw_angle >= 360.0 {
            false
        } else {
            true
        }
    }
}
