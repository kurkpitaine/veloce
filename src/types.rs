use crate::{Error, Result};

use core::fmt;

const TENTH_OF_MICRO_PER_DEG: i32 = 10_000_000;

/// A `Latitude` type to represent a latitude angular measurement.
///
/// `Latitude` is composed of a whole number represented in 10th of microdegrees (ie: 10e-7).
/// It is suitable for an accuracy worth up to 11 mm.
///
/// It implements [`Default`] by returning a zero `Latitude`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Latitude(i32);

impl Latitude {
    /// The minimum latitude value in 10th of microdegrees.
    pub const MIN: i32 = -900_000_000;

    /// The maximum latitude value in 10th of microdegrees.
    pub const MAX: i32 = 900_000_000;

    /// Creates a new `Latitude` from the specified number of 10th of microdegrees.
    pub fn new_unchecked(value: i32) -> Latitude {
        Latitude(value)
    }

    /// Creates a new `Latitude` from the specified number of 10th of microdegrees.
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(value: i32) -> Result<Latitude> {
        let lat = Self::new_unchecked(value);
        lat.check_constraints()?;
        Ok(lat)
    }

    /// Ensure that the assigned latitude value is not out of bounds.
    ///
    /// Returns `Err(Error::Overflow)` if the value overflows constraints.
    pub fn check_constraints(&self) -> Result<()> {
        if self.0 >= Self::MIN && self.0 <= Self::MAX {
            Ok(())
        } else {
            Err(Error::Overflow)
        }
    }

    /// Creates a new `Latitude` from the specified number of degrees represented
    /// as `f64`.
    ///
    /// Returns `Err(Error::Overflow)` if the value overflows constraints.
    pub fn from_degrees_f64(degs: f64) -> Result<Latitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f64);
        Self::new_checked(value as i32)
    }

    /// Creates a new `Latitude` from the specified number of degrees represented
    /// as `f32`.
    ///
    /// Returns `Err(Error::Overflow)` if the value overflows constraints.
    pub fn from_degrees_f32(degs: f32) -> Result<Latitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f32);
        Self::new_checked(value as i32)
    }

    /// Returns the latitude value as degrees contained by this `Latitude` as `f64`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the latitude.
    pub fn as_degrees_f64(&self) -> f64 {
        self.0 as f64 / TENTH_OF_MICRO_PER_DEG as f64
    }

    /// Returns the latitude value as degrees contained by this `Latitude` as `f32`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the latitude.
    pub fn as_degrees_f32(&self) -> f32 {
        self.0 as f32 / TENTH_OF_MICRO_PER_DEG as f32
    }

    /// Returns the latitude value contained by this `Latitude` as 10th of microdegrees in `i32`.
    pub fn as_tenth_of_microdegrees_i32(&self) -> i32 {
        self.0
    }
}

impl fmt::Display for Latitude {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 / TENTH_OF_MICRO_PER_DEG)
    }
}

/// A `Longitude` type to represent a longitude angular measurement.
///
/// `Longitude` is composed of a whole number represented in 10th of microdegrees (ie: 10e-7).
/// It is suitable for an accuracy worth up to 11 mm.
///
/// It implements [`Default`] by returning a zero `Longitude`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Longitude(i32);

impl Longitude {
    /// The minimum longitude value in 10th of microdegrees.
    pub const MIN: i32 = -1_800_000_000;

    /// The maximum longitude value in 10th of microdegrees.
    pub const MAX: i32 = 1_800_000_000;

    /// Creates a new `Longitude` from the specified number of 10th of microdegrees.
    pub fn new_unchecked(value: i32) -> Longitude {
        Longitude(value)
    }

    /// Creates a new `Longitude` from the specified number of 10th of microdegrees.
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(value: i32) -> Result<Longitude> {
        let lon = Self::new_unchecked(value);
        lon.check_constraints()?;
        Ok(lon)
    }

    /// Ensure that the assigned longitude value is not out of bounds.
    ///
    /// Returns `Err(Error::Overflow)` if the value overflows constraints.
    pub fn check_constraints(&self) -> Result<()> {
        if self.0 >= Self::MIN && self.0 <= Self::MAX {
            Ok(())
        } else {
            Err(Error::Overflow)
        }
    }

    /// Creates a new `Longitude` from the specified number of degrees represented
    /// as `f64`.
    ///
    /// Returns `Err(Error::Overflow)` if the value overflows constraints.
    pub fn from_degrees_f64(degs: f64) -> Result<Longitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f64);
        Self::new_checked(value as i32)
    }

    /// Creates a new `Longitude` from the specified number of degrees represented
    /// as `f32`.
    ///
    /// Returns `Err(Error::Overflow)` if the value overflows constraints.
    pub fn from_degrees_f32(degs: f32) -> Result<Longitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f32);
        Self::new_checked(value as i32)
    }

    /// Returns the longitude value as degrees contained by this `Longitude` as `f64`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the longitude.
    pub fn as_degrees_f64(&self) -> f64 {
        self.0 as f64 / TENTH_OF_MICRO_PER_DEG as f64
    }

    /// Returns the longitude value as degrees contained by this `Longitude` as `f32`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the longitude.
    pub fn as_degrees_f32(&self) -> f32 {
        self.0 as f32 / TENTH_OF_MICRO_PER_DEG as f32
    }

    /// Returns the longitude value contained by this `Longitude` as 10th of microdegrees in `i32`.
    pub fn as_tenth_of_microdegrees_i32(&self) -> i32 {
        self.0
    }
}

impl fmt::Display for Longitude {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 / TENTH_OF_MICRO_PER_DEG)
    }
}

/// An `Angle` type to represent an angular measurement.
///
/// `Angle` is composed of a whole number represented in degrees.
///
/// It implements [`Default`] by returning a zero `Angle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Angle(u16);

impl Angle {
    /// One degree expressed as radians.
    const RADIAN: f64 = 1.745_329_251_994_329_576_923_690_768_489E-2;

    /// Creates a new `Angle` from the specified number of degrees.
    pub fn new(value: u16) -> Angle {
        Angle(value)
    }

    /// Returns the angle value as degrees contained by this `Angle` as `f64`.
    pub fn as_degrees_f64(&self) -> f64 {
        self.0.into()
    }

    /// Returns the angle value as degrees contained by this `Angle` as `f32`.
    pub fn as_degrees_f32(&self) -> f32 {
        self.0.into()
    }

    /// Returns the angle value contained by this `Angle` as degrees in `u16`.
    pub fn as_degrees_u16(&self) -> u16 {
        self.0
    }

    /// Returns the angle value as radians contained by this `Angle` as `f64`.
    pub fn as_radians_f64(&self) -> f64 {
        self.0 as f64 * Self::RADIAN
    }

    /// Returns the angle value as radians contained by this `Angle` as `f32`.
    pub fn as_radians_f32(&self) -> f32 {
        self.0 as f32 * Self::RADIAN as f32
    }
}

impl fmt::Display for Angle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An `Distance` type to represent a distance measurement.
///
/// `Distance` is composed of a whole number represented in meters.
///
/// It implements [`Default`] by returning a zero `Distance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Distance(u16);

impl Distance {
    /// Creates a new `Distance` from the specified number of meters.
    pub fn new(value: u16) -> Distance {
        Distance(value)
    }

    /// Returns the distance value as meters contained by this `Distance` as `u16`.
    pub fn as_meters_u16(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for Distance {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

mod test {
    mod latitude {
        use super::super::{Latitude, TENTH_OF_MICRO_PER_DEG};
        use crate::Error;

        const OVERFLOWING_LAT: i32 = 950_000_000;

        #[test]
        fn test_new_min() {
            assert_eq!(
                Err(Error::Overflow),
                Latitude::new_checked(-OVERFLOWING_LAT)
            );
        }

        #[test]
        fn test_new_max() {
            assert_eq!(Err(Error::Overflow), Latitude::new_checked(OVERFLOWING_LAT));
        }

        #[test]
        fn test_from_f64() {
            assert_eq!(
                Latitude::from_degrees_f64(OVERFLOWING_LAT as f64 / TENTH_OF_MICRO_PER_DEG as f64),
                Err(Error::Overflow)
            );
        }

        #[test]
        fn test_from_f32() {
            assert_eq!(
                Latitude::from_degrees_f32(OVERFLOWING_LAT as f32 / TENTH_OF_MICRO_PER_DEG as f32),
                Err(Error::Overflow)
            );
        }

        #[test]
        fn test_as_f64() {
            let lat = Latitude::new_unchecked(487667533);
            assert_eq!(lat.as_degrees_f64(), 48.7667533);
        }

        #[test]
        fn test_as_f32() {
            let lat = Latitude::new_unchecked(487667533);
            assert_eq!(lat.as_degrees_f32(), 48.76675);
        }

        #[test]
        fn test_as_tenth_of_microdegrees() {
            let lat = Latitude::new_unchecked(487667533);
            assert_eq!(lat.as_tenth_of_microdegrees_i32(), 487667533);
        }
    }

    mod longitude {
        use super::super::{Longitude, TENTH_OF_MICRO_PER_DEG};
        use crate::Error;

        const OVERFLOWING_LON: i32 = 1_900_000_000;

        #[test]
        fn test_new_min() {
            assert_eq!(
                Err(Error::Overflow),
                Longitude::new_checked(-OVERFLOWING_LON)
            );
        }

        #[test]
        fn test_new_max() {
            assert_eq!(
                Err(Error::Overflow),
                Longitude::new_checked(OVERFLOWING_LON)
            );
        }

        #[test]
        fn test_from_f64() {
            assert_eq!(
                Longitude::from_degrees_f64(OVERFLOWING_LON as f64 / TENTH_OF_MICRO_PER_DEG as f64),
                Err(Error::Overflow)
            );
        }

        #[test]
        fn test_from_f32() {
            assert_eq!(
                Longitude::from_degrees_f32(OVERFLOWING_LON as f32 / TENTH_OF_MICRO_PER_DEG as f32),
                Err(Error::Overflow)
            );
        }

        #[test]
        fn test_as_f64() {
            let lon = Longitude::new_unchecked(24841550);
            assert_eq!(lon.as_degrees_f64(), 2.4841550);
        }

        #[test]
        fn test_as_f32() {
            let lon = Longitude::new_unchecked(24841550);
            assert_eq!(lon.as_degrees_f32(), 2.4841550);
        }

        #[test]
        fn test_as_tenth_of_microdegrees() {
            let lon = Longitude::new_unchecked(24841550);
            assert_eq!(lon.as_tenth_of_microdegrees_i32(), 24841550);
        }
    }

    mod angle {
        use super::super::Angle;

        #[test]
        fn test_new() {
            let angle = Angle::new(277);
            assert_eq!(277, angle.0)
        }

        #[test]
        fn test_as_degrees_f64() {
            let angle = Angle::new(333);
            assert_eq!(333.0, angle.as_degrees_f64())
        }

        #[test]
        fn test_as_degrees_f32() {
            let angle = Angle::new(150);
            assert_eq!(150.0, angle.as_degrees_f32())
        }

        #[test]
        fn test_as_degrees_u16() {
            let angle = Angle::new(56);
            assert_eq!(56, angle.as_degrees_u16())
        }

        #[test]
        fn test_as_radians_f64() {
            let angle = Angle::new(35);
            assert_eq!(0.6108652381980153, angle.as_radians_f64())
        }

        #[test]
        fn test_as_radians_f32() {
            let angle = Angle::new(22);
            assert_eq!(0.38397244, angle.as_radians_f32())
        }
    }

    mod distance {
        use super::super::Distance;

        #[test]
        fn test_new() {
            let distance = Distance::new(4237);
            assert_eq!(4237, distance.0)
        }

        #[test]
        fn test_as_meters_u16() {
            let distance = Distance::new(15641);
            assert_eq!(15641, distance.as_meters_u16())
        }
    }
}
