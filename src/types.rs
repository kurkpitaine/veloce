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

    /// Creates a new `Latitude` from the specified number of 10th of microdegrees
    ///
    /// # Panics
    ///
    /// This constructor will panic if the value is not within `Latitude` bounds
    pub fn new(value: i32) -> Latitude {
        match Self::new_checked(value) {
            None => panic!("Latitude value is out of bounds"),
            Some(val) => val,
        }
    }

    /// Creates a new `Latitude` from the specified number of 10th of microdegrees
    ///
    /// This constructor return [`None`] if overflow occured.
    pub fn new_checked(value: i32) -> Option<Latitude> {
        if value >= Self::MIN && value <= Self::MAX {
            Some(Latitude(value))
        } else {
            None
        }
    }

    /// Creates a new `Latitude` from the specified number of degrees represented
    /// as `f64`.
    ///
    /// This constructor return [`None`] if overflow occured.
    pub fn from_degs_f64(degs: f64) -> Option<Latitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f64);
        Self::new_checked(value as i32)
    }

    /// Creates a new `Latitude` from the specified number of degrees represented
    /// as `f32`.
    ///
    /// This constructor return [`None`] if overflow occured.
    pub fn from_degs_f32(degs: f32) -> Option<Latitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f32);
        Self::new_checked(value as i32)
    }

    /// Returns the latitude value as degrees contained by this `Latitude` as `f64`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the latitude.
    pub fn as_degs_f64(&self) -> f64 {
        self.0 as f64 / TENTH_OF_MICRO_PER_DEG as f64
    }

    /// Returns the latitude value as degrees contained by this `Latitude` as `f32`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the latitude.
    pub fn as_degs_f32(&self) -> f32 {
        self.0 as f32 / TENTH_OF_MICRO_PER_DEG as f32
    }

    /// Returns the latitude value contained by this `Latitude` as 10th of microdegrees in `i32`.
    pub fn as_raw(&self) -> i32 {
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

    /// Creates a new `Longitude` from the specified number of 10th of microdegrees
    ///
    /// # Panics
    ///
    /// This constructor will panic if the value is not within `Latitude` bounds
    pub fn new(value: i32) -> Longitude {
        match Self::new_checked(value) {
            None => panic!("Longitude value is out of bounds"),
            Some(val) => val,
        }
    }

    /// Creates a new `Longitude` from the specified number of 10th of microdegrees
    ///
    /// This constructor return [`None`] if overflow occured.
    pub fn new_checked(value: i32) -> Option<Longitude> {
        if value >= Self::MIN && value <= Self::MAX {
            Some(Longitude(value))
        } else {
            None
        }
    }

    /// Creates a new `Longitude` from the specified number of degrees represented
    /// as `f64`.
    ///
    /// This constructor return [`None`] if overflow occured.
    pub fn from_degs_f64(degs: f64) -> Option<Longitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f64);
        Self::new_checked(value as i32)
    }

    /// Creates a new `Longitude` from the specified number of degrees represented
    /// as `f32`.
    ///
    /// This constructor return [`None`] if overflow occured.
    pub fn from_degs_f32(degs: f32) -> Option<Longitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f32);
        Self::new_checked(value as i32)
    }

    /// Returns the longitude value as degrees contained by this `Longitude` as `f64`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the longitude.
    pub fn as_degs_f64(&self) -> f64 {
        self.0 as f64 / TENTH_OF_MICRO_PER_DEG as f64
    }

    /// Returns the longitude value as degrees contained by this `Longitude` as `f32`.
    ///
    /// The returned value does include the fractional (0.1 microdegree) part of the longitude.
    pub fn as_degs_f32(&self) -> f32 {
        self.0 as f32 / TENTH_OF_MICRO_PER_DEG as f32
    }

    /// Returns the longitude value contained by this `Longitude` as 10th of microdegrees in `i32`.
    pub fn as_raw(&self) -> i32 {
        self.0
    }
}

impl fmt::Display for Longitude {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 / TENTH_OF_MICRO_PER_DEG)
    }
}

mod test {
    use super::*;

    const OVERFLOWING_LAT: i32 = 950_000_000;
    const OVERFLOWING_LON: i32 = 1_900_000_000;

    #[test]
    #[should_panic(expected = "Latitude value is out of bounds")]
    fn test_new_lat_min() {
        Latitude::new(-OVERFLOWING_LAT);
    }

    #[test]
    #[should_panic(expected = "Latitude value is out of bounds")]
    fn test_new_lat_max() {
        Latitude::new(OVERFLOWING_LAT);
    }

    #[test]
    #[should_panic(expected = "Longitude value is out of bounds")]
    fn test_new_lon_min() {
        Longitude::new(-OVERFLOWING_LON);
    }

    #[test]
    #[should_panic(expected = "Longitude value is out of bounds")]
    fn test_new_lon_max() {
        Longitude::new(OVERFLOWING_LON);
    }

    #[test]
    fn test_from_f64_lat() {
        assert_eq!(Latitude::from_degs_f64(OVERFLOWING_LAT as f64 / TENTH_OF_MICRO_PER_DEG as f64), None);
    }

    #[test]
    fn test_from_f32_lat() {
        assert_eq!(Latitude::from_degs_f32(OVERFLOWING_LAT as f32 / TENTH_OF_MICRO_PER_DEG as f32), None);
    }

    #[test]
    fn test_from_f64_lon() {
        assert_eq!(Longitude::from_degs_f64(OVERFLOWING_LON as f64 / TENTH_OF_MICRO_PER_DEG as f64), None);
    }

    #[test]
    fn test_from_f32_lon() {
        assert_eq!(Longitude::from_degs_f32(OVERFLOWING_LON as f32 / TENTH_OF_MICRO_PER_DEG as f32), None);
    }

    #[test]
    fn test_as_f64_lat() {
        let lat = Latitude::new(487667533);
        assert_eq!(lat.as_degs_f64(), 48.7667533);
    }

    #[test]
    fn test_as_f32_lat() {
        let lat = Latitude::new(487667533);
        assert_eq!(lat.as_degs_f32(), 48.76675);
    }

    #[test]
    fn test_as_f64_lon() {
        let lon = Longitude::new(24841550);
        assert_eq!(lon.as_degs_f64(), 2.4841550);
    }

    #[test]
    fn test_as_f32_lon() {
        let lon = Longitude::new(24841550);
        assert_eq!(lon.as_degs_f32(), 2.4841550);
    }

    #[test]
    fn test_as_raw_lat() {
        let lat = Latitude::new(487667533);
        assert_eq!(lat.as_raw(), 487667533);
    }

    #[test]
    fn test_as_raw_lon() {
        let lon = Longitude::new(24841550);
        assert_eq!(lon.as_raw(), 24841550);
    }
}
