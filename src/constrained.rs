const TENTH_OF_MICRO_PER_DEG: i32 = 10_000_000;

/// A `Latitude` type to represent a latitude angular measurement.
///
/// `Latitude` is composed of a whole number represented in 10th of microdegrees (ie: 10e-7).
/// It is suitable for an accuracy worth up to 11 mm.
///
/// [`Latitude`]s implement many common traits, including [`Add`], [`Sub`], and other
/// [`ops`] traits. It implements [`Default`] by returning a zero `Latitude`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
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

    pub fn new_checked(value: i32) -> Option<Latitude> {
        if value >= Self::MIN && value <= Self::MAX {
            Some(Latitude(value))
        } else {
            None
        }
    }

    pub fn from_degs_f64(degs: f64) -> Option<Latitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f64);
        Self::new_checked(value as i32)
    }

    pub fn from_degs_f32(degs: f32) -> Option<Latitude> {
        let value = degs * (TENTH_OF_MICRO_PER_DEG as f32);
        Self::new_checked(value as i32)
    }

    pub fn as_degs_f64(&self) -> f64 {
        self.0 as f64 / TENTH_OF_MICRO_PER_DEG as f64
    }

    pub fn as_degs_f32(&self) -> f32 {
        self.0 as f32 / TENTH_OF_MICRO_PER_DEG as f32
    }
}
