use core::fmt;

use chrono::Utc;
use uom::si::{
    angle::degree,
    f64::{Angle, Length, Velocity},
    length::meter,
};
use veloce::types::{meter_per_second, Latitude, LatitudeTrait, Longitude, LongitudeTrait};

use crate::{FixMode, GpsInfo};

pub type FixedResult<T> = core::result::Result<T, FixedError>;

#[derive(Debug)]
pub enum FixedError {
    /// Latitude out of bounds.
    LatitudeOutOfBounds(f64),
    /// Longitude out of bounds.
    LongitudeOutOfBounds(f64),
}

impl fmt::Display for FixedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixedError::LatitudeOutOfBounds(lat) => write!(f, "Latitude value out of bounds. Should be in [-90.0..=90.0] degrees range. Got {lat}"),
            FixedError::LongitudeOutOfBounds(lon) => write!(f, "Longitude value out of bounds. Should be between [-180.0..=180.0] degrees range. Got {lon}"),
        }
    }
}

/// A fixed position provider.
#[derive(Debug)]
pub struct Fixed {
    position: GpsInfo,
}

impl Fixed {
    /// Constructs a new [Fixed] position provider from a `latitude`, `longitude` and `altitude`.
    /// `latitude` and `longitude` are expected to be in degrees units.
    /// `altitude` is expected to be in meters units.
    pub fn new(latitude: f64, longitude: f64, altitude: f64) -> FixedResult<Fixed> {
        let mut position = GpsInfo::default();

        let latitude = Latitude::new::<degree>(latitude);
        let longitude = Longitude::new::<degree>(longitude);
        let altitude = Length::new::<meter>(altitude);

        if !latitude.is_valid_latitude_value() {
            return Err(FixedError::LatitudeOutOfBounds(latitude.get::<degree>()));
        }

        if !longitude.is_valid_longitude_value() {
            return Err(FixedError::LongitudeOutOfBounds(longitude.get::<degree>()));
        }

        position.fix.time = Some(Utc::now());
        position.fix.mode = FixMode::Fix3d;
        position.fix.latitude = Some(latitude);
        position.fix.longitude = Some(longitude);
        position.fix.altitude = Some(altitude);

        // Fixed values for track and speed.
        position.fix.track = Some(Angle::new::<degree>(0.0));
        position.fix.speed = Some(Velocity::new::<meter_per_second>(0.0));

        // Confidence is set to max precision values.
        position.confidence = Some(crate::Confidence {
            semi_major_axis: Length::new::<meter>(0.0),
            semi_minor_axis: Length::new::<meter>(0.0),
            semi_major_orientation: Angle::new::<degree>(0.0),
        });

        Ok(Fixed { position })
    }

    /// Fetch the position from the [Fixed] provider.
    pub fn fetch_position(&mut self) -> GpsInfo {
        // Update the timestamp
        self.position.fix.time = Some(Utc::now());

        self.position
    }
}
