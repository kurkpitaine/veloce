use crate::geonet::types::{meter, Latitude, LatitudeTrait, Longitude, LongitudeTrait};
use uom::si::f32::{Length, Ratio};
use uom::si::ratio::ratio;

/// The equatorial radius of WGS84 ellipsoid (6_378_137 m).
const WGS84_A: f32 = 6_378_137.0;
/// The inverse flattening of WGS84 ellipsoid (1/298.257223563).
const WGS84_F: f32 = 1.0 / (298_257_223_563.0 / 1_000_000_000.0);

const GEO_TRANSFORM_MATRIX_LEN: usize = 9;

pub struct Geocentric {
    /// Equatorial radius of the WGS84 ellipsoid.
    a: Length,
    /// Square of Eccentricity.
    e_sq: Ratio,
    /// Square of Eccentricity.
    e_sq_m: Ratio,
}

impl Geocentric {
    pub fn wgs_84() -> Self {
        let a = Length::new::<meter>(WGS84_A);
        let f = Ratio::new::<ratio>(WGS84_F);
        let e_sq = f * (Ratio::new::<ratio>(2.0) - f);
        let e_sq_m = (Ratio::new::<ratio>(1.0) - f) * (Ratio::new::<ratio>(1.0) - f);

        Geocentric { a, e_sq, e_sq_m }
    }

    /// Convert from geodetic to geocentric coordinates with 'lat' and 'lon' value validity check.
    /// `lat` latitude of point (degrees).
    /// `lon` longitude of point (degrees).
    /// `alt` height of point above the ellipsoid (meters).
    /// Returns a [`GeocentricPosition`] containing the (x,y,z) geocentric coordinates.
    pub fn forward_checked(
        &self,
        lat: Latitude,
        lon: Longitude,
        alt: Length,
        transform: Option<&mut [Ratio; GEO_TRANSFORM_MATRIX_LEN]>,
    ) -> Result<GeocentricPosition, InvalidCoord> {
        if !lat.is_valid_latitude_value() {
            return Err(InvalidCoord::InvalidLat);
        }

        if !lon.is_valid_longitude_value() {
            return Err(InvalidCoord::InvalidLon);
        }

        Ok(self.forward_unchecked(lat, lon, alt, transform))
    }

    /// Convert from geodetic to geocentric coordinates without checking 'lat' and 'lon' value validity.
    /// `lat` latitude of point (degrees).
    /// `lon` longitude of point (degrees).
    /// `alt` height of point above the ellipsoid (meters).
    /// Returns a [`GeocentricPosition`] containing the (x,y,z) geocentric coordinates.
    pub fn forward_unchecked(
        &self,
        lat: Latitude,
        lon: Longitude,
        alt: Length,
        transform: Option<&mut [Ratio; GEO_TRANSFORM_MATRIX_LEN]>,
    ) -> GeocentricPosition {
        let (sin_phi, cos_phi) = lat.sin_cos();
        let (sin_lambda, cos_lambda) = lon.sin_cos();
        let n = self.a / (Ratio::new::<ratio>(1.0) - self.e_sq * sin_phi * sin_phi).sqrt();

        let x = (n + alt) * cos_phi;
        let y = x * sin_lambda;
        let z = (self.e_sq_m * n + alt) * sin_phi;

        if let Some(mat) = transform {
            self.rotation(&sin_phi, &cos_phi, &sin_lambda, &cos_lambda, mat);
        }

        GeocentricPosition {
            x: x * cos_lambda,
            y,
            z,
        }
    }

    /// Fills the `transform` matrix.
    pub fn rotation(
        &self,
        sin_phi: &Ratio,
        cos_phi: &Ratio,
        sin_lambda: &Ratio,
        cos_lambda: &Ratio,
        transform: &mut [Ratio; GEO_TRANSFORM_MATRIX_LEN],
    ) {
        transform[0] = -*sin_lambda;
        transform[1] = -*cos_lambda * *sin_phi;
        transform[2] = *cos_lambda * *cos_phi;
        transform[3] = *cos_lambda;
        transform[4] = -*sin_lambda * *sin_phi;
        transform[5] = *sin_lambda * *cos_phi;
        transform[6] = Ratio::new::<ratio>(0.0);
        transform[7] = *cos_phi;
        transform[8] = *sin_phi;
    }
}

pub struct LocalCartesian {
    /// Projection system.
    proj: Geocentric,
    /// Origin latitude.
    origin_lat: Latitude,
    /// Origin longitude.
    origin_lon: Longitude,
    /// Origin altitude.
    origin_alt: Length,
    /// Origin geocentric coordinates.
    origin_geo_pos: GeocentricPosition,
    /// Transform matrix.
    transform: [Ratio; GEO_TRANSFORM_MATRIX_LEN],
}

impl LocalCartesian {
    /// Constructs a new [`LocalCartesian`] with `lat` and `lon` values validity check.
    pub fn new_checked(
        proj: Geocentric,
        lat: Latitude,
        lon: Longitude,
        alt: Length,
    ) -> Result<LocalCartesian, InvalidCoord> {
        if !lat.is_valid_latitude_value() {
            return Err(InvalidCoord::InvalidLat);
        }

        if !lon.is_valid_longitude_value() {
            return Err(InvalidCoord::InvalidLon);
        }

        Ok(Self::new_unchecked(proj, lat, lon, alt))
    }

    /// Constructs a new [`LocalCartesian`] without checking `lat` and `lon` values.
    pub fn new_unchecked(
        proj: Geocentric,
        lat: Latitude,
        lon: Longitude,
        alt: Length,
    ) -> LocalCartesian {
        let mut matrix = [Ratio::new::<ratio>(0.0); GEO_TRANSFORM_MATRIX_LEN];
        let geo_pos = proj.forward_unchecked(lat, lon, alt, Some(&mut matrix));

        LocalCartesian {
            proj,
            origin_lat: lat,
            origin_lon: lon,
            origin_alt: alt,
            origin_geo_pos: geo_pos,
            transform: matrix,
        }
    }

    /// Convert from geodetic into the local cartesian system coordinates with 'lat' and 'lon' value validity check.
    /// `lat` latitude of point (degrees).
    /// `lon` longitude of point (degrees).
    /// `alt` height of point above the ellipsoid (meters).
    /// Returns a [`GeocentricPosition`] containing the (x,y,z) local cartesian coordinates.
    pub fn forward_checked(
        &self,
        lat: Latitude,
        lon: Longitude,
        alt: Length,
    ) -> Result<GeocentricPosition, InvalidCoord> {
        if !lat.is_valid_latitude_value() {
            return Err(InvalidCoord::InvalidLat);
        }

        if !lon.is_valid_longitude_value() {
            return Err(InvalidCoord::InvalidLon);
        }

        Ok(self.forward_unchecked(lat, lon, alt))
    }

    /// Convert from geodetic the local cartesian system coordinates without checking 'lat' and 'lon' value validity.
    /// `lat` latitude of point (degrees).
    /// `lon` longitude of point (degrees).
    /// `alt` height of point above the ellipsoid (meters).
    /// Returns a [`GeocentricPosition`] containing the (x,y,z) local cartesian coordinates.
    pub fn forward_unchecked(
        &self,
        lat: Latitude,
        lon: Longitude,
        alt: Length,
    ) -> GeocentricPosition {
        let mut geo_pos = self.proj.forward_unchecked(lat, lon, alt, None);
        geo_pos.x -= self.origin_geo_pos.x;
        geo_pos.y -= self.origin_geo_pos.y;
        geo_pos.z -= self.origin_geo_pos.z;

        GeocentricPosition {
            x: self.transform[0] * geo_pos.x
                + self.transform[3] * geo_pos.y
                + self.transform[6] * geo_pos.z,
            y: self.transform[1] * geo_pos.x
                + self.transform[4] * geo_pos.y
                + self.transform[7] * geo_pos.z,
            z: self.transform[2] * geo_pos.x
                + self.transform[5] * geo_pos.y
                + self.transform[8] * geo_pos.z,
        }
    }
}

pub enum InvalidCoord {
    /// Error representing an invalid latitude value.
    InvalidLat,
    /// Error representing an invalid longitude value.
    InvalidLon,
}

/// Geocentric position.
pub struct GeocentricPosition {
    /// x geocentric coordinate.
    pub x: Length,
    /// y geocentric coordinate.
    pub y: Length,
    /// z geocentric coordinate.
    pub z: Length,
}
