use core::f32::consts::FRAC_PI_2;
use core::mem;

use crate::types::{meter, Latitude, LatitudeTrait, Longitude, LongitudeTrait};
use uom::si::angle::radian;
use uom::si::f32::{Angle, Length, Ratio};
use uom::si::ratio::ratio;
use uom::typenum::{P2, P3};

/// The equatorial radius of WGS84 ellipsoid (6_378_137 m).
const WGS84_A: f32 = 6_378_137.0;
/// The inverse flattening of WGS84 ellipsoid (1/298.257223563).
const WGS84_F: f32 = 1.0 / (298_257_223_563.0 / 1_000_000_000.0);

const GEO_TRANSFORM_MATRIX_LEN: usize = 9;

pub struct Geocentric {
    /// Equatorial radius of the WGS84 ellipsoid.
    a: Length,
    /// Inverse flattening of the WGS84 ellipsoid.
    f: Ratio,
    /// Square of Eccentricity.
    e_sq: Ratio,
    /// Square of Eccentricity.
    e_sq_m: Ratio,
    /// Square of Eccentricity absolute value.
    e_sq_a: Ratio,
    /// Square of [Geocentric::e_sq] absolute value.
    e_4_a: Ratio,
    /// Maximum usable radius.
    max_radius: Length,
}

impl Geocentric {
    pub fn wgs_84() -> Self {
        let a = Length::new::<meter>(WGS84_A);
        let f = Ratio::new::<ratio>(WGS84_F);
        let e_sq = f * (Ratio::new::<ratio>(2.0) - f);
        let e_sq_m = (Ratio::new::<ratio>(1.0) - f) * (Ratio::new::<ratio>(1.0) - f);
        let e_sq_a = e_sq.abs();
        let e_4_a = e_sq * e_sq;
        let max_radius = Ratio::new::<ratio>(2.0) * a / Ratio::new::<ratio>(f32::EPSILON);

        Geocentric {
            a,
            f,
            e_sq,
            e_sq_m,
            e_sq_a,
            e_4_a,
            max_radius,
        }
    }

    /// Convert from geodetic to geocentric coordinates with 'lat' and 'lon' value validity check.
    /// `lat` latitude of point (degrees).
    /// `lon` longitude of point (degrees).
    /// `alt` height of point above the ellipsoid (meters).
    /// Returns a [`GeocentricPosition`] containing the (x,y,z) geocentric coordinates.
    #[allow(unused)]
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

    /// Convert from geocentric to geodetic coordinates.
    /// `geocentric` geocentric point coordinates.
    /// Returns a tuple containing the (latitude,longitude,altitude) of the point in geodetic coordinates.
    /// Warning: altitude value should not be considered accurate.
    pub fn reverse(
        &self,
        geocentric: GeocentricPosition,
        transform: Option<&mut [Ratio; GEO_TRANSFORM_MATRIX_LEN]>,
    ) -> (Latitude, Longitude, Length) {
        let GeocentricPosition { x, y, z } = geocentric;

        let mut r = x.hypot(y);
        let mut sin_lambda = if r != Length::new::<meter>(0.0) {
            y / r
        } else {
            Ratio::new::<ratio>(0.0)
        };

        let mut cos_lambda = if r != Length::new::<meter>(0.0) {
            x / r
        } else {
            Ratio::new::<ratio>(1.0)
        };

        let mut sin_phi;
        let cos_phi;

        /* Distance to center of earth. */
        let mut alt = r.hypot(z);

        if alt > self.max_radius {
            /* Really far away case. */
            let x_scaled = x / Ratio::new::<ratio>(2.0);
            let y_scaled = y / Ratio::new::<ratio>(2.0);
            let z_scaled = z / Ratio::new::<ratio>(2.0);

            r = x_scaled.hypot(y_scaled);
            sin_lambda = if r != Length::new::<meter>(0.0) {
                y_scaled / r
            } else {
                Ratio::new::<ratio>(0.0)
            };

            cos_lambda = if r != Length::new::<meter>(0.0) {
                x_scaled / r
            } else {
                Ratio::new::<ratio>(1.0)
            };

            let h = z_scaled.hypot(r);
            sin_phi = z_scaled / h;
            cos_phi = r / h;
        } else if self.e_4_a == Ratio::new::<ratio>(0.0) {
            /* Spherical case. */
            let h = if alt == Length::new::<meter>(0.0) {
                Length::new::<meter>(1.0).hypot(r)
            } else {
                z.hypot(r)
            };

            sin_phi = if h == Length::new::<meter>(0.0) {
                Length::new::<meter>(1.0) / h
            } else {
                z / h
            };

            cos_phi = r / h;
            alt -= self.a;
        } else {
            /* Prolate spheroid case. */
            let mut p = (r / self.a).powi(P2::new());
            let mut q = self.e_sq_m * (z / self.a).powi(P2::new());
            let r_ = (p + q - self.e_4_a) / Ratio::new::<ratio>(6.0);
            if self.f < Ratio::new::<ratio>(0.0) {
                mem::swap(&mut p, &mut q);
            }

            if !(self.e_4_a * q == Ratio::new::<ratio>(0.0) && r_ <= Ratio::new::<ratio>(0.0)) {
                let s = self.e_4_a * p * q / Ratio::new::<ratio>(4.0);
                let r2_ = r_.powi(P2::new());
                let r3_ = r_.powi(P3::new());
                let disc = s * (Ratio::new::<ratio>(2.0) * r3_ + s);
                let mut u = r_;

                if disc >= Ratio::new::<ratio>(0.0) {
                    let mut t3 = s + r3_;
                    t3 += if t3 < Ratio::new::<ratio>(0.0) {
                        -disc.sqrt()
                    } else {
                        disc.sqrt()
                    };
                    let t = t3.cbrt();
                    u += t + if t != Ratio::new::<ratio>(0.0) {
                        r2_ / t
                    } else {
                        Ratio::new::<ratio>(0.0)
                    };
                } else {
                    let ang = (-disc).sqrt().atan2(-(s + r3_));
                    let ang_div_3 = ang / 3.0;
                    u += Ratio::new::<ratio>(2.0) * r_ * ang_div_3.cos();
                }
                let v = (u.powi(P2::new()) + self.e_4_a * q).sqrt();
                let uv = if u < Ratio::new::<ratio>(0.0) {
                    self.e_4_a * q / (v - u)
                } else {
                    u + v
                };
                let w = Ratio::new::<ratio>(0.0).max(self.e_sq_a * (uv - q) / (2.0 * v));
                let k = uv / ((uv + w.powi(P2::new())).sqrt() + w);
                let k1 = if self.f >= Ratio::new::<ratio>(0.0) {
                    k
                } else {
                    k - self.e_sq
                };
                let k2 = if self.f >= Ratio::new::<ratio>(0.0) {
                    k + self.e_sq
                } else {
                    k
                };
                let d = k1 * r / k2;
                let h = (z / k1).hypot(r / k2);
                sin_phi = (z / k1) / h;
                cos_phi = (r / k2) / h;
                alt = (Ratio::new::<ratio>(1.0) - self.e_sq_m / k1) * d.hypot(z);
            } else {
                let zz = (if self.f >= Ratio::new::<ratio>(0.0) {
                    self.e_4_a - p
                } else {
                    p
                } / self.e_sq_m)
                    .sqrt();
                let xx = (if self.f < Ratio::new::<ratio>(0.0) {
                    self.e_4_a - p
                } else {
                    p
                })
                .sqrt();
                let h = zz.hypot(xx);
                sin_phi = zz / h;
                cos_phi = xx / h;
                if z < Length::new::<meter>(0.0) {
                    sin_phi = -sin_phi;
                }
                alt = -self.a
                    * (if self.f >= Ratio::new::<ratio>(0.0) {
                        self.e_sq_m
                    } else {
                        Ratio::new::<ratio>(1.0)
                    })
                    * h
                    / self.e_sq_a;
            }
        }

        let lat = sin_phi.atan2(cos_phi);
        let lon = sin_lambda.atan2(cos_lambda);

        if let Some(mat) = transform {
            self.rotation(&sin_phi, &cos_phi, &sin_lambda, &cos_lambda, mat);
        }

        (lat, lon, alt)
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

#[allow(unused)]
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
    #[allow(unused)]
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
    #[allow(unused)]
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

    /// Convert from the local cartesian system to geodetic coordinates.
    /// `geo_pos` local cartesian point coordinates.
    /// Returns a tuple containing the (latitude,longitude,altitude) of the point in geodetic coordinates.
    /// Warning: altitude value should not be considered accurate.
    #[allow(unused)]
    pub fn reverse(&self, geo_pos: GeocentricPosition) -> (Latitude, Longitude, Length) {
        let geocentric = GeocentricPosition {
            x: self.origin_geo_pos.x
                + self.transform[0] * geo_pos.x
                + self.transform[1] * geo_pos.y
                + self.transform[2] * geo_pos.z,
            y: self.origin_geo_pos.y
                + self.transform[3] * geo_pos.x
                + self.transform[4] * geo_pos.y
                + self.transform[5] * geo_pos.z,
            z: self.origin_geo_pos.z
                + self.transform[6] * geo_pos.x
                + self.transform[7] * geo_pos.y
                + self.transform[8] * geo_pos.z,
        };

        self.proj.reverse(geocentric, None)
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

impl GeocentricPosition {
    /// Rotate self using `azimuth` angle.
    pub fn rotate(&mut self, azimuth: Angle) {
        let zenith = Angle::new::<radian>(FRAC_PI_2) - azimuth;
        let (sin_z, cos_z) = zenith.sin_cos();

        self.x = cos_z * self.x + sin_z * self.y;
        self.y = -sin_z * self.x + cos_z * self.y;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::{degree, Latitude, Longitude};
    use approx::assert_relative_eq;

    #[test]
    fn test_reverse() {
        let geocentric_system = Geocentric::wgs_84();

        // Point to move
        let system = LocalCartesian::new_unchecked(
            geocentric_system,
            Latitude::new::<degree>(48.2764384),
            Longitude::new::<degree>(-3.5519532),
            Length::new::<meter>(0.0),
        );

        let move_to = GeocentricPosition {
            x: Length::new::<meter>(-1000.0),
            y: Length::new::<meter>(-1000.0),
            z: Length::new::<meter>(0.0),
        };

        let (lat, lon, _) = system.reverse(move_to);

        assert_relative_eq!(lat.get::<degree>(), 48.267450);
        assert_relative_eq!(lon.get::<degree>(), -3.565424);

        let move_to = GeocentricPosition {
            x: Length::new::<meter>(-1000.0),
            y: Length::new::<meter>(1000.0),
            z: Length::new::<meter>(0.0),
        };

        let (lat, lon, _) = system.reverse(move_to);

        assert_relative_eq!(lat.get::<degree>(), 48.285430);
        assert_relative_eq!(lon.get::<degree>(), -3.565428);

        let move_to = GeocentricPosition {
            x: Length::new::<meter>(1000.0),
            y: Length::new::<meter>(1000.0),
            z: Length::new::<meter>(0.0),
        };

        let (lat, lon, _) = system.reverse(move_to);

        assert_relative_eq!(lat.get::<degree>(), 48.285430);
        assert_relative_eq!(lon.get::<degree>(), -3.538478);

        let move_to = GeocentricPosition {
            x: Length::new::<meter>(1000.0),
            y: Length::new::<meter>(-1000.0),
            z: Length::new::<meter>(0.0),
        };

        let (lat, lon, _) = system.reverse(move_to);

        assert_relative_eq!(lat.get::<degree>(), 48.267450);
        assert_relative_eq!(lon.get::<degree>(), -3.538483);
    }
}
