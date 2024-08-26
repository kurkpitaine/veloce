use super::wgs::{Geocentric, LocalCartesian};
use crate::types::{meter, radian, Distance, Latitude, Longitude};
use crate::wire::{GeoAnycastRepr, GeoBroadcastRepr, GeonetPacketType};

use core::f64::consts::FRAC_PI_2;
use core::f64::consts::PI;
use uom::si::area::square_kilometer;
use uom::si::f64::{Angle, Area, Length, Ratio};
use uom::si::length::kilometer;
use uom::si::ratio::ratio;
use uom::typenum::P2;

/// Trait on [`Shape`] defining the `distance_a` and `distance_b` extraction methods.
pub trait DistanceAB {
    /// Return the "distance a" of the shape.
    fn distance_a(&self) -> Distance;
    /// Return the "distance b" of the shape.
    fn distance_b(&self) -> Distance;
    /// Return "distance_a" and "distance b" of the shape.
    fn distances(&self) -> (Distance, Distance) {
        (self.distance_a(), self.distance_b())
    }
}

/// A cartesian position, defined with abscissa X and ordinate Y coordinates.
#[derive(Debug, Clone, Copy)]
pub struct CartesianPosition {
    /// X coordinate.
    pub x: Distance,
    /// Y coordinate.
    pub y: Distance,
}

/// A geographic position, defined with latitude and longitude coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoPosition {
    /// Latitude of the position.
    pub latitude: Latitude,
    /// Longitude of the position.
    pub longitude: Longitude,
}

impl GeoPosition {
    /// Compute the distance to `other` position.
    pub fn distance_to(&self, rhs: &GeoPosition) -> Length {
        let r = Length::new::<meter>(6371008.8); // Mean earth radius in meters.
        let haversine = |theta: Angle| (theta / 2.0).sin().powi(P2::new());
        let delta_lat = self.latitude - self.latitude;
        let delta_lon = self.longitude - self.longitude;

        let a =
            haversine(delta_lat) + self.latitude.cos() * rhs.latitude.cos() * haversine(delta_lon);

        Ratio::new::<ratio>(2.0) * r * a.sqrt().atan2((Ratio::new::<ratio>(1.0) - a).sqrt())
    }
}

/// A circle area shape.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct Circle {
    /// Radius of the circle.
    pub radius: Distance,
}

impl Circle {
    /// Geometric function for the circle shape as described in ETSI EN 302 931 - V1.1.0.
    pub(crate) fn geometric_function(&self, position: CartesianPosition) -> Ratio {
        if self.radius > Distance::new::<meter>(0.0) {
            let x_over_r = position.x / self.radius;
            let y_over_r = position.y / self.radius;
            Ratio::new::<ratio>(1.0) - (x_over_r * x_over_r) - (y_over_r * y_over_r)
        } else {
            Ratio::new::<ratio>(f64::NEG_INFINITY)
        }
    }
}

impl DistanceAB for Circle {
    fn distance_a(&self) -> Distance {
        self.radius
    }

    fn distance_b(&self) -> Distance {
        Distance::new::<meter>(0.0)
    }
}

/// A rectangle area shape.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct Rectangle {
    /// Center to long side length.
    pub a: Distance,
    /// Center to short side length.
    pub b: Distance,
}

impl Rectangle {
    /// Geometric function for the rectangle shape as described in ETSI EN 302 931 - V1.1.0.
    pub(crate) fn geometric_function(&self, position: CartesianPosition) -> Ratio {
        if self.a > Distance::new::<meter>(0.0) && self.b > Distance::new::<meter>(0.0) {
            let x_over_a = position.x / self.a;
            let y_over_b = position.y / self.b;
            let x_op = Ratio::new::<ratio>(1.0) - x_over_a * x_over_a;
            let y_op = Ratio::new::<ratio>(1.0) - y_over_b * y_over_b;
            x_op.min(y_op)
        } else {
            Ratio::new::<ratio>(f64::NEG_INFINITY)
        }
    }
}

impl DistanceAB for Rectangle {
    fn distance_a(&self) -> Distance {
        self.a
    }

    fn distance_b(&self) -> Distance {
        self.b
    }
}

/// An ellipse area shape.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct Ellipse {
    /// Center to long side length.
    pub a: Distance,
    /// Center to short side length.
    pub b: Distance,
}

impl Ellipse {
    /// Geometric function for the ellipse shape as described in ETSI EN 302 931 - V1.1.0.
    pub(crate) fn geometric_function(&self, position: CartesianPosition) -> Ratio {
        if self.a > Distance::new::<meter>(0.0) && self.b > Distance::new::<meter>(0.0) {
            let x_over_a = position.x / self.a;
            let y_over_b = position.y / self.b;
            Ratio::new::<ratio>(1.0) - x_over_a * x_over_a - y_over_b * y_over_b
        } else {
            Ratio::new::<ratio>(f64::NEG_INFINITY)
        }
    }
}

impl DistanceAB for Ellipse {
    fn distance_a(&self) -> Distance {
        self.a
    }

    fn distance_b(&self) -> Distance {
        self.b
    }
}

/// Area shape.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum Shape {
    /// Shape is circle.
    Circle(Circle),
    /// Shape is rectangle.
    Rectangle(Rectangle),
    /// Shape is ellipse.
    Ellipse(Ellipse),
}

impl Shape {
    /// Geometric function for each [`Shape`].
    fn geometric_function(&self, position: CartesianPosition) -> Ratio {
        match self {
            Shape::Circle(c) => c.geometric_function(position),
            Shape::Rectangle(r) => r.geometric_function(position),
            Shape::Ellipse(e) => e.geometric_function(position),
        }
    }

    /// Query whether `position` is inside shape.
    pub fn inside_shape(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) > Ratio::new::<ratio>(0.0)
    }

    /// Query whether `position` is outside shape.
    pub fn outside_shape(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) < Ratio::new::<ratio>(0.0)
    }

    /// Query whether `position` is at shape border.
    pub fn at_shape_border(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) == Ratio::new::<ratio>(0.0)
    }

    /// Query whether `position` is at shape center.
    pub fn at_shape_center(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) == Ratio::new::<ratio>(1.0)
    }
}

impl DistanceAB for Shape {
    fn distance_a(&self) -> Distance {
        match self {
            Shape::Circle(c) => c.distance_a(),
            Shape::Rectangle(r) => r.distance_a(),
            Shape::Ellipse(e) => e.distance_a(),
        }
    }

    fn distance_b(&self) -> Distance {
        match self {
            Shape::Circle(c) => c.distance_b(),
            Shape::Rectangle(r) => r.distance_b(),
            Shape::Ellipse(e) => e.distance_a(),
        }
    }
}

/// A geographic area as described in ETSI EN 302 931 - V1.1.0.
/// An area is a geometric `shape` [`Shape`], centered at a `position` [`GeoPosition`] and oriented towards an `angle` [`Angle`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct GeoArea {
    /// Shape of the area.
    pub shape: Shape,
    /// Position (center) of the area.
    pub position: GeoPosition,
    /// Angle (orientation) of the area.
    pub angle: Angle,
}

impl GeoArea {
    /// Constructs a new Area from a [`GeoAnycastRepr`].
    ///
    /// # Panics
    ///
    /// This method panics when `header_type` is not one of
    /// [`GeonetPacketType::GeoAnycastCircle`], [`GeonetPacketType::GeoAnycastRect`]
    /// and [`GeonetPacketType::GeoAnycastElip`] type.
    pub const fn from_gac(header_type: &GeonetPacketType, gac_repr: &GeoAnycastRepr) -> Self {
        let shape = match header_type {
            GeonetPacketType::GeoAnycastCircle => Shape::Circle(Circle {
                radius: gac_repr.distance_a,
            }),
            GeonetPacketType::GeoAnycastRect => Shape::Rectangle(Rectangle {
                a: gac_repr.distance_a,
                b: gac_repr.distance_b,
            }),
            GeonetPacketType::GeoAnycastElip => Shape::Ellipse(Ellipse {
                a: gac_repr.distance_a,
                b: gac_repr.distance_b,
            }),
            _ => panic!(),
        };

        Self {
            shape,
            position: GeoPosition {
                latitude: gac_repr.latitude,
                longitude: gac_repr.longitude,
            },
            angle: gac_repr.angle,
        }
    }

    /// Constructs a new GeoArea from a [`GeoBroadcastRepr`].
    ///
    /// # Panics
    ///
    /// This method panics when `header_type` is not one of
    /// [`GeonetPacketType::GeoBroadcastCircle`], [`GeonetPacketType::GeoBroadcastRect`]
    /// and [`GeonetPacketType::GeoBroadcastElip`] type.
    pub const fn from_gbc(header_type: &GeonetPacketType, gbc_repr: &GeoBroadcastRepr) -> Self {
        let shape = match header_type {
            GeonetPacketType::GeoBroadcastCircle => Shape::Circle(Circle {
                radius: gbc_repr.distance_a,
            }),
            GeonetPacketType::GeoBroadcastRect => Shape::Rectangle(Rectangle {
                a: gbc_repr.distance_a,
                b: gbc_repr.distance_b,
            }),
            GeonetPacketType::GeoBroadcastElip => Shape::Ellipse(Ellipse {
                a: gbc_repr.distance_a,
                b: gbc_repr.distance_b,
            }),
            _ => panic!(),
        };

        Self {
            shape,
            position: GeoPosition {
                latitude: gbc_repr.latitude,
                longitude: gbc_repr.longitude,
            },
            angle: gbc_repr.angle,
        }
    }

    /// Query whether `position` is inside or at border of the [GeoArea].
    pub fn inside_or_at_border(&self, position: GeoPosition) -> bool {
        let local = to_cartesian(self.position, position);
        let rotated = rotate(local, self.angle);
        !self.shape.outside_shape(rotated)
    }

    /// Computes the [GeoArea] size.
    pub fn size(&self) -> Area {
        match self.shape {
            Shape::Circle(c) => Area::new::<square_kilometer>(
                PI * c.distance_a().get::<kilometer>() * c.distance_a().get::<kilometer>(),
            ),
            Shape::Rectangle(r) => Area::new::<square_kilometer>(
                4.0 * r.distance_a().get::<kilometer>() * r.distance_b().get::<kilometer>(),
            ),
            Shape::Ellipse(e) => Area::new::<square_kilometer>(
                PI * e.distance_a().get::<kilometer>() * e.distance_b().get::<kilometer>(),
            ),
        }
    }
}

/// Converts a geographic position `position` into a cartesian position in the
/// coordinates system centered on `origin`.
fn to_cartesian(origin: GeoPosition, position: GeoPosition) -> CartesianPosition {
    let geocentric_system = Geocentric::wgs_84();
    let system = LocalCartesian::new_unchecked(
        geocentric_system,
        origin.latitude,
        origin.longitude,
        Length::new::<meter>(0.0),
    );

    let cartesian = system.forward_unchecked(
        position.latitude,
        position.longitude,
        Length::new::<meter>(0.0),
    );

    CartesianPosition {
        x: cartesian.x,
        y: cartesian.y,
    }
}

/// Rotate a `point` using `azimuth` angle.
fn rotate(point: CartesianPosition, azimuth: Angle) -> CartesianPosition {
    let zenith = Angle::new::<radian>(FRAC_PI_2) - azimuth;
    let (sin_z, cos_z) = zenith.sin_cos();

    CartesianPosition {
        x: cos_z * point.x + sin_z * point.y,
        y: -sin_z * point.x + cos_z * point.y,
    }
}

#[cfg(test)]
mod test {
    use super::{Circle, GeoArea, GeoPosition, Shape};
    use crate::{
        common::geo_area::{Ellipse, Rectangle},
        types::{Distance, Latitude, Longitude},
    };
    use uom::si::{angle::degree, f64::Angle, length::meter};

    #[test]
    fn test_circle_geo_zone() {
        let area = GeoArea {
            shape: Shape::Circle(Circle {
                radius: Distance::new::<meter>(500.0),
            }),
            position: GeoPosition {
                latitude: Latitude::new::<degree>(48.2764384),
                longitude: Longitude::new::<degree>(-3.5519532),
            },
            angle: Angle::new::<degree>(0.0),
        };

        let inside = GeoPosition {
            latitude: Latitude::new::<degree>(48.277888),
            longitude: Longitude::new::<degree>(-3.552507),
        };

        assert!(area.inside_or_at_border(inside));

        let outside = GeoPosition {
            latitude: Latitude::new::<degree>(48.273751),
            longitude: Longitude::new::<degree>(-3.535616),
        };

        assert!(!area.inside_or_at_border(outside));
    }

    #[test]
    fn test_rectangle_geo_zone() {
        let mut area = GeoArea {
            shape: Shape::Rectangle(Rectangle {
                a: Distance::new::<meter>(125.0),
                b: Distance::new::<meter>(250.0),
            }),
            position: GeoPosition {
                latitude: Latitude::new::<degree>(48.2764384),
                longitude: Longitude::new::<degree>(-3.5519532),
            },
            angle: Angle::new::<degree>(0.0),
        };

        let inside = GeoPosition {
            latitude: Latitude::new::<degree>(48.277027),
            longitude: Longitude::new::<degree>(-3.552216),
        };

        assert!(area.inside_or_at_border(inside));

        let outside = GeoPosition {
            latitude: Latitude::new::<degree>(48.278316),
            longitude: Longitude::new::<degree>(-3.553161),
        };

        assert!(!area.inside_or_at_border(outside));

        // Rotate shape to make "outside" point inside the rectangle.
        area.angle = Angle::new::<degree>(45.0);

        assert!(area.inside_or_at_border(outside));
    }

    #[test]
    fn test_ellipse_geo_zone() {
        let mut area = GeoArea {
            shape: Shape::Ellipse(Ellipse {
                a: Distance::new::<meter>(125.0),
                b: Distance::new::<meter>(250.0),
            }),
            position: GeoPosition {
                latitude: Latitude::new::<degree>(48.2764384),
                longitude: Longitude::new::<degree>(-3.5519532),
            },
            angle: Angle::new::<degree>(0.0),
        };

        let inside = GeoPosition {
            latitude: Latitude::new::<degree>(48.277027),
            longitude: Longitude::new::<degree>(-3.552216),
        };

        assert!(area.inside_or_at_border(inside));

        let outside = GeoPosition {
            latitude: Latitude::new::<degree>(48.278316),
            longitude: Longitude::new::<degree>(-3.553161),
        };

        assert!(!area.inside_or_at_border(outside));

        // Rotate shape to make "outside" point inside the ellipse.
        area.angle = Angle::new::<degree>(65.0);

        assert!(area.inside_or_at_border(outside));
    }
}
