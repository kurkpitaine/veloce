use super::wgs::{Geocentric, LocalCartesian};
use crate::geonet::types::{meter, radian, Distance, Latitude, Longitude};
use crate::geonet::wire::{GeoAnycastRepr, GeoBroadcastRepr, GeonetPacketType};

use core::f32::consts::FRAC_PI_2;
use uom::si::f32::{Angle, Length, Ratio};
use uom::si::ratio::ratio;
use uom::typenum::P2;

/// A cartesian position, defined with abscissa X and ordinate Y coordinates.
#[derive(Debug, Clone, Copy)]
pub struct CartesianPosition {
    /// X coordinate.
    pub x: Distance,
    /// Y coordinate.
    pub y: Distance,
}

/// A geographic position, defined with latitude and longitude coordinates.
#[derive(Debug, Clone, Copy)]
pub struct GeoPosition {
    /// Latitude of the position.
    pub latitude: Latitude,
    /// Longitude of the position.
    pub longitude: Longitude,
}

impl GeoPosition {
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
            Ratio::new::<ratio>(f32::NEG_INFINITY)
        }
    }
}

/// A rectangle area shape.
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
            Ratio::new::<ratio>(f32::NEG_INFINITY)
        }
    }
}

/// An ellipse area shape.
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
            Ratio::new::<ratio>(f32::NEG_INFINITY)
        }
    }
}

/// Area shape.
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
    pub(crate) fn geometric_function(&self, position: CartesianPosition) -> Ratio {
        match self {
            Shape::Circle(c) => c.geometric_function(position),
            Shape::Rectangle(r) => r.geometric_function(position),
            Shape::Ellipse(e) => e.geometric_function(position),
        }
    }

    /// Query wether `position` is inside shape.
    pub fn inside_shape(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) > Ratio::new::<ratio>(0.0)
    }

    /// Query wether `position` is outside shape.
    pub fn outside_shape(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) < Ratio::new::<ratio>(0.0)
    }

    /// Query wether `position` is at shape border.
    pub fn at_shape_border(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) == Ratio::new::<ratio>(0.0)
    }

    /// Query wether `position` is at shape center.
    pub fn at_shape_center(&self, position: CartesianPosition) -> bool {
        self.geometric_function(position) == Ratio::new::<ratio>(1.0)
    }
}

/// A geographic area as described in ETSI EN 302 931 - V1.1.0.
/// An area is a geometric `shape` [`Shape`], centered at a `position` [`GeoPosition`] and oriented towards an `angle` [`Angle`].
pub struct Area {
    /// Shape of the area.
    pub shape: Shape,
    /// Position (center) of the area.
    pub position: GeoPosition,
    /// Angle (orientation) of the area.
    pub angle: Angle,
}

impl Area {
    /// Constructs a new Area from a [`GeoAnycastRepr`].
    ///
    /// # Panics
    ///
    /// This method panics when `header_type` is not one of
    /// [`GeonetPacketType::GeoAnycastCircle`], [`GeonetPacketType::GeoAnycastRect`]
    /// and [`GeonetPacketType::GeoAnycastElip`] type.
    pub fn from_gac(header_type: &GeonetPacketType, gac_repr: &GeoAnycastRepr) -> Self {
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

        Area {
            shape,
            position: GeoPosition {
                latitude: gac_repr.latitude,
                longitude: gac_repr.longitude,
            },
            angle: gac_repr.angle,
        }
    }

    /// Constructs a new Area from a [`GeoBroadcastRepr`].
    ///
    /// # Panics
    ///
    /// This method panics when `header_type` is not one of
    /// [`GeonetPacketType::GeoBroadcastCircle`], [`GeonetPacketType::GeoBroadcastRect`]
    /// and [`GeonetPacketType::GeoBroadcastElip`] type.
    pub fn from_gbc(header_type: &GeonetPacketType, gbc_repr: &GeoBroadcastRepr) -> Self {
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

        Area {
            shape,
            position: GeoPosition {
                latitude: gbc_repr.latitude,
                longitude: gbc_repr.longitude,
            },
            angle: gbc_repr.angle,
        }
    }

    pub fn inside_or_at_border(&self, position: GeoPosition) -> bool {
        let local = to_cartesian(self.position, position);
        let rotated = rotate(local, self.angle);
        !self.shape.outside_shape(rotated)
    }
}

/// Converts a geographic position `position` into a cartesian position in the
/// coordinates system centered on `origin`.
pub(crate) fn to_cartesian(origin: GeoPosition, position: GeoPosition) -> CartesianPosition {
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
pub(crate) fn rotate(point: CartesianPosition, azimuth: Angle) -> CartesianPosition {
    let zenith = Angle::new::<radian>(FRAC_PI_2) - azimuth;
    let (sin_z, cos_z) = zenith.sin_cos();

    CartesianPosition {
        x: cos_z * point.x + sin_z * point.y,
        y: -sin_z * point.x + cos_z * point.y,
    }
}
