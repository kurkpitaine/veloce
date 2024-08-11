//! This module contains the implementation of the Poti module as defined in ETSI EN 302 890-2 V2.1.1.
//! Only the positioning part is implemented, timing is considered out of scope in Veloce Poti implementation.
#[cfg(not(feature = "std"))]
use alloc::collections::vec_deque::VecDeque;

#[cfg(feature = "std")]
use std::collections::VecDeque;

use heapless::HistoryBuffer;

use uom::si::{
    angle::degree,
    f32::Length,
    length::{centimeter, kilometer, meter},
    velocity::{centimeter_per_second, meter_per_second},
};

use crate::{
    time::{Duration, TAI2004},
    types::{decidegree, tenth_of_microdegree, Heading, Latitude, Longitude, Speed},
};

#[cfg(feature = "asn1")]
use veloce_asn1::{
    defs::etsi_messages_r2::etsi__its__cdd::{
        AltitudeConfidence as EtsiAltitudeConfidence, AltitudeValue as EtsiAltitudeValue,
        DeltaAltitude, DeltaLatitude, DeltaLongitude, DeltaReferencePosition,
        HeadingConfidence as EtsiHeadingConfidence, HeadingValue as EtsiHeadingValue,
        Latitude as EtsiLatitude, Longitude as EtsiLongitude, Path as EtsiPath, PathDeltaTime,
        PathPoint as EtsiPathPoint, SemiAxisLength as EtsiSemiAxisLength,
        SpeedConfidence as EtsiSpeedConfidence, SpeedValue as EtsiSpeedValue,
        Wgs84AngleValue as EtsiWgs84AngleValue,
    },
    prelude::rasn::types::{Integer, SequenceOf},
};

#[cfg(feature = "proto-security")]
use veloce_asn1::defs::etsi_103097_v211::ieee1609Dot2Base_types::ThreeDLocation;

use super::wgs::{Geocentric, GeocentricPosition, LocalCartesian};

/// Antenna offset values.
/// Vehicle coordinate system is defined in ISO 8855, ie:
/// - X axis is the East axis.
/// - Y axis is the North axis.
/// - Z axis is the Altitude axis.
///
/// The origin is the center of the edge of the front bumper of the vehicle,
/// at the ground level as defined in ETSI EN 302 890-2 V2.1.1.
/// So, assuming the vehicle is facing east (90° heading):
/// - A positive X value moves the received position towards east.
/// - A positive Y value moves the received position towards north.
/// - A positive Z value moves the received position upwards.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AntennaOffset(Length, Length, Length);

impl AntennaOffset {
    /// Create a new [AntennaOffset] with the given values.
    pub const fn new(x: Length, y: Length, z: Length) -> Self {
        Self(x, y, z)
    }

    /// Get the X offset value.
    pub const fn x(&self) -> Length {
        self.0
    }

    /// Get the Y offset value.
    pub const fn y(&self) -> Length {
        self.1
    }

    /// Get the Z offset value.
    pub const fn z(&self) -> Length {
        self.2
    }
}

/// [Poti] module configuration.
#[derive(Debug, Default)]
pub struct Config {
    /// Antenna offset values.
    antenna_offset: Option<AntennaOffset>,
}

/// Poti error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Error in fix.
    Fix(FixError),
}

/// Position and Timing aka `Poti`.
#[derive(Default, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Poti {
    /// Module configuration.
    config: Config,
    /// Position history.
    history: PathHistory,
    /// Current position fix.
    fix: Fix,
}

impl Poti {
    /// Create a Poti instance with default values.
    pub fn new() -> Self {
        Self {
            history: PathHistory::new(),
            ..Default::default()
        }
    }

    /// Push a new [Fix] to the [Poti] module.
    pub fn push_fix(&mut self, fix: Fix) -> Result<Fix, Error> {
        self.push_fix_inner(fix).map_err(|e| {
            // Keep the old fix but set it as gnss signal lost mode.
            self.fix.mode = Mode::Lost;
            e
        })
    }

    /// Get the current [Fix].
    pub fn fix(&self) -> &Fix {
        &self.fix
    }

    /// Query whether the [Fix] confidence values are available.
    /// See C2C Consortium Vehicle C-ITS station profile, requirement VRS_BSP_535.
    pub fn confidence_available(&self) -> bool {
        self.fix.confidence_available()
    }

    /// Get a reference on the current [PathHistory] points.
    pub fn path_history(&self) -> &PositionHistory {
        self.history.points()
    }

    fn push_fix_inner(&mut self, mut fix: Fix) -> Result<Fix, Error> {
        // ETSI EN 302 890-2 V2.1.1 requires that the fix must be in 3D mode.
        if !fix.is_mode_3d() {
            return Err(Error::Fix(FixError::Mode));
        }

        // Apply antenna offset if configured.
        if let Some(offset) = self.config.antenna_offset {
            fix.apply_antenna_offset(offset).map_err(Error::Fix)?;
        }

        // Heading latch.
        match (fix.should_latch_heading(), self.fix.motion.heading) {
            (Ok(true), Some(prev_hdg)) => {
                fix.motion.heading = Some(prev_hdg);
            }
            _ => {}
        }

        // C2C Consortium Vehicle C-ITS station profile, requirement RS_BSP_215.
        // Traces and path history data shall be generated only when position confidence information is available.
        if fix.confidence_available() {
            // Add the position to the history.
            self.history
                .push_position(PathPoint::try_from(&fix).map_err(Error::Fix)?);
        }

        // Assign the new fix.
        self.fix = fix;

        Ok(fix)
    }
}

/// Fix error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FixError {
    /// Unexpected mode.
    Mode,
    /// No latitude value in fix.
    NoLatitude,
    /// No longitude value in fix.
    NoLongitude,
    /// No altitude value in fix.
    NoAltitude,
    /// No heading value in fix.
    NoHeading,
    /// No heading value in fix.
    NoHeadingConfidence,
    /// No speed value in fix.
    NoSpeed,
}

impl core::fmt::Display for FixError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FixError::Mode => write!(f, "Unexpected fix mode"),
            FixError::NoLatitude => write!(f, "No latitude value in fix"),
            FixError::NoLongitude => write!(f, "No longitude value in fix"),
            FixError::NoAltitude => write!(f, "No altitude value in fix"),
            FixError::NoHeading => write!(f, "No heading value in fix"),
            FixError::NoHeadingConfidence => write!(f, "No heading confidence value in fix"),
            FixError::NoSpeed => write!(f, "No speed value in fix"),
        }
    }
}

/// A Poti GNSS fix.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Fix {
    /// Fix mode.
    pub mode: Mode,
    /// Timestamp at which the `position`, `motion` and `confidence` values where received.
    pub timestamp: TAI2004,
    /// Position value.
    pub position: Position,
    /// Motion values at `position`.
    pub motion: Motion,
    /// Confidence of `position` and `motion` values.
    pub confidence: Confidence,
}

impl Fix {
    /// Get the latitude of the fix.
    pub fn latitude(&self) -> Result<Latitude, FixError> {
        self.position.latitude.ok_or(FixError::NoLatitude)
    }

    /// Get the longitude of the fix.
    pub fn longitude(&self) -> Result<Longitude, FixError> {
        self.position.longitude.ok_or(FixError::NoLongitude)
    }

    /// Get the altitude of the fix.
    pub fn altitude(&self) -> Result<Length, FixError> {
        self.position.altitude.ok_or(FixError::NoAltitude)
    }

    /// Get the heading of the fix.
    pub fn heading(&self) -> Result<Heading, FixError> {
        self.motion.heading.ok_or(FixError::NoHeading)
    }

    /// Get the speed of the fix.
    pub fn speed(&self) -> Result<Speed, FixError> {
        self.motion.speed.ok_or(FixError::NoSpeed)
    }

    /// Query whether the fix is in 3D mode.
    pub fn is_mode_3d(&self) -> bool {
        self.mode == Mode::Fix3d
    }

    /// Query whether self contains a stationary fix.
    /// "Does not move" is defined as when the speed is below 8cm/s.
    /// See C2C Consortium Vehicle C-ITS station profile, requirement VRS_BSP_511.
    /// Returns `Err(FixError::NoHeading)` if no heading is available.
    pub fn is_stationary(&self) -> Result<bool, FixError> {
        self.motion
            .speed
            .map(|s| s.get::<centimeter_per_second>() < 8.0)
            .ok_or(FixError::NoHeading)
    }

    /// Apply the antenna offset to the given `fix`.
    pub fn apply_antenna_offset(&mut self, offset: AntennaOffset) -> Result<(), FixError> {
        let lat = &mut self.position.latitude.ok_or(FixError::NoLatitude)?;
        let lon = &mut self.position.longitude.ok_or(FixError::NoLongitude)?;
        let alt = &mut self.position.altitude.ok_or(FixError::NoAltitude)?;
        let hdg = &mut self.motion.heading.ok_or(FixError::NoHeading)?;

        let geocentric_system = Geocentric::wgs_84();
        let system = LocalCartesian::new_unchecked(geocentric_system, *lat, *lon, *alt);
        let mut move_to = GeocentricPosition {
            x: offset.x(),
            y: offset.y(),
            z: offset.z(),
        };

        move_to.rotate(*hdg);

        let (m_lat, m_lon, _) = system.reverse(move_to);
        *lat = m_lat;
        *lon = m_lon;
        *alt += offset.z();

        Ok(())
    }

    /// Query whether the heading should be latched.
    /// Latching algorithm is defined in C2C Consortium Vehicle C-ITS station profile, requirement RS_BSP_444.
    /// Returns an error in case latching cannot be determined.
    pub fn should_latch_heading(&self) -> Result<bool, FixError> {
        let spd = self.motion.speed.ok_or(FixError::NoSpeed)?;
        let hdg_confidence = self
            .confidence
            .heading
            .ok_or(FixError::NoHeadingConfidence)?;

        if self.is_stationary()? {
            // Stationary, we can latch the heading.
            Ok(true)
        } else if spd.get::<meter_per_second>() < 1.4 && hdg_confidence.get::<degree>() > 12.5 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Query whether the [Fix] confidence values are available.
    /// See C2C Consortium Vehicle C-ITS station profile, requirement VRS_BSP_535.
    pub fn confidence_available(&self) -> bool {
        self.confidence
            .position
            .semi_major
            .is_some_and(|sm| sm.get::<centimeter>() < 4094.0)
            && self
                .confidence
                .position
                .semi_minor
                .is_some_and(|sm| sm.get::<centimeter>() < 4094.0)
            && self.confidence.position.semi_major_orientation.is_some()
            && self.confidence.altitude.is_some()
            && self.confidence.speed.is_some()
            && self.confidence.heading.is_some()
    }
}

/// Type of GPS fix.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Mode {
    /// No fix at all.
    #[default]
    NoFix,
    /// Two dimensional fix, 2D.
    Fix2d,
    /// Three dimensional fix, 3D (i.e. with altitude).
    Fix3d,
    /// GNSS signal lost.
    Lost,
}

/// Position category dimensions.
/// Describes a position, as 3D point (x,y,z) in a WGS84 coordinates system.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Position {
    /// Latitude of the position.
    pub latitude: Option<Latitude>,
    /// Longitude of the position.
    pub longitude: Option<Longitude>,
    /// Altitude of the position.
    pub altitude: Option<Length>,
}

impl Position {
    #[cfg(feature = "asn1")]
    /// Return the latitude as an [EtsiLongitude].
    pub fn latitude_value(&self) -> EtsiLatitude {
        self.latitude.map_or(EtsiLatitude(900_000_001), |lat| {
            let val = lat.get::<tenth_of_microdegree>() as i32;
            EtsiLatitude(val)
        })
    }

    #[cfg(feature = "asn1")]
    /// Return the longitude as an [EtsiLongitude].
    pub fn longitude_value(&self) -> EtsiLongitude {
        self.longitude.map_or(EtsiLongitude(1_800_000_001), |lon| {
            let val = lon.get::<tenth_of_microdegree>() as i32;
            EtsiLongitude(val)
        })
    }

    #[cfg(feature = "asn1")]
    /// Return the altitude as an [EtsiAltitudeValue].
    pub fn altitude_value(&self) -> EtsiAltitudeValue {
        self.altitude.map_or(EtsiAltitudeValue(800_001), |alt| {
            let val = alt.get::<centimeter>() as i32;
            EtsiAltitudeValue(val.clamp(-100_000, 800_000))
        })
    }

    #[cfg(feature = "proto-security")]
    /// Get the [Position] as a [ThreeDLocation] for use in security..
    pub fn as_3d_location(&self) -> ThreeDLocation {
        use veloce_asn1::defs::etsi_103097_v211::ieee1609Dot2Base_types::{
            Elevation, Latitude, Longitude, NinetyDegreeInt, OneEightyDegreeInt, ThreeDLocation,
            Uint16,
        };

        use uom::si::length::decimeter;

        let latitude = self
            .latitude
            .map_or(Latitude(NinetyDegreeInt(900_000_001)), |lat| {
                let val = lat.get::<tenth_of_microdegree>() as i32;
                Latitude(NinetyDegreeInt(val))
            });

        let longitude =
            self.longitude
                .map_or(Longitude(OneEightyDegreeInt(1_800_000_001)), |lon| {
                    let val = lon.get::<tenth_of_microdegree>() as i32;
                    Longitude(OneEightyDegreeInt(val))
                });

        let elevation = self.altitude.map_or(Elevation(Uint16(4095)), |alt| {
            // The 16-bit value is interpreted as an integer number of decimeters representing the height above a
            // minimum height of −409.5 m, with the maximum height being 6143.9 m.
            let val = (alt.get::<decimeter>().clamp(-4095.0, 61439.0) + 4095.0) as u16;
            Elevation(Uint16(val))
        });

        ThreeDLocation {
            latitude,
            longitude,
            elevation,
        }
    }
}

/// Motion category dimensions.
/// Describes the motion at a given position.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Motion {
    /// Speed value at the position.
    pub speed: Option<Speed>,
    /// Vertical speed value at the position.
    pub vertical_speed: Option<Speed>,
    /// Heading value at the position.
    pub heading: Option<Heading>,
}

impl Motion {
    #[cfg(feature = "asn1")]
    /// Return the speed as an [EtsiSpeedValue].
    pub fn speed_value(&self) -> EtsiSpeedValue {
        self.speed.map_or(EtsiSpeedValue(16383), |spd| {
            let val = spd.get::<centimeter_per_second>() as u16;
            EtsiSpeedValue(val.clamp(0, 16382))
        })
    }

    #[cfg(feature = "asn1")]
    /// Return the heading as an [EtsiHeadingValue].
    pub fn heading_value(&self) -> EtsiHeadingValue {
        self.heading.map_or(EtsiHeadingValue(3601), |axis| {
            let val = axis.get::<decidegree>() as u16;
            EtsiHeadingValue(val.clamp(0, 3599))
        })
    }
}

/// Confidence category dimensions.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Confidence {
    /// Confidence of the position.
    pub position: PositionConfidence,
    /// Confidence of the altitude.
    pub altitude: Option<Length>,
    /// Confidence of the speed.
    pub speed: Option<Speed>,
    /// Confidence of the heading.
    pub heading: Option<Heading>,
}

impl Confidence {
    #[cfg(feature = "asn1")]
    /// Return altitude confidence as a [EtsiAltitudeConfidence].
    pub fn altitude_confidence(&self) -> EtsiAltitudeConfidence {
        self.altitude
            .map_or(EtsiAltitudeConfidence::unavailable, |alt| {
                match alt.get::<meter>() {
                    val if val > 200.0 => EtsiAltitudeConfidence::outOfRange,
                    val if val > 100.0 => EtsiAltitudeConfidence::alt_200_00,
                    val if val > 50.0 => EtsiAltitudeConfidence::alt_100_00,
                    val if val > 20.0 => EtsiAltitudeConfidence::alt_050_00,
                    val if val > 10.0 => EtsiAltitudeConfidence::alt_020_00,
                    val if val > 5.0 => EtsiAltitudeConfidence::alt_010_00,
                    val if val > 2.0 => EtsiAltitudeConfidence::alt_005_00,
                    val if val > 1.0 => EtsiAltitudeConfidence::alt_002_00,
                    val if val > 0.5 => EtsiAltitudeConfidence::alt_001_00,
                    val if val > 0.2 => EtsiAltitudeConfidence::alt_000_50,
                    val if val > 0.1 => EtsiAltitudeConfidence::alt_000_20,
                    val if val > 0.05 => EtsiAltitudeConfidence::alt_000_10,
                    val if val > 0.02 => EtsiAltitudeConfidence::alt_000_05,
                    val if val > 0.01 => EtsiAltitudeConfidence::alt_000_02,
                    val if val >= 0.0 => EtsiAltitudeConfidence::alt_000_01,
                    _ => EtsiAltitudeConfidence::unavailable,
                }
            })
    }

    #[cfg(feature = "asn1")]
    /// Return the speed confidence as a [EtsiSpeedConfidence].
    pub fn speed_confidence(&self) -> EtsiSpeedConfidence {
        self.speed.map_or(EtsiSpeedConfidence(127), |spd| {
            let val = spd.get::<centimeter_per_second>() as u8;
            EtsiSpeedConfidence(val.clamp(1, 126))
        })
    }

    /// Return the heading confidence as an [EtsiHeadingConfidence].
    #[cfg(feature = "asn1")]
    pub fn heading_confidence(&self) -> EtsiHeadingConfidence {
        self.heading.map_or(EtsiHeadingConfidence(127), |hdg| {
            let val = hdg.get::<decidegree>() as u8;
            EtsiHeadingConfidence(val.clamp(1, 126))
        })
    }
}

/// Horizontal position confidence.
/// Describes the confidence ellipse of a `position`.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PositionConfidence {
    /// Semi major axis confidence.
    pub semi_major: Option<Length>,
    /// Semi minor axis confidence.
    pub semi_minor: Option<Length>,
    /// Semi major orientation confidence.
    pub semi_major_orientation: Option<Heading>,
}

impl PositionConfidence {
    #[cfg(feature = "asn1")]
    /// Return the semi major axis confidence as an [EtsiSemiAxisLength].
    pub fn semi_major_axis_length(&self) -> EtsiSemiAxisLength {
        self.semi_major.map_or(EtsiSemiAxisLength(4095), |axis| {
            let val = axis.get::<centimeter>() as u16;
            EtsiSemiAxisLength(val.clamp(1, 4094))
        })
    }

    #[cfg(feature = "asn1")]
    /// Return the semi major axis confidence as an [EtsiSemiAxisLength].
    pub fn semi_minor_axis_length(&self) -> EtsiSemiAxisLength {
        self.semi_minor.map_or(EtsiSemiAxisLength(4095), |axis| {
            let val = axis.get::<centimeter>() as u16;
            EtsiSemiAxisLength(val.clamp(1, 4094))
        })
    }

    #[cfg(feature = "asn1")]
    /// Return the semi major axis confidence as an [EtsiWgs84AngleValue].
    pub fn semi_minor_orientation_angle(&self) -> EtsiWgs84AngleValue {
        self.semi_major_orientation
            .map_or(EtsiWgs84AngleValue(3601), |axis| {
                let val = axis.get::<decidegree>() as u16;
                EtsiWgs84AngleValue(val.clamp(0, 3599))
            })
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Geographical point used in the [PathHistory] structure.
/// Used to describe a current or former position of the station.
pub struct PathPoint {
    /// Timestamp at which the coordinates were acquired.
    pub timestamp: TAI2004,
    /// Latitude of the point.
    pub latitude: Latitude,
    /// Longitude of the point.
    pub longitude: Longitude,
    /// Altitude of the point.
    pub altitude: Length,
    /// Heading at the point.
    pub heading: Heading,
    /// Speed at the point.
    pub speed: Speed,
}

impl PathPoint {
    /// Compute the distance between `self` and `other`. Does not use Haversine formula.
    /// Used formula is defined in C2C Consortium Vehicle C-ITS station profile, requirement RS_BSP_318.
    pub fn distance_to(&self, other: &PathPoint) -> Length {
        // pTraceEarthMeridian in C2C spec.
        let earth_meridian_radius = Length::new::<kilometer>(6378.137);

        (self.latitude.cos() * other.latitude.cos() * (self.longitude - other.longitude).cos()
            + self.latitude.sin() * other.latitude.sin())
        .acos()
            * earth_meridian_radius
    }
}

impl TryFrom<&Fix> for PathPoint {
    type Error = FixError;

    fn try_from(value: &Fix) -> Result<Self, Self::Error> {
        let lat = value.position.latitude.ok_or(FixError::NoLatitude)?;
        let lon = value.position.longitude.ok_or(FixError::NoLongitude)?;
        let alt = value.position.altitude.ok_or(FixError::NoAltitude)?;
        let hdg = value.motion.heading.ok_or(FixError::NoHeading)?;
        let spd = value.motion.speed.ok_or(FixError::NoSpeed)?;

        Ok(PathPoint {
            timestamp: value.timestamp,
            latitude: lat,
            longitude: lon,
            altitude: alt,
            heading: hdg,
            speed: spd,
        })
    }
}

/// Position history type.
/// First element is the current position.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PositionHistory(pub VecDeque<PathPoint>);

impl PositionHistory {
    /// Get the [PositionHistory] as an ETSI Path.
    #[cfg(feature = "asn1")]
    pub fn as_etsi_path(&self, fix: &Fix) -> Result<EtsiPath, FixError> {
        let mut base_time = fix.timestamp;
        let mut base_lat = fix.position.latitude.ok_or(FixError::NoLatitude)?;
        let mut base_lon = fix.position.longitude.ok_or(FixError::NoLongitude)?;
        let mut base_alt = fix.position.altitude.ok_or(FixError::NoAltitude)?;

        let mut path = SequenceOf::new();

        // Skip the first point, as it is the current position.
        for point in self.0.iter().skip(1) {
            let delta_lat = point.latitude.get::<tenth_of_microdegree>()
                - base_lat.get::<tenth_of_microdegree>();
            let delta_lon = point.longitude.get::<tenth_of_microdegree>()
                - base_lon.get::<tenth_of_microdegree>();
            let delta_alt = point.altitude.get::<centimeter>() - base_alt.get::<centimeter>();
            let delta_time = (base_time - point.timestamp)
                .clamp(Duration::from_millis(10), Duration::from_millis(655350));

            base_time = point.timestamp;
            base_lat = point.latitude;
            base_lon = point.longitude;
            base_alt = point.altitude;

            let path_point = EtsiPathPoint {
                path_position: DeltaReferencePosition {
                    delta_latitude: DeltaLatitude(delta_lat as i32),
                    delta_longitude: DeltaLongitude(delta_lon as i32),
                    delta_altitude: DeltaAltitude(delta_alt as i16),
                },
                path_delta_time: Some(PathDeltaTime(Integer::from(delta_time.total_millis() / 10))),
            };

            path.push(path_point);
        }

        Ok(EtsiPath(path))
    }
}

#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PathHistory {
    /// Vehicle path GNSS data points samples.
    samples: HistoryBuffer<PathPoint, 3>,
    /// Concise points, ie: history points.
    concise_points: PositionHistory,
}

impl PathHistory {
    /// Create a new [PathHistory].
    pub const fn new() -> Self {
        Self {
            samples: HistoryBuffer::new(),
            concise_points: PositionHistory(VecDeque::new()),
        }
    }

    /// Push a new [PathPoint] into the history.
    pub fn push_position(&mut self, position: PathPoint) {
        self.samples.write(position);

        // Insert the starting point in the concise points.
        if self.concise_points.0.is_empty() {
            self.concise_points.0.push_front(position);
        }

        self.update_concise_points().ok();
        self.trucate_concise_points();
    }

    /// Get a reference on the current [PathHistory] points.
    pub fn points(&self) -> &PositionHistory {
        &self.concise_points
    }

    fn update_concise_points(&mut self) -> Result<(), ()> {
        // Step 1: Check if we have enough samples.
        if self.samples.is_full() {
            // We have the required amount of samples.
            let starting = self.concise_points.0.front().ok_or(())?;
            let next = self.samples.recent().ok_or(())?;
            let previous = self.samples.oldest_ordered().nth(1).ok_or(())?;

            // Step 2: calculate the chord length between the starting point and the next point.
            let chord_length = starting.distance_to(&next);

            //  K_PH_CHORDLENGTHTHRESHOLD = pTraceMaxDeltaDistance = 22.5m
            let actual_error = if chord_length > Length::new::<meter>(22.5) {
                // pTraceAllowableError = K_PHALLOWABLEERROR_M = 0.47m
                Length::new::<meter>(0.47 + 1.0)
            } else {
                // Step 3: calculate the heading difference between the starting point and the next point.
                let delta_phi = next.heading - starting.heading;

                // Step 4: calculate the estimated radius of the curvature.
                // K_PHSMALLDELTAPHI_R = pTraceDeltaPhi = 1.0°
                let (_estimated_radius, actual_error) =
                    if delta_phi.abs() < Heading::new::<degree>(1.0) {
                        // estimated_radius = K_PH_MAXESTIMATEDRADIUS = REarthMeridian
                        (
                            Length::new::<kilometer>(6378.137),
                            Length::new::<meter>(0.0),
                        )
                    } else {
                        let estimated_radius = chord_length / (2.0 * (delta_phi / 2.0).cos());
                        // Step 5: calculate the distance d value.
                        let d = estimated_radius * (delta_phi / 2.0).cos();
                        // Step 6: calculate the actual maximum error.
                        let actual_error = estimated_radius - d;
                        (estimated_radius, actual_error)
                    };

                actual_error
            };

            // Step 7: add the previous point to the concise points.
            // K_PHALLOWABLEERROR_M = pTraceAllowableError = 0.47m
            if actual_error > Length::new::<meter>(0.47) {
                self.concise_points.0.push_front(*previous);
            }
        }

        Ok(())
    }

    fn trucate_concise_points(&mut self) {
        if self.concise_points.0.len() > 2 {
            let mut distance = Length::new::<meter>(0.0);
            let points: VecDeque<PathPoint> = self
                .concise_points
                .0
                .iter()
                .zip(self.concise_points.0.iter().skip(1))
                .take_while(|(p_prev, p_curr)| {
                    // K_PHDISTANCE_M = pCamTraceMinLength = 200m.
                    if distance >= Length::new::<meter>(200.0) {
                        return false;
                    } else {
                        distance += p_prev.distance_to(p_curr);
                        true
                    }
                })
                .map(|(_, p2)| *p2)
                .collect();

            self.concise_points = PositionHistory(points);
        }
    }
}
