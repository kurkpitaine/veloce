use crate::types::{Angle, Distance, Latitude, Longitude};
use crate::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;
use std::ops::Deref;

use self::field::LATITUDE;

use super::position_vector::LongVector as LongPositionVector;
use super::SeqNumber;

/// A read/write wrapper around a Geonetworking Anycast/Broadcast Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.8.5.2 for details about fields
mod field {
    use crate::wire::field::*;

    // 2-octet Sequence Number of the Geonetworking Anycast/Broadcast Header.
    pub const SEQ_NUM: Field = 0..2;
    // 2-octet Reserved field of the Geonetworking Anycast/Broadcast Header.
    pub const RESERVED_1: Field = 2..4;
    // 24-octet Source Position Vector of the Geonetworking Anycast/Broadcast Header.
    pub const SO_PV: Field = 4..28;
    // 4-octet geo-area Latitude of the Geonetworking Anycast/Broadcast Header.
    pub const LATITUDE: Field = 28..32;
    // 4-octet geo-area Longitude of the Geonetworking Anycast/Broadcast Header.
    pub const LONGITUDE: Field = 32..36;
    // 2-octet geo-area Distance A of the Geonetworking Anycast/Broadcast Header.
    pub const DISTANCE_A: Field = 36..38;
    // 2-octet geo-area Distance B of the Geonetworking Anycast/Broadcast Header.
    pub const DISTANCE_B: Field = 38..40;
    // 2-octet geo-area Angle of the Geonetworking Anycast/Broadcast Header.
    pub const ANGLE: Field = 40..42;
    // 2-octet Reserved field of the Geonetworking Anycast/Broadcast Header.
    pub const RESERVED_2: Field = 42..44;
}

// The Geonetworking Anycast/Broadcast Header length.
pub const HEADER_LEN: usize = field::RESERVED_2.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a Geonetworking Anycast/Broadcast Header structure.
    pub fn new_unchecked(buffer: T) -> Header<T> {
        Header { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < HEADER_LEN {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the sequence number.
    #[inline]
    pub fn sequence_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(NetworkEndian::read_u16(&data[field::SEQ_NUM]))
    }

    /// Return the source position vector.
    #[inline]
    pub fn source_position_vector(&self) -> LongPositionVector {
        let data = self.buffer.as_ref();
        LongPositionVector::from_bytes(&data[field::SO_PV])
    }

    /// Return the geo-area latitude.
    #[inline]
    pub fn latitude(&self) -> Latitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::LATITUDE]);
        Latitude::new_unchecked(raw)
    }

    /// Return the geo-area longitude.
    #[inline]
    pub fn longitude(&self) -> Longitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::LONGITUDE]);
        Longitude::new_unchecked(raw)
    }

    /// Return the geo-area distance A.
    #[inline]
    pub fn distance_a(&self) -> Distance {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::DISTANCE_A]);
        Distance::new(raw)
    }

    /// Return the geo-area distance B.
    #[inline]
    pub fn distance_b(&self) -> Distance {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::DISTANCE_B]);
        Distance::new(raw)
    }

    /// Return the geo-area angle.
    #[inline]
    pub fn angle(&self) -> Angle {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::ANGLE]);
        Angle::new(raw)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the sequence number.
    #[inline]
    pub fn set_sequence_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::SEQ_NUM], value.0);
    }

    /// Clear the reserved fields.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::RESERVED_1], 0);
        NetworkEndian::write_u16(&mut data[field::RESERVED_2], 0);
    }

    /// Set the source position vector field.
    #[inline]
    pub fn set_source_position_vector(&mut self, value: LongPositionVector) {
        let data = self.buffer.as_mut();
        data[field::SO_PV].copy_from_slice(value.as_bytes());
    }

    /// Set the geo-area latitude.
    #[inline]
    pub fn set_latitude(&mut self, value: Latitude) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(
            &mut data[field::LATITUDE],
            value.as_tenth_of_microdegrees_i32(),
        );
    }

    /// Set the geo-area longitude.
    #[inline]
    pub fn set_longitude(&mut self, value: Longitude) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(
            &mut data[field::LONGITUDE],
            value.as_tenth_of_microdegrees_i32(),
        );
    }

    /// Set the geo-area distance A
    #[inline]
    pub fn set_distance_a(&mut self, value: Distance) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DISTANCE_A], value.as_meters_u16());
    }

    /// Set the geo-area distance B
    #[inline]
    pub fn set_distance_b(&mut self, value: Distance) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DISTANCE_B], value.as_meters_u16());
    }
    /// Set the geo-area angle
    #[inline]
    pub fn set_angle(&mut self, value: Angle) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ANGLE], value.as_degrees_u16());
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Anycast/Broadcast Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Anycast/Broadcast header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The Sequence number contained inside the Anycast/Broadcast header.
    pub sequence_number: SeqNumber,
    /// The Source Position Vector contained inside the Anycast/Broadcast header.
    pub source_position_vector: LongPositionVector,
    /// The geo-area latitude contained inside the Anycast/Broadcast header.
    pub latitude: Latitude,
    /// The geo-area longitude contained inside the Anycast/Broadcast header.
    pub longitude: Longitude,
    /// The geo-area distance A contained inside the Anycast/Broadcast header.
    pub distance_a: Distance,
    /// The geo-area distance B contained inside the Anycast/Broadcast header.
    pub distance_b: Distance,
    /// The geo-area angle contained inside the Anycast/Broadcast header.
    pub angle: Angle,
}

impl Repr {
    /// Parse a Anycast/Broadcast Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            sequence_number: header.sequence_number(),
            source_position_vector: header.source_position_vector(),
            latitude: header.latitude(),
            longitude: header.longitude(),
            distance_a: header.distance_a(),
            distance_b: header.distance_b(),
            angle: header.angle(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Anycast/Broadcast Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<&mut T>) {
        header.set_sequence_number(self.sequence_number);
        header.set_source_position_vector(self.source_position_vector);
        header.set_latitude(self.latitude);
        header.set_longitude(self.longitude);
        header.set_distance_a(self.distance_a);
        header.set_distance_b(self.distance_b);
        header.set_angle(self.angle);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Anycast/Broadcast Header sn={} so_pv={} lat={} lon={} dist_a={} dist_b={} angle={}",
            self.sequence_number,
            self.source_position_vector,
            self.latitude,
            self.longitude,
            self.distance_a,
            self.distance_b,
            self.angle
        )
    }
}
