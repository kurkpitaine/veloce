use crate::wire::{Error, Result};
use core::fmt;

use super::{long_position_vector::{Header as LPVBuf, Repr as LongPositionVector}, Address};

/// A read/write wrapper around a Geonetworking Beacon Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.8.6.2 for details about fields
mod field {
    use crate::wire::field::*;

    // 24-octet Source Position Vector of the Geonetworking Beacon Header.
    pub const SO_PV: Field = 0..24;
}

// The Geonetworking Beacon Header length.
pub const HEADER_LEN: usize = field::SO_PV.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a Geonetworking Beacon Header structure.
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
    /// Returns `Err(Error)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < HEADER_LEN {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the source position vector.
    #[inline]
    pub fn source_position_vector(&self) -> Result<LongPositionVector> {
        let data = self.buffer.as_ref();
        let spv_buf = LPVBuf::new_unchecked(&data[field::SO_PV]);
        LongPositionVector::parse(&spv_buf)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the source position vector field.
    #[inline]
    pub fn set_source_position_vector(&mut self, value: LongPositionVector) {
        let data = self.buffer.as_mut();
        let mut spv_buf = LPVBuf::new_unchecked(&mut data[field::SO_PV]);
        value.emit(&mut spv_buf);
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Beacon Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Beacon header.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    /// The Source Position Vector contained inside the Beacon header.
    pub source_position_vector: LongPositionVector,
}

impl Repr {
    /// Parse a Beacon Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            source_position_vector: header.source_position_vector()?,
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Beacon Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_source_position_vector(self.source_position_vector);
    }

    /// Returns the source Geonetworking address contained inside the
    /// source position vector of the Beacon header.
    pub const fn src_addr(&self) -> Address {
        self.source_position_vector.address
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Beacon Header so_pv={}", self.source_position_vector)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::*;
    use crate::wire::ethernet::Address as MacAddress;
    use crate::wire::geonet::{Address as GnAddress, StationType, PositionVectorTimestamp};

    static BYTES_HEADER: [u8; 24] = [
        0xbc, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x00, 0x00, 0x00, 0x78, 0x1c, 0xc6, 0x66,
        0x60, 0xfd, 0xe2, 0x03, 0xd4, 0x80, 0x18, 0x0b, 0x2c,
    ];

    fn lpv_repr() -> LongPositionVector {
        LongPositionVector {
            address: GnAddress::new(
                true,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
            ),
            timestamp: PositionVectorTimestamp(120),
            latitude: Latitude::new::<tenth_of_microdegree>(482764384.0),
            longitude: Longitude::new::<tenth_of_microdegree>(-35519532.0),
            is_accurate: true,
            speed: Speed::new::<centimeter_per_second>(24.0),
            heading: Heading::new::<decidegree>(2860.0),
        }
    }

    #[test]
    fn test_check_len() {
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_HEADER[..23]).check_len()
        );

        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(header.source_position_vector().unwrap(), lpv_repr());
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                source_position_vector: lpv_repr()
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            source_position_vector: lpv_repr(),
        };
        let mut bytes = [0u8; HEADER_LEN];
        let mut long = Header::new_unchecked(&mut bytes);
        repr.emit(&mut long);
        assert_eq!(long.into_inner(), &BYTES_HEADER);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_HEADER.len());
    }
}
