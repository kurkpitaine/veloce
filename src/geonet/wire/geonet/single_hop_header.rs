use crate::geonet::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::long_position_vector::{Header as LPVBuf, Repr as LongPositionVector};

/// A read/write wrapper around a Geonetworking Single Hop Broadcast Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.8.3.2 for details about fields
mod field {
    use crate::geonet::wire::field::*;

    // 24-octet Source Position Vector of the Geonetworking Single Hop Broadcast Header.
    pub const SO_PV: Field = 0..24;
    // 2-octet Reserved field of the Geonetworking Single Hop Broadcast Header.
    pub const RESERVED: Field = 24..28;
}

// The Geonetworking Single Hop Broadcast Header length.
pub const HEADER_LEN: usize = field::RESERVED.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a Geonetworking Single Hop Broadcast Header structure.
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

    /// Clear the reserved field.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::RESERVED], 0);
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Single Hop Broadcast Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Single Hop Broadcast header.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Repr {
    /// The Source Position Vector contained inside the Single Hop Broadcast header.
    pub source_position_vector: LongPositionVector,
}

impl Repr {
    /// Parse a Single Hop Broadcast Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            source_position_vector: header.source_position_vector()?,
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Single Hop Broadcast Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<&mut T>) {
        header.set_source_position_vector(self.source_position_vector);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Single Hop Broadcast Header so_pv={}",
            self.source_position_vector
        )
    }
}

/* #[cfg(test)]
mod test {
    use super::*;
    use crate::geonet::types::*;
    use crate::geonet::wire::ethernet::Address as MacAddress;
    use crate::geonet::wire::geonet::{Address as GnAddress, StationType};

    static BYTES_HEADER: [u8; 28] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x60, 0x01, 0x7b, 0x0d, 0x4e, 0x80, 0x18, 0x0b, 0x2c, 0x00, 0x00, 0x00, 0x00,
    ];

    static BYTES_SO_PV: [u8; 24] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x60, 0x01, 0x7b, 0x0d, 0x4e, 0x80, 0x18, 0x0b, 0x2c,
    ];

    #[test]
    fn test_check_len() {
        assert_eq!(
            Err(Error::Truncated),
            Header::new_unchecked(&BYTES_HEADER[..HEADER_LEN - 1]).check_len()
        );

        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(
            header.source_position_vector(),
            LongPositionVector::from_bytes(&BYTES_SO_PV)
        );
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                source_position_vector: LongPositionVector::new(
                    GnAddress::new(
                        false,
                        StationType::RoadSideUnit,
                        MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])
                    ),
                    307970884,
                    Latitude::new::<tenth_of_microdegree>(487667533.0),
                    Longitude::new::<tenth_of_microdegree>(24841520.0),
                    true,
                    Speed::new::<centimeter_per_second>(24.0),
                    Heading::new::<decidegree>(2860.0),
                ),
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            source_position_vector: LongPositionVector::new(
                GnAddress::new(
                    false,
                    StationType::RoadSideUnit,
                    MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
                ),
                307970884,
                Latitude::new::<tenth_of_microdegree>(487667533.0),
                Longitude::new::<tenth_of_microdegree>(24841520.0),
                true,
                Speed::new::<centimeter_per_second>(24.0),
                Heading::new::<decidegree>(2860.0),
            ),
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
} */
