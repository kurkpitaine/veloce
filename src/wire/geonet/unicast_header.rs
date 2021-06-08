use crate::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::position_vector::{
    LongVector as LongPositionVector, ShortVector as ShortPositionVector,
};
use super::SeqNumber;

/// A read/write wrapper around a Geonetworking Unicast Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.8.2.2 for details about fields
mod field {
    use crate::wire::field::*;

    // 2-octet Sequence Number of the Geonetworking Unicast Header.
    pub const SEQ_NUM: Field = 0..2;
    // 2-octet Reserved field of the Geonetworking Unicast Header.
    pub const RESERVED: Field = 2..4;
    // 24-octet Source Position Vector of the Geonetworking Unicast Header.
    pub const SO_PV: Field = 4..28;
    // 20-octet Destination Position Vector of the Geonetworking Unicast Header.
    pub const DE_PV: Field = 28..48;
}

// The Geonetworking Unicast Header length.
pub const HEADER_LEN: usize = field::DE_PV.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a Geonetworking Unicast Header structure.
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

    /// Return the destination position vector.
    #[inline]
    pub fn destination_position_vector(&self) -> ShortPositionVector {
        let data = self.buffer.as_ref();
        ShortPositionVector::from_bytes(&data[field::DE_PV])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the sequence number.
    #[inline]
    pub fn set_sequence_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::SEQ_NUM], value.0);
    }

    /// Clear the reserved field.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::RESERVED], 0);
    }

    /// Set the source position vector field.
    #[inline]
    pub fn set_source_position_vector(&mut self, value: LongPositionVector) {
        let data = self.buffer.as_mut();
        data[field::SO_PV].copy_from_slice(value.as_bytes());
    }

    /// Set the destination position vector field.
    #[inline]
    pub fn set_destination_position_vector(&mut self, value: ShortPositionVector) {
        let data = self.buffer.as_mut();
        data[field::DE_PV].copy_from_slice(value.as_bytes());
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Unicast Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Unicast header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The Sequence number contained inside the Unicast header.
    pub sequence_number: SeqNumber,
    /// The Source Position Vector contained inside the Unicast header.
    pub source_position_vector: LongPositionVector,
    /// The Destination Position Vector contained inside the Unicast header.
    pub destination_position_vector: ShortPositionVector,
}

impl Repr {
    /// Parse a Unicast Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            sequence_number: header.sequence_number(),
            source_position_vector: header.source_position_vector(),
            destination_position_vector: header.destination_position_vector(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Unicast Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<&mut T>) {
        header.set_sequence_number(self.sequence_number);
        header.set_source_position_vector(self.source_position_vector);
        header.set_destination_position_vector(self.destination_position_vector);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Unicast Header sn={} so_pv={} de_pv={}",
            self.sequence_number, self.source_position_vector, self.destination_position_vector
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::ethernet::Address as MacAddress;
    use crate::wire::geonet::{Address as GnAddress, StationType};

    static BYTES_HEADER: [u8; 48] = [
        0x09, 0x29, 0x00, 0x00, 0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43,
        0x44, 0x1d, 0x11, 0x37, 0x4d, 0x01, 0x7b, 0x0d, 0x4e, 0x80, 0x18, 0x0b, 0x2c, 0x14, 0x00,
        0x16, 0x33, 0x12, 0x28, 0x26, 0x45, 0x21, 0xf2, 0x41, 0x39, 0x01, 0xa4, 0xa9, 0xaf, 0x1d,
        0x0f, 0xa0, 0x22,
    ];

    static BYTES_SO_PV: [u8; 24] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x4d, 0x01, 0x7b, 0x0d, 0x4e, 0x80, 0x18, 0x0b, 0x2c,
    ];
    static BYTES_DE_PV: [u8; 20] = [
        0x14, 0x00, 0x16, 0x33, 0x12, 0x28, 0x26, 0x45, 0x21, 0xf2, 0x41, 0x39, 0x01, 0xa4, 0xa9,
        0xaf, 0x1d, 0x0f, 0xa0, 0x22,
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
        assert_eq!(header.sequence_number(), SeqNumber(2345));
        assert_eq!(
            header.source_position_vector(),
            LongPositionVector::from_bytes(&BYTES_SO_PV)
        );
        assert_eq!(
            header.destination_position_vector(),
            ShortPositionVector::from_bytes(&BYTES_DE_PV)
        );
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                sequence_number: SeqNumber(2345),
                source_position_vector: LongPositionVector::new(
                    GnAddress::new(
                        false,
                        StationType::RoadSideUnit,
                        MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])
                    ),
                    307970884,
                    487667533,
                    24841550,
                    true,
                    24,
                    2860,
                ),
                destination_position_vector: ShortPositionVector::new(
                    GnAddress::new(
                        false,
                        StationType::PassengerCar,
                        MacAddress([0x16, 0x33, 0x12, 0x28, 0x26, 0x45])
                    ),
                    569524537,
                    27568559,
                    487563298,
                ),
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            sequence_number: SeqNumber(2345),
            source_position_vector: LongPositionVector::new(
                GnAddress::new(
                    false,
                    StationType::RoadSideUnit,
                    MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
                ),
                307970884,
                487667533,
                24841550,
                true,
                24,
                2860,
            ),
            destination_position_vector: ShortPositionVector::new(
                GnAddress::new(
                    false,
                    StationType::PassengerCar,
                    MacAddress([0x16, 0x33, 0x12, 0x28, 0x26, 0x45]),
                ),
                569524537,
                27568559,
                487563298,
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
}
