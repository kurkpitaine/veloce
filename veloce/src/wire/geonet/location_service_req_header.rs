use crate::wire::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::long_position_vector::{Header as LPVBuf, Repr as LongPositionVector};
use super::Address as GnAddress;
use super::SequenceNumber;

/// A read/write wrapper around a Geonetworking Location Service Request Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.8.7 for details about fields.
mod field {
    use crate::wire::field::*;

    // 2-octet Sequence Number of the Geonetworking Location Service Request Header.
    pub const SEQ_NUM: Field = 0..2;
    // 2-octet Reserved field of the Geonetworking Location Service Request Header.
    pub const RESERVED: Field = 2..4;
    // 24-octet Source Position Vector of the Geonetworking Location Service Request Header.
    pub const SO_PV: Field = 4..28;
    // 8-octet Request Geonet Address of the Geonetworking Location Service Request Header.
    pub const REQ_ADDR: Field = 28..36;
}

// The Geonetworking Location Service Request Header length.
pub const HEADER_LEN: usize = field::REQ_ADDR.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a Geonetworking Location Service Request Header structure.
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

    /// Return the sequence number.
    #[inline]
    pub fn sequence_number(&self) -> SequenceNumber {
        let data = self.buffer.as_ref();
        SequenceNumber(NetworkEndian::read_u16(&data[field::SEQ_NUM]))
    }

    /// Return the source position vector.
    #[inline]
    pub fn source_position_vector(&self) -> Result<LongPositionVector> {
        let data = self.buffer.as_ref();
        let spv_buf = LPVBuf::new_unchecked(&data[field::SO_PV]);
        LongPositionVector::parse(&spv_buf)
    }

    /// Return the request Geonetworking address.
    #[inline]
    pub fn request_address(&self) -> GnAddress {
        let data = self.buffer.as_ref();
        GnAddress::from_bytes(&data[field::REQ_ADDR])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the sequence number.
    #[inline]
    pub fn set_sequence_number(&mut self, value: SequenceNumber) {
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
        let mut spv_buf = LPVBuf::new_unchecked(&mut data[field::SO_PV]);
        value.emit(&mut spv_buf);
    }

    /// Set the request Geonetworking address field.
    #[inline]
    pub fn set_request_address(&mut self, value: GnAddress) {
        let data = self.buffer.as_mut();
        data[field::REQ_ADDR].copy_from_slice(value.as_bytes());
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "LS Request Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Location Service Request header.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Repr {
    /// The Sequence number contained inside the Location Service Request header.
    pub sequence_number: SequenceNumber,
    /// The Source Position Vector contained inside the Location Service Request header.
    pub source_position_vector: LongPositionVector,
    /// The Destination Position Vector contained inside the Location Service Request header.
    pub request_address: GnAddress,
}

impl Repr {
    /// Parse a Location Service Request Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            sequence_number: header.sequence_number(),
            source_position_vector: header.source_position_vector()?,
            request_address: header.request_address(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Location Service Request Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_sequence_number(self.sequence_number);
        header.set_source_position_vector(self.source_position_vector);
        header.set_request_address(self.request_address);
    }

    /// Returns the source Geonetworking address contained inside the
    /// source position vector of the Location Service header.
    pub const fn src_addr(&self) -> GnAddress {
        self.source_position_vector.address
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LS Request Header sn={} so_pv={} req_addr={}",
            self.sequence_number, self.source_position_vector, self.request_address
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::*;
    use crate::wire::ethernet::Address as MacAddress;
    use crate::wire::geonet::{Address as GnAddress, PositionVectorTimestamp, StationType};

    static BYTES_HEADER: [u8; 36] = [
        0x09, 0x29, 0x00, 0x00, 0xbc, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x00, 0x00, 0x00,
        0x78, 0x1c, 0xc6, 0x66, 0x60, 0xfd, 0xe2, 0x03, 0xd4, 0x80, 0x18, 0x0b, 0x2c, 0x14, 0x00,
        0x16, 0x33, 0x12, 0x28, 0x26, 0x45,
    ];

    static BYTES_REQ_ADDR: [u8; 8] = [0x14, 0x00, 0x16, 0x33, 0x12, 0x28, 0x26, 0x45];

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
            Header::new_unchecked(&BYTES_HEADER[..HEADER_LEN - 1]).check_len()
        );

        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(header.sequence_number(), SequenceNumber(2345));
        assert_eq!(header.source_position_vector().unwrap(), lpv_repr());
        assert_eq!(
            header.request_address(),
            GnAddress::from_bytes(&BYTES_REQ_ADDR)
        );
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                sequence_number: SequenceNumber(2345),
                source_position_vector: lpv_repr(),
                request_address: GnAddress::new(
                    false,
                    StationType::PassengerCar,
                    MacAddress([0x16, 0x33, 0x12, 0x28, 0x26, 0x45])
                ),
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            sequence_number: SequenceNumber(2345),
            source_position_vector: lpv_repr(),
            request_address: GnAddress::new(
                false,
                StationType::PassengerCar,
                MacAddress([0x16, 0x33, 0x12, 0x28, 0x26, 0x45]),
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
