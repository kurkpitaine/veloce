use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use crate::geonet::types::*;
use crate::geonet::wire::geonet::Address as GnAddress;
use crate::geonet::wire::LongPositionVectorRepr;
use crate::geonet::wire::{Error, Result};

use super::PositionVectorTimestamp;

/// A read/write wrapper around a Long/Short Position Vector Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.5 for details about fields
mod field {
    use crate::geonet::wire::field::*;
    // Geonetworking address
    pub const GN_ADDR: Field = 0..8;

    // 32-bit timestamp at which the latitude / longitude were acquired.
    pub const TIMESTAMP: Field = 8..12;

    // 32-bit latitude.
    pub const LATITUDE: Field = 12..16;

    // 32-bit longitude.
    pub const LONGITUDE: Field = 16..20;
}

// The Geonetworking Short Position Vector Header length.
pub const HEADER_LEN: usize = field::LONGITUDE.end;

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

    /// Return the Address field.
    #[inline]
    pub fn address(&self) -> GnAddress {
        let data = self.buffer.as_ref();
        GnAddress::from_bytes(&data[field::GN_ADDR])
    }

    /// Return the Timestamp field.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::TIMESTAMP])
    }

    /// Return the Latitude field.
    #[inline]
    pub fn latitude(&self) -> Latitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::LATITUDE]);
        Latitude::new::<tenth_of_microdegree>(raw as f32)
    }

    /// Return the Longitude field.
    #[inline]
    pub fn longitude(&self) -> Longitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::LONGITUDE]);
        Longitude::new::<tenth_of_microdegree>(raw as f32)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the Address field.
    #[inline]
    pub fn set_address(&mut self, value: GnAddress) {
        let data = self.buffer.as_mut();
        data[field::GN_ADDR].copy_from_slice(value.as_bytes());
    }

    /// Set the Timestamp field.
    #[inline]
    pub fn set_timestamp(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::TIMESTAMP], value);
    }

    /// Set the Latitude field.
    #[inline]
    pub fn set_latitude(&mut self, value: Latitude) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(
            &mut data[field::LATITUDE],
            value.get::<tenth_of_microdegree>() as i32,
        );
    }

    /// Set the Longitude field.
    #[inline]
    pub fn set_longitude(&mut self, value: Longitude) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(
            &mut data[field::LONGITUDE],
            value.get::<tenth_of_microdegree>() as i32,
        );
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Short Position Vector Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Short Position Vector header.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Repr {
    /// The Geonetworking address contained inside the Short Position Vector header.
    pub address: GnAddress,
    /// The timestamp contained inside the Short Position Vector header.
    pub timestamp: PositionVectorTimestamp,
    /// The latitude contained inside the Short Position Vector header.
    pub latitude: Latitude,
    /// The longitude contained inside the Short Position Vector header.
    pub longitude: Longitude,
}

impl Repr {
    /// Parse a Short Position Vector Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            address: header.address(),
            timestamp: PositionVectorTimestamp(header.timestamp()),
            latitude: header.latitude(),
            longitude: header.longitude(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Short Position Vector Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_address(self.address);
        header.set_timestamp(self.timestamp.0);
        header.set_latitude(self.latitude);
        header.set_longitude(self.longitude);
    }
}

impl From<LongPositionVectorRepr> for Repr {
    fn from(value: LongPositionVectorRepr) -> Self {
        Repr {
            address: value.address,
            timestamp: value.timestamp,
            latitude: value.latitude,
            longitude: value.longitude,
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Short Position Vector addr={} tst={}ms lat={}° lon={}°",
            self.address,
            self.timestamp.0,
            self.latitude.get::<degree>(),
            self.longitude.get::<degree>(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::geonet::wire::ethernet::Address as MacAddress;
    use crate::geonet::wire::geonet::{Address as GnAddress, StationType};

    static BYTES_SPV: [u8; 20] = [
        0xbc, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x00, 0x00, 0x00, 0x78, 0x1c, 0xc6, 0x66,
        0x60, 0xfd, 0xe2, 0x03, 0xd4,
    ];

    #[test]
    fn test_check_len() {
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_SPV[..2]).check_len()
        );

        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_SPV).check_len());
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_SPV);
        assert_eq!(
            header.address(),
            GnAddress::new(
                true,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
            )
        );
        assert_eq!(header.timestamp(), 120);
        assert_eq!(
            header.latitude(),
            Latitude::new::<tenth_of_microdegree>(482764384.0)
        );
        assert_eq!(
            header.longitude(),
            Longitude::new::<tenth_of_microdegree>(-35519532.0)
        );
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_SPV);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                address: GnAddress::new(
                    true,
                    StationType::RoadSideUnit,
                    MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
                ),
                timestamp: PositionVectorTimestamp(120),
                latitude: Latitude::new::<tenth_of_microdegree>(482764384.0),
                longitude: Longitude::new::<tenth_of_microdegree>(-35519532.0),
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            address: GnAddress::new(
                true,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
            ),
            timestamp: PositionVectorTimestamp(120),
            latitude: Latitude::new::<tenth_of_microdegree>(482764384.0),
            longitude: Longitude::new::<tenth_of_microdegree>(-35519532.0),
        };

        let mut bytes = [0u8; 20];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);

        assert_eq!(header.into_inner(), &BYTES_SPV);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&BYTES_SPV);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_SPV.len());
    }
}
