use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use crate::geonet::time::Instant;
use crate::geonet::types::*;
use crate::geonet::wire::geonet::Address as GnAddress;
use crate::geonet::{Error, Result};

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

    // 1-bit position accuracy indicator and 15-bit speed.
    pub const PAI_SPEED: Field = 20..22;

    // 16-bit heading.
    pub const HEADING: Field = 22..24;
}

// The Geonetworking Long Position Vector Header length.
pub const HEADER_LEN: usize = field::HEADING.end;

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

    /// Return the Position Accuracy Indicator flag.
    #[inline]
    pub fn position_accuracy_indicator(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        (raw & 0x8000) != 0
    }

    /// Return the Speed field.
    #[inline]
    pub fn speed(&self) -> Speed {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        Speed::new::<centimeter_per_second>((raw & !0x8000) as f32)
    }

    /// Return the Heading field.
    #[inline]
    pub fn heading(&self) -> Heading {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::HEADING]);
        Heading::new::<decidegree>(raw as f32)
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

    /// Set the Position Accuracy Indicator flag.
    #[inline]
    pub fn set_position_accuracy_indicator(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        let raw = if value { raw | 0x8000 } else { raw & !0x8000 };
        NetworkEndian::write_u16(&mut data[field::PAI_SPEED], raw);
    }

    /// Set the Speed field.
    #[inline]
    pub fn set_speed(&mut self, value: Speed) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        let raw = raw | ((value.get::<centimeter_per_second>() as u16) & !0x8000);
        NetworkEndian::write_u16(&mut data[field::PAI_SPEED], raw);
    }

    /// Set the Heading field.
    #[inline]
    pub fn set_heading(&mut self, value: Heading) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(
            &mut data[field::PAI_SPEED],
            value.get::<decidegree>() as u16,
        );
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Long Position Vector Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Long Position Vector header.
#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub struct Repr {
    /// The Geonetworking address contained inside the Long Position Vector header.
    pub address: GnAddress,
    /// The timestamp contained inside the Long Position Vector header.
    /// This is also the time at which this Long Position Vector was generated.
    pub timestamp: Instant,
    /// The latitude contained inside the Long Position Vector header.
    pub latitude: Latitude,
    /// The longitude contained inside the Long Position Vector header.
    pub longitude: Longitude,
    /// Position accuracy flag contained inside the Long Position Vector header.
    pub is_accurate: bool,
    /// The speed contained inside the Long Position Vector header.
    pub speed: Speed,
    /// The heading contained inside the Long Position Vector header.
    pub heading: Heading,
}

impl Repr {
    /// Parse a Long Position Vector Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&T>) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        header.check_len()?;
        Ok(Repr {
            address: header.address(),
            timestamp: Instant::from_millis(header.timestamp()),
            latitude: header.latitude(),
            longitude: header.longitude(),
            is_accurate: header.position_accuracy_indicator(),
            speed: header.speed(),
            heading: header.heading(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Long Position Vector Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        header.set_address(self.address);
        header.set_timestamp(self.timestamp.millis() as u32);
        header.set_latitude(self.latitude);
        header.set_longitude(self.longitude);
        header.set_position_accuracy_indicator(self.is_accurate);
        header.set_speed(self.speed);
        header.set_heading(self.heading);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Long Position Vector addr={} tst={}s lat={}° lon={}° is accurate={} speed={:.01}km/h heading={:.01}°",
            self.address,
            self.timestamp,
            self.latitude.get::<degree>(),
            self.longitude.get::<degree>(),
            self.is_accurate,
            self.speed.get::<kilometer_per_hour>(),
            self.heading.get::<degree>(),
        )
    }
}

/* #[cfg(test)]
mod test {
    use super::*;
    use crate::geonet::wire::ethernet::Address as MacAddress;
    use crate::geonet::wire::geonet::{Address as GnAddress, StationType};

    static BYTES_LPV: [u8; 24] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x60, 0x01, 0x7b, 0x0d, 0x4e, 0x80, 0x18, 0x0b, 0x2c,
    ];

    static BYTES_SPV: [u8; 20] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x60, 0x01, 0x7b, 0x0d, 0x4e,
    ];

    #[test]
    fn test_lpv_new() {
        let lpv = LongVector::new(
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
        );

        assert_eq!(lpv.as_bytes(), &BYTES_LPV);
    }

    #[test]
    fn test_spv_new() {
        let spv = ShortVector::new(
            GnAddress::new(
                false,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
            ),
            307970884,
            Latitude::new::<tenth_of_microdegree>(487667533.0),
            Longitude::new::<tenth_of_microdegree>(24841520.0),
        );

        assert_eq!(spv.as_bytes(), &BYTES_SPV);
    }

    #[test]
    fn test_lpv_from_bytes() {
        let lpv = LongVector::from_bytes(&BYTES_LPV);
        assert_eq!(
            lpv.address(),
            GnAddress::new(
                false,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])
            )
        );
        assert_eq!(lpv.timestamp(), 307970884);
        assert_eq!(lpv.latitude().get::<tenth_of_microdegree>(), 487667533.0);
        assert_eq!(lpv.longitude().get::<tenth_of_microdegree>(), 24841520.0);
        assert_eq!(lpv.is_accurate(), true);
        assert_eq!(lpv.speed(), Speed::new::<centimeter_per_second>(24.0));
        assert_eq!(lpv.heading(), Heading::new::<decidegree>(2860.0));
    }

    #[test]
    fn test_spv_from_bytes() {
        let spv = ShortVector::from_bytes(&BYTES_SPV);
        assert_eq!(
            spv.address(),
            GnAddress::new(
                false,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])
            )
        );
        assert_eq!(spv.timestamp(), 307970884);
        assert_eq!(spv.latitude().get::<tenth_of_microdegree>(), 487667533.0);
        assert_eq!(spv.longitude().get::<tenth_of_microdegree>(), 24841520.0);
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_lpv_from_bytes_too_long() {
        let _ = LongVector::from_bytes(&[0u8; 25]);
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_spv_from_bytes_too_long() {
        let _ = ShortVector::from_bytes(&[0u8; 21]);
    }
} */
