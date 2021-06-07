use crate::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::Address;

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.5 for details about fields
mod field {
    use crate::wire::field::*;
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

/// A read/write wrapper around a Geonetworking Long Position Vector.
#[derive(Debug, PartialEq)]
pub struct Long<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Long<T> {
    /// Create a raw octet buffer with a Geonetworking Long Position Vector structure.
    pub fn new_unchecked(buffer: T) -> Long<T> {
        Long { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Long<T>> {
        let lpv = Self::new_unchecked(buffer);
        lpv.check_len()?;
        Ok(lpv)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::HEADING.end {
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
    pub fn address(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::GN_ADDR])
    }

    /// Return the Timestamp field.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::TIMESTAMP])
    }

    /// Return the Latitude field.
    #[inline]
    pub fn latitude(&self) -> i32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_i32(&data[field::LATITUDE])
    }

    /// Return the Latitude field.
    #[inline]
    pub fn longitude(&self) -> i32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_i32(&data[field::LONGITUDE])
    }

    /// Return the Position Accuracy Indicator field.
    #[inline]
    pub fn position_accuracy_indicator(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        (raw & 0x8000) != 0
    }

    /// Return the Speed field.
    #[inline]
    pub fn speed(&self) -> i16 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        (raw & !0x8000) as i16
    }

    /// Return the Heading field.
    #[inline]
    pub fn heading(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::HEADING])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Long<T> {
    /// Set the Address field.
    #[inline]
    pub fn set_address(&mut self, value: Address) {
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
    pub fn set_latitude(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::LATITUDE], value);
    }

    /// Set the Latitude field.
    #[inline]
    pub fn set_longitude(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::LONGITUDE], value);
    }

    /// Set the Position Accuracy Indicator field.
    #[inline]
    pub fn set_position_accuracy_indicator(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        let raw = if value { raw | 0x8000 } else { raw & !0x8000 };
        NetworkEndian::write_u16(&mut data[field::PAI_SPEED], raw);
    }

    /// Set the Speed field.
    #[inline]
    pub fn set_speed(&mut self, value: i16) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::PAI_SPEED]);
        let raw = raw | (value as u16 & !0x8000);
        NetworkEndian::write_i16(&mut data[field::PAI_SPEED], raw as i16);
    }

    /// Set the Heading field.
    #[inline]
    pub fn set_heading(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::HEADING], value);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Long<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match LongRepr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Long Position Vector ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Geonetworking Long Position Vector.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct LongRepr {
    /// The Geonetworking address of the station.
    pub address: Address,
    /// The timestamp at which the latitude/longitude were acquired by the station.
    pub timestamp: u32,
    /// The latitude of the station.
    pub latitude: i32,
    /// The longitude of the station.
    pub longitude: i32,
    /// The position accuracy indicator.
    pub position_accuracy_indicator: bool,
    /// The speed of the station.
    pub speed: i16,
    /// The heading of the station.
    pub heading: u16,
}

impl LongRepr {
    /// Parse a Geonetworking Long Position Vector and return a high-level representation.
    pub fn parse<T>(lpv: &Long<&T>) -> Result<LongRepr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(LongRepr {
            address: lpv.address(),
            timestamp: lpv.timestamp(),
            latitude: lpv.latitude(),
            longitude: lpv.longitude(),
            position_accuracy_indicator: lpv.position_accuracy_indicator(),
            speed: lpv.speed(),
            heading: lpv.heading(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        field::HEADING.end
    }

    /// Emit a high-level representation into a Geonetworking Long Position Vector.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, lpv: &mut Long<&mut T>) {
        lpv.set_address(self.address);
        lpv.set_timestamp(self.timestamp);
        lpv.set_latitude(self.latitude);
        lpv.set_longitude(self.longitude);
        lpv.set_position_accuracy_indicator(self.position_accuracy_indicator);
        lpv.set_speed(self.speed);
        lpv.set_heading(self.heading);
    }
}

impl<'a> fmt::Display for LongRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Long Position Vector gn_addr={} tst={} lat={} lon={} pai={} spd={} hdg={}",
            self.address,
            self.timestamp,
            self.latitude,
            self.longitude,
            self.position_accuracy_indicator,
            self.speed,
            self.heading,
        )
    }
}

/// A read/write wrapper around a Geonetworking Short Position Vector.
#[derive(Debug, PartialEq)]
pub struct Short<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Short<T> {
    /// Create a raw octet buffer with a Geonetworking Short Position Vector structure.
    pub fn new_unchecked(buffer: T) -> Short<T> {
        Short { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Short<T>> {
        let lpv = Self::new_unchecked(buffer);
        lpv.check_len()?;
        Ok(lpv)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::LONGITUDE.end {
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
    pub fn address(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::GN_ADDR])
    }

    /// Return the Timestamp field.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::TIMESTAMP])
    }

    /// Return the Latitude field.
    #[inline]
    pub fn latitude(&self) -> i32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_i32(&data[field::LATITUDE])
    }

    /// Return the Latitude field.
    #[inline]
    pub fn longitude(&self) -> i32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_i32(&data[field::LONGITUDE])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Short<T> {
    /// Set the Address field.
    #[inline]
    pub fn set_address(&mut self, value: Address) {
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
    pub fn set_latitude(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::LATITUDE], value);
    }

    /// Set the Latitude field.
    #[inline]
    pub fn set_longitude(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::LONGITUDE], value);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Short<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match ShortRepr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Short Position Vector ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Geonetworking Short Position Vector.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ShortRepr {
    /// The Geonetworking address of the station.
    pub address: Address,
    /// The timestamp at which the latitude/longitude were acquired by the station.
    pub timestamp: u32,
    /// The latitude of the station.
    pub latitude: i32,
    /// The longitude of the station.
    pub longitude: i32,
}

impl ShortRepr {
    /// Parse a Geonetworking Short Position Vector and return a high-level representation.
    pub fn parse<T>(lpv: &Short<&T>) -> Result<ShortRepr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(ShortRepr {
            address: lpv.address(),
            timestamp: lpv.timestamp(),
            latitude: lpv.latitude(),
            longitude: lpv.longitude(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        field::LONGITUDE.end
    }

    /// Emit a high-level representation into a Geonetworking Short Position Vector.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, spv: &mut Short<&mut T>) {
        spv.set_address(self.address);
        spv.set_timestamp(self.timestamp);
        spv.set_latitude(self.latitude);
        spv.set_longitude(self.longitude);
    }
}

impl<'a> fmt::Display for ShortRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Short Position Vector gn_addr={} tst={} lat={} lon={}",
            self.address, self.timestamp, self.latitude, self.longitude,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::geonet::{Address, StationType};
    use crate::wire::ethernet::Address as MacAddress;

    static BYTES_LPV: [u8; 24] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x4d, 0x01, 0x7b, 0x0d, 0x4e, 0x80, 0x18, 0x0b, 0x2c,
    ];

    static BYTES_SPV: [u8; 20] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x4d, 0x01, 0x7b, 0x0d, 0x4e,
    ];

    #[test]
    fn test_long_check_len() {
        assert_eq!(
            Err(Error::Truncated),
            Long::new_unchecked(&BYTES_LPV[..23]).check_len()
        );

        assert_eq!(Ok(()), Long::new_unchecked(&BYTES_LPV).check_len());
    }

    #[test]
    fn test_short_check_len() {
        assert_eq!(
            Err(Error::Truncated),
            Short::new_unchecked(&BYTES_SPV[..19]).check_len()
        );

        assert_eq!(Ok(()), Short::new_unchecked(&BYTES_SPV).check_len());
    }

    #[test]
    fn test_long_deconstruct() {
        let lpv = Long::new_unchecked(&BYTES_LPV);
        assert_eq!(lpv.address(), Address::new(false, StationType::RoadSideUnit, MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])));
        assert_eq!(lpv.timestamp(), 307970884);
        assert_eq!(lpv.latitude(), 487667533);
        assert_eq!(lpv.longitude(), 24841550);
        assert_eq!(lpv.position_accuracy_indicator(), true);
        assert_eq!(lpv.speed(), 24);
        assert_eq!(lpv.heading(), 2860);
    }

    #[test]
    fn test_short_deconstruct() {
        let lpv = Short::new_unchecked(&BYTES_SPV);
        assert_eq!(lpv.address(), Address::new(false, StationType::RoadSideUnit, MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])));
        assert_eq!(lpv.timestamp(), 307970884);
        assert_eq!(lpv.latitude(), 487667533);
        assert_eq!(lpv.longitude(), 24841550);
    }

    #[test]
    fn test_long_repr_parse_valid() {
        let lpv = Long::new_unchecked(&BYTES_LPV);
        let repr = LongRepr::parse(&lpv).unwrap();
        assert_eq!(
            repr,
            LongRepr {
                address: Address::new(false, StationType::RoadSideUnit, MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])),
                timestamp: 307970884,
                latitude: 487667533,
                longitude: 24841550,
                position_accuracy_indicator: true,
                speed: 24,
                heading: 2860,
            }
        );
    }

    #[test]
    fn test_short_repr_parse_valid() {
        let spv = Short::new_unchecked(&BYTES_SPV);
        let repr = ShortRepr::parse(&spv).unwrap();
        assert_eq!(
            repr,
            ShortRepr {
                address: Address::new(false, StationType::RoadSideUnit, MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])),
                timestamp: 307970884,
                latitude: 487667533,
                longitude: 24841550,
            }
        );
    }

    #[test]
    fn test_long_repr_emit() {
        let repr = LongRepr {
            address: Address::new(false, StationType::RoadSideUnit, MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])),
            timestamp: 307970884,
            latitude: 487667533,
            longitude: 24841550,
            position_accuracy_indicator: true,
            speed: 24,
            heading: 2860,
    };
        let mut bytes = [0u8; 24];
        let mut long = Long::new_unchecked(&mut bytes);
        repr.emit(&mut long);
        assert_eq!(long.into_inner(), &BYTES_LPV);
    }

    #[test]
    fn test_short_repr_emit() {
        let repr = ShortRepr {
            address: Address::new(false, StationType::RoadSideUnit, MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])),
            timestamp: 307970884,
            latitude: 487667533,
            longitude: 24841550,
    };
        let mut bytes = [0u8; 20];
        let mut short = Short::new_unchecked(&mut bytes);
        repr.emit(&mut short);
        assert_eq!(short.into_inner(), &BYTES_SPV);
    }

    #[test]
    fn test_long_buffer_len() {
        let header = Long::new_unchecked(&BYTES_LPV);
        let repr = LongRepr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_LPV.len());
    }

    #[test]
    fn test_short_buffer_len() {
        let header = Short::new_unchecked(&BYTES_SPV);
        let repr = ShortRepr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_SPV.len());
    }
}
