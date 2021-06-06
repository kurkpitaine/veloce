use crate::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::Address;

/// A read/write wrapper around a Geonetworking Long Position Vector.
#[derive(Debug, PartialEq)]
pub struct Long<T: AsRef<[u8]>> {
    buffer: T,
}

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
