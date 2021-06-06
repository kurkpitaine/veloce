use crate::{Error, Result};
use core::fmt;
use core::time::Duration;

enum_with_unknown! {
   /// Geonetworking Next Header as carried inside the Basic Header.
   pub enum NextHeader(u8) {
       Any = 0,
       CommonHeader = 1,
       SecuredHeader = 2,
   }
}

impl fmt::Display for NextHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NextHeader::Any => write!(f, "Any Header"),
            NextHeader::CommonHeader => write!(f, "Common Header"),
            NextHeader::SecuredHeader => write!(f, "Secured Header"),
            NextHeader::Unknown(id) => write!(f, "0x{:02x}", id),
        }
    }
}

/// A read/write wrapper around a Geonetworking Basic Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.6.2 for details about fields
mod field {
    // 4-bits version and 4 bit identifier of the header following this header.
    pub const V_NXT_HDR: usize = 0;

    // 8-bits reserved field.
    pub const RESERVED: usize = 1;

    // 8-bits field containing the lifetime.
    pub const LIFETIME: usize = 2;

    // 8-bits field containing the remaining hop limit.
    pub const RHL: usize = 3;
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a Geonetworking Basic Header structure.
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

        if len < field::RHL + 1 {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::V_NXT_HDR] >> 4
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> NextHeader {
        let data = self.buffer.as_ref();
        NextHeader::from(data[field::V_NXT_HDR] & 0x0f)
    }

    /// Return the lifetime field.
    /// # Panics
    /// This function panics if the `base` of the lifetime is not decodable which is never likely to happen.
    #[inline]
    pub fn lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        let multiplier = u64::from((data[field::LIFETIME] & 0xfc) >> 2);
        let base = data[field::LIFETIME] & !0xfc;
        match base {
            0 => Duration::from_millis(multiplier * 50),
            1 => Duration::from_secs(multiplier * 1),
            2 => Duration::from_secs(multiplier * 10),
            3 => Duration::from_secs(multiplier * 100),
            _ => panic!("Decoding of Lifetime base failed"),
        }
    }

    /// Return the remaining hop limit field.
    #[inline]
    pub fn remaining_hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::RHL]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::V_NXT_HDR] = (data[field::V_NXT_HDR] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: NextHeader) {
        let data = self.buffer.as_mut();
        data[field::V_NXT_HDR] = (data[field::V_NXT_HDR] & 0xf0) | (u8::from(value) & 0x0f);
    }

    /// Set reserved field.
    /// Set 8-bit reserved field after the next header field.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        data[field::RESERVED] = 0;
    }

    /// Set the lifetime field.
    #[inline]
    pub fn set_lifetime(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        let raw = if value.as_secs() % 100 == 0 {
            // Base is 100 seconds
            ((value.as_secs() / 100) << 2) | 0x03
        } else if value.as_secs() % 10 == 0 {
            // base is 10 seconds
            ((value.as_secs() / 10) << 2) | 0x02
        } else if value.as_millis() % 1000 == 0 {
            // base is 1 second
            (value.as_secs() << 2) | 0x01
        } else {
            // base is 50 milliseconds
            ((value.as_millis() / 50) << 2) as u64
        };
        data[field::LIFETIME] = raw as u8;
    }

    /// Set the remaining hop limit field.
    #[inline]
    pub fn set_remaining_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::RHL] = value;
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Basic Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Geonetworking Basic Header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The Geonetworking protocol version number.
    pub version: u8,
    /// The type of header immediately following the Basic Header.
    pub next_header: NextHeader,
    /// The lifetime of the packet.
    pub lifetime: Duration,
    /// The remaining hop limit of the packet.
    pub remaining_hop_limit: u8,
}

impl Repr {
    /// Parse a Geonetworking Basic Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&T>) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(Repr {
            version: header.version(),
            next_header: header.next_header(),
            lifetime: header.lifetime(),
            remaining_hop_limit: header.remaining_hop_limit(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        field::RHL + 1
    }

    /// Emit a high-level representation into a Geonetworking Basic Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        header.set_version(self.version);
        header.set_next_header(self.next_header);
        header.clear_reserved();
        header.set_lifetime(self.lifetime);
        header.set_remaining_hop_limit(self.remaining_hop_limit);
    }
}

impl<'a> fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Basic Header version={} next_hdr={} lifetime={} rhl={}",
            self.version,
            self.next_header,
            self.lifetime.as_millis(),
            self.remaining_hop_limit
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Basic Header
    static BYTES_HEADER: [u8; 4] = [0x11, 0x00, 0x05, 0x01];

    #[test]
    fn test_check_len() {
        // less than 4 bytes
        assert_eq!(
            Err(Error::Truncated),
            Header::new_unchecked(&BYTES_HEADER[..2]).check_len()
        );

        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(header.version(), 1);
        assert_eq!(header.next_header(), NextHeader::CommonHeader);
        assert_eq!(header.lifetime(), Duration::from_secs(1));
        assert_eq!(header.remaining_hop_limit(), 1);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                version: 1,
                next_header: NextHeader::CommonHeader,
                lifetime: Duration::from_secs(1),
                remaining_hop_limit: 1
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            version: 1,
            next_header: NextHeader::CommonHeader,
            lifetime: Duration::from_secs(1),
            remaining_hop_limit: 1,
        };
        let mut bytes = [0u8; 4];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_HEADER);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_HEADER.len());
    }
}
