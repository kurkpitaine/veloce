use crate::wire::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{packet::Protocol, TrafficClass};

enum_with_unknown! {
   /// Geonetworking Header Type / Header Sub-Type values.
   pub enum HeaderType(u8) {
       Any = 0x00,
       Beacon = 0x10,
       GeoUnicast = 0x20,
       GeoAnycastCircle = 0x30,
       GeoAnycastRect = 0x31,
       GeoAnycastElip = 0x32,
       GeoBroadcastCircle = 0x40,
       GeoBroadcastRect = 0x41,
       GeoBroadcastElip = 0x42,
       TsbSingleHop = 0x50,
       TsbMultiHop = 0x51,
       LsRequest = 0x60,
       LsReply = 0x61
   }
}

impl fmt::Display for HeaderType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HeaderType::Any => write!(f, "Any"),
            HeaderType::Beacon => write!(f, "Beacon"),
            HeaderType::GeoUnicast => write!(f, "Geo unicast"),
            HeaderType::GeoAnycastCircle => write!(f, "Geo anycast circle"),
            HeaderType::GeoAnycastRect => write!(f, "Geo anycast rectangle"),
            HeaderType::GeoAnycastElip => write!(f, "Geo anycast ellipse"),
            HeaderType::GeoBroadcastCircle => write!(f, "Geo broadcast circle"),
            HeaderType::GeoBroadcastRect => write!(f, "Geo broadcast rectangle"),
            HeaderType::GeoBroadcastElip => write!(f, "Geo broadcast ellipse"),
            HeaderType::TsbSingleHop => write!(f, "Tsb single hop"),
            HeaderType::TsbMultiHop => write!(f, "Tsb multi hop"),
            HeaderType::LsRequest => write!(f, "Ls request"),
            HeaderType::LsReply => write!(f, "Ls reply"),
            HeaderType::Unknown(id) => write!(f, "0x{:02x}", id),
        }
    }
}

/// A read/write wrapper around a Geonetworking Basic Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.7.2 for details about fields
mod field {
    use crate::wire::field::*;
    // 4-bit identifier of the header following the Geonetworking headers and 4-bit reserved.
    pub const NXT_HDR_R: usize = 0;

    // 8-bit identifier of the header immediately following this header.
    pub const HDR_TYPE: usize = 1;

    // 8-bit field containing the traffic class.
    pub const TRAFFIC_CLASS: usize = 2;

    // 8-bit field containing the flags.
    pub const FLAGS: usize = 3;

    // 16-bit field containing the Geonetworking payload length.
    pub const PAYLOAD_LEN: Field = 4..6;

    // 8-bit field containing the packet maximum hop limit.
    pub const MAX_HOP_LIMIT: usize = 6;

    // 8-bit field containing reserved bits.
    pub const RESERVED: usize = 7;
}

/// The Common header length
pub const HEADER_LEN: usize = field::RESERVED + 1;

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
    /// Returns `Err(Error)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::RESERVED + 1 {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::NXT_HDR_R] >> 4)
    }

    /// Return the header type field.
    #[inline]
    pub fn header_type(&self) -> HeaderType {
        let data = self.buffer.as_ref();
        HeaderType::from(data[field::HDR_TYPE])
    }

    /// Return the traffic class field.
    #[inline]
    pub fn traffic_class(&self) -> TrafficClass {
        let data = self.buffer.as_ref();
        TrafficClass::from_byte(&data[field::TRAFFIC_CLASS])
    }

    /// Return the mobile flag.
    #[inline]
    pub fn mobile(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::FLAGS] & 0x80 != 0
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_length(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::PAYLOAD_LEN]).into()
    }

    /// Return the maximum hop limit field.
    #[inline]
    pub fn maximum_hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::MAX_HOP_LIMIT]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Header<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR_R] = (data[field::NXT_HDR_R] & 0x0f) | (u8::from(value) << 4);
    }

    /// Clear the two reserved fields.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR_R] &= 0xf0;
        data[field::RESERVED] = 0;
    }

    /// Set the header type field.
    #[inline]
    pub fn set_header_type(&mut self, value: HeaderType) {
        let data = self.buffer.as_mut();
        data[field::HDR_TYPE] = value.into();
    }

    /// Set the traffic class field.
    #[inline]
    pub fn set_traffic_class(&mut self, value: TrafficClass) {
        let data = self.buffer.as_mut();
        data[field::TRAFFIC_CLASS] = *value.as_byte();
    }

    /// Clear the whole flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        data[field::FLAGS] = 0;
    }

    /// Set the "mobile" flag.
    #[inline]
    pub fn set_mobile(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = data[field::FLAGS];
        data[field::FLAGS] = if value { raw | 0x80 } else { raw & !0x80 };
    }

    /// Set the payload length field.
    #[inline]
    pub fn set_payload_length(&mut self, value: usize) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::PAYLOAD_LEN], value as u16);
    }

    /// Set the maximum hop limit field.
    #[inline]
    pub fn set_maximum_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::MAX_HOP_LIMIT] = value;
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Common Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Geonetworking Common Header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The type of the header following the Geonetworking headers.
    pub next_header: Protocol,
    /// The type of the header immediately following this header.
    pub header_type: HeaderType,
    /// The traffic class of the packet.
    pub traffic_class: TrafficClass,
    /// The mobile flag.
    pub mobile: bool,
    /// The payload length of the packet.
    pub payload_len: usize,
    /// The maximum hop limit of the packet.
    pub max_hop_limit: u8,
}

impl Repr {
    /// Parse a Geonetworking Basic Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&T>) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        header.check_len()?;

        Ok(Repr {
            next_header: header.next_header(),
            header_type: header.header_type(),
            traffic_class: header.traffic_class(),
            mobile: header.mobile(),
            payload_len: header.payload_length(),
            max_hop_limit: header.maximum_hop_limit(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        field::RESERVED + 1
    }

    /// Emit a high-level representation into a Geonetworking Common Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_next_header(self.next_header);
        header.clear_reserved();
        header.set_header_type(self.header_type);
        header.set_traffic_class(self.traffic_class);
        header.clear_flags();
        header.set_mobile(self.mobile);
        header.set_payload_length(self.payload_len);
        header.set_maximum_hop_limit(self.max_hop_limit);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Common Header next_hdr={} hdr_type={} tc={} mobile={} p_len={} mhl={}",
            self.next_header,
            self.header_type,
            self.traffic_class,
            self.mobile,
            self.payload_len,
            self.max_hop_limit,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Common Header
    static BYTES_HEADER: [u8; 8] = [0x20, 0x50, 0x02, 0x00, 0x00, 0x1e, 0x01, 0x00];

    #[test]
    fn test_check_len() {
        // less than 8 bytes
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_HEADER[..6]).check_len()
        );

        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(header.next_header(), Protocol::BtpB);
        assert_eq!(header.header_type(), HeaderType::TsbSingleHop);
        assert_eq!(header.traffic_class(), TrafficClass::new(false, 2));
        assert_eq!(header.mobile(), false);
        assert_eq!(header.payload_length(), 30);
        assert_eq!(header.maximum_hop_limit(), 1);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                next_header: Protocol::BtpB,
                header_type: HeaderType::TsbSingleHop,
                traffic_class: TrafficClass::new(false, 2),
                mobile: false,
                payload_len: 30,
                max_hop_limit: 1,
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            next_header: Protocol::BtpB,
            header_type: HeaderType::TsbSingleHop,
            traffic_class: TrafficClass::new(false, 2),
            mobile: false,
            payload_len: 30,
            max_hop_limit: 1,
        };
        let mut bytes = [0u8; 8];
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
