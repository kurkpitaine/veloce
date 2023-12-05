//! This module implements the LLC Link Layer Control wire format.
//! Only LLC type 1 is supported, with SNAP extension.
//! No protocol logic is implemented as layer 2 protocols are usually
//! implemented in 802.11 radio chip firmware.

use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, EthernetProtocol, Result};
use core::fmt;

enum_with_unknown! {
   /// LLC protocol type.
   pub enum AccessProtocol(u8) {
       SNAP = 0xaa,
   }
}

impl fmt::Display for AccessProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AccessProtocol::SNAP => write!(f, "SNAP"),
            AccessProtocol::Unknown(id) => write!(f, "0x{:04x}", id),
        }
    }
}

/// A read/write wrapper around a Link Layer Control with SNAP frame buffer.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::geonet::wire::field::*;

    /// LLC Destination Service Access Point field.
    pub const DSAP: usize = 0;
    /// LLC Source Service Access Point field.
    pub const SSAP: usize = 1;
    /// LLC Control field.
    pub const CTRL: usize = 2;
    /// SNAP vendor ID.
    pub const VENDOR: Field = 3..6;
    /// SNAP Upper protocol.
    pub const PROTO: Field = 6..8;
    /// Frame payload.
    pub const PAYLOAD: Rest = 14..;
}

/// Length of an LLC with SNAP header.
pub const HEADER_LEN: usize = field::PROTO.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Imbue a raw octet buffer with an LLC with SNAP packet structure.
    pub const fn new_unchecked(buffer: T) -> Header<T> {
        Header { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < HEADER_LEN {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the `DSAP` field.
    #[inline]
    pub fn dsap(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSAP]
    }

    /// Return the `SSAP` field.
    #[inline]
    pub fn ssap(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::SSAP]
    }

    /// Return the `control` field.
    #[inline]
    pub fn control(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CTRL]
    }

    /// Return the SNAP `vendor` field.
    #[inline]
    pub fn snap_vendor(&self) -> [u8; 3] {
        let data = self.buffer.as_ref();
        let mut raw = [0u8; 3];
        raw.copy_from_slice(&data[field::VENDOR]);
        raw
    }

    /// Return the SNAP `protocol` field.
    #[inline]
    pub fn snap_protocol(&self) -> EthernetProtocol {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::PROTO]);
        EthernetProtocol::from(raw)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Header<&'a T> {
    /// Return a pointer to the payload, without checking for 802.1Q.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Return the `DSAP` field.
    #[inline]
    pub fn set_dsap(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSAP] = value;
    }

    /// Return the `SSAP` field.
    #[inline]
    pub fn set_ssap(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::SSAP] = value;
    }

    /// Return the `control` field.
    #[inline]
    pub fn set_control(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CTRL] = value;
    }

    /// Return the SNAP `vendor` field.
    #[inline]
    pub fn set_snap_vendor(&mut self, value: [u8; 3]) {
        let data = self.buffer.as_mut();
        data[field::VENDOR].copy_from_slice(&value);
    }

    /// Return the SNAP `protocol` field.
    #[inline]
    pub fn set_snap_protocol(&mut self, value: EthernetProtocol) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::PROTO], value.into());
    }
}

/// A high-level representation of an LLC with SNAP header.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    /// The Destination Service Access Point `DSAP` field.
    pub dsap: u8,
    /// The Source Service Access Point `SSAP` field.
    pub ssap: u8,
    /// The control field.
    pub control: u8,
    /// The SNAP vendor field.
    pub snap_vendor: [u8; 3],
    /// The SNAP protocol field.
    pub snap_protocol: EthernetProtocol,
}

impl Repr {
    /// Parse an LLC with SNAP Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            dsap: header.dsap(),
            ssap: header.ssap(),
            control: header.control(),
            snap_vendor: header.snap_vendor(),
            snap_protocol: header.snap_protocol(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into an LLC with SNAP Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_dsap(self.dsap);
        header.set_ssap(self.ssap);
        header.set_control(self.control);
        header.set_snap_vendor(self.snap_vendor);
        header.set_snap_protocol(self.snap_protocol);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LLC SNAP dsap={} ssap={} control={} snap_vendor={:?} snap_protocol={}",
            self.dsap, self.ssap, self.control, self.snap_vendor, self.snap_protocol,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // An LLC with SNAP header.
    static BYTES_HEADER: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x89, 0x47];

    #[test]
    fn test_check_len() {
        // less than 8 bytes
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_HEADER[..7]).check_len()
        );

        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(header.dsap(), 0xaa);
        assert_eq!(header.ssap(), 0xaa);
        assert_eq!(header.control(), 3);
        assert_eq!(header.snap_vendor(), [0u8; 3]);
        assert_eq!(header.snap_protocol(), EthernetProtocol::Geonet);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                dsap: 0xaa,
                ssap: 0xaa,
                control: 3,
                snap_vendor: [0u8; 3],
                snap_protocol: EthernetProtocol::Geonet
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            dsap: 0xaa,
            ssap: 0xaa,
            control: 3,
            snap_vendor: [0u8; 3],
            snap_protocol: EthernetProtocol::Geonet,
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
