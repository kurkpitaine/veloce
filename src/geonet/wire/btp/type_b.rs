use crate::geonet::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

/// A read/write wrapper around a BTP-B Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-5-1 V2.2.1 chapter 7.3 for details about fields
mod field {
    use crate::geonet::wire::field::*;

    // 2-octet Destination Port field of the BTP-B Header.
    pub const DST_PORT: Field = 0..2;
    // 2-octet Destination Port Info field of the BTP-B Header.
    pub const DST_PORT_INFO: Field = 2..4;
}

// The BTP-B Header length.
pub const HEADER_LEN: usize = field::DST_PORT_INFO.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a BTP-B Header structure.
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

    /// Return the destination port.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::DST_PORT])
    }

    /// Return the destination port info.
    #[inline]
    pub fn destination_port_info(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::DST_PORT_INFO])
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
    /// Set the destination port.
    #[inline]
    pub fn set_destination_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DST_PORT], value);
    }

    /// Set the destination port info.
    #[inline]
    pub fn set_destination_port_info(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DST_PORT_INFO], value);
    }
}

/// A high-level representation of a BTP-B header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The destination port contained inside the BTP-B header.
    pub dst_port: u16,
    /// The destination port information contained inside the BTP-B header.
    pub dst_port_info: u16,
}

impl Repr {
    /// Parse a BTP-B Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            dst_port: header.destination_port(),
            dst_port_info: header.destination_port_info(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a BTP-B Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_destination_port(self.dst_port);
        header.set_destination_port_info(self.dst_port_info);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => write!(f, "BTP-B ({err})"),
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BTP-B dst={} dst_info={}", self.dst_port, self.dst_port_info)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Repr {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "BTP-B dst={} dst_info={}", self.dst_port, self.dst_port_info);
    }
}

use crate::geonet::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Header<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        match Header::new_checked(buffer) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(packet) => write!(f, "{indent}{packet}"),
        }
    }
}
