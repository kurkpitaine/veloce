use crate::geonet::wire::PC5Address;
use crate::geonet::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::HardwareAddress;

enum_with_unknown! {
    /// Ethernet protocol type.
    /// We support only Geonet and WSMP protocols
    pub enum EtherType(u16) {
        Geonet = 0x8947,
        WSMP = 0x88DC,
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EtherType::Geonet => write!(f, "Geonet"),
            EtherType::WSMP => write!(f, "WSMP"),
            EtherType::Unknown(id) => write!(f, "0x{:04x}", id),
        }
    }
}

/// A six-octet Ethernet II address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 6]);

impl Address {
    /// The broadcast address.
    pub const BROADCAST: Address = Address([0xff; 6]);

    /// Construct an Ethernet address from parts.
    pub const fn new(a0: u8, a1: u8, a2: u8, a3: u8, a4: u8, a5: u8) -> Address {
        Address([a0, a1, a2, a3, a4, a5])
    }

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Query whether the "multicast" bit in the OUI is set.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Query whether the "locally administered" bit in the OUI is set.
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Convert to an [`HardwareAddress`].
    ///
    /// Same as `.into()`, but works in `const`.
    pub const fn into_hardware_address(self) -> HardwareAddress {
        HardwareAddress::Ethernet(self)
    }
}

/// Convert the given PC5 Layer 2 address into an Ethernet address.
impl From<PC5Address> for Address {
    fn from(pc5_addr: PC5Address) -> Self {
        let mut addr = [0u8; 6];
        addr[0] = pc5_addr.as_bytes()[0];
        addr[1] = pc5_addr.as_bytes()[1];
        addr[2] = pc5_addr.as_bytes()[2];
        Self::from_bytes(&addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

/// A read/write wrapper around an Ethernet II frame buffer.
#[derive(Debug, Clone)]
pub struct Frame<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::geonet::wire::field::*;

    pub const DESTINATION: Field = 0..6;
    pub const SOURCE: Field = 6..12;
    pub const ETHERTYPE: Field = 12..14;
    pub const PAYLOAD: Rest = 14..;
}

/// The Ethernet header length
pub const HEADER_LEN: usize = field::PAYLOAD.start;

impl<T: AsRef<[u8]>> Frame<T> {
    /// Imbue a raw octet buffer with Ethernet frame structure.
    pub fn new_unchecked(buffer: T) -> Frame<T> {
        Frame { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < HEADER_LEN {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the length of a frame header.
    pub fn header_len() -> usize {
        HEADER_LEN
    }

    /// Return the length of a buffer required to hold a packet with the payload
    /// of a given length.
    pub const fn buffer_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DESTINATION])
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SOURCE])
    }

    /// Return the EtherType field, without checking for 802.1Q.
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::ETHERTYPE]);
        EtherType::from(raw)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Frame<&'a T> {
    /// Return a pointer to the payload, without checking for 802.1Q.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DESTINATION].copy_from_slice(value.as_bytes())
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SOURCE].copy_from_slice(value.as_bytes())
    }

    /// Set the EtherType field.
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ETHERTYPE], value.into())
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EthernetII src={} dst={} type={}",
            self.src_addr(),
            self.dst_addr(),
            self.ethertype()
        )
    }
}

use crate::geonet::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Frame<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        let frame = match Frame::new_checked(buffer) {
            Err(err) => return write!(f, "{indent}({err})"),
            Ok(frame) => frame,
        };
        write!(f, "{indent}{frame}")?;

        match frame.ethertype() {
            _ => Ok(()),
        }
    }
}

/// A high-level representation of an Ethernet II frame header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub src_addr: Address,
    pub dst_addr: Address,
    pub ethertype: EtherType,
}

impl Repr {
    /// Parse an Ethernet II frame and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &Frame<&T>) -> Result<Repr> {
        frame.check_len()?;
        Ok(Repr {
            src_addr: frame.src_addr(),
            dst_addr: frame.dst_addr(),
            ethertype: frame.ethertype(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into an Ethernet II frame.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Frame<T>) {
        frame.set_src_addr(self.src_addr);
        frame.set_dst_addr(self.dst_addr);
        frame.set_ethertype(self.ethertype);
    }
}

#[cfg(test)]
mod test {
    // Tests that are valid with any combination of
    // "proto-*" features.
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
        assert!(Address::BROADCAST.is_multicast());
        assert!(Address::BROADCAST.is_local());
    }
}
