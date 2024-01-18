use byteorder::{ByteOrder, NetworkEndian};

mod field {
    use crate::wire::field::*;

    /// UtBtpTriggerA fields.
    /// Destination port.
    pub const BTP_A_DST_PORT: Field = 0..2;
    /// Source port.
    pub const BTP_A_SRC_PORT: Field = 2..4;

    /// UtBtpTriggerB fields.
    /// Destination port.
    pub const BTP_B_DST_PORT: Field = 0..2;
    /// Source port info.
    pub const BTP_B_DST_PORT_INFO: Field = 2..4;

    /// UtBtpEventInd fields.
    /// Length of 'Packet' field.
    pub const BTP_IND_PAYLOAD_LEN: Field = 0..2;
    /// Packet Payload.
    pub const BTP_IND_PAYLOAD: Rest = 2..;
}

/// A read/write wrapper around a UtBtpTriggerA packet.
#[derive(Debug, PartialEq)]
pub struct UtBtpTriggerA<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtBtpTriggerA<T> {
    /// Create a raw octet buffer with a UtBtpTriggerA packet structure.
    pub fn new(buffer: T) -> UtBtpTriggerA<T> {
        UtBtpTriggerA { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the destination port field.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::BTP_A_DST_PORT])
    }

    /// Return the source port field.
    #[inline]
    pub fn src_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::BTP_A_SRC_PORT])
    }
}

/// A read/write wrapper around a UtBtpTriggerB packet.
#[derive(Debug, PartialEq)]
pub struct UtBtpTriggerB<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtBtpTriggerB<T> {
    /// Create a raw octet buffer with a UtBtpTriggerB packet structure.
    pub fn new(buffer: T) -> UtBtpTriggerB<T> {
        UtBtpTriggerB { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the destination port field.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::BTP_B_DST_PORT])
    }

    /// Return the destination port info field.
    #[inline]
    pub fn dst_port_info(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::BTP_B_DST_PORT_INFO])
    }
}

/// A read/write wrapper around a UtBtpEventInd packet.
#[derive(Debug, PartialEq)]
pub struct UtBtpEventInd<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtBtpEventInd<T> {
    /// Create a raw octet buffer with a UtBtpEventInd packet structure.
    pub fn new(buffer: T) -> UtBtpEventInd<T> {
        UtBtpEventInd { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UtBtpEventInd<T> {
    /// Set the payload length field.
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::BTP_IND_PAYLOAD_LEN], value);
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::BTP_IND_PAYLOAD]
    }
}
