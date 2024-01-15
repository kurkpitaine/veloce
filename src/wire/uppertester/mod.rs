use byteorder::{ByteOrder, NetworkEndian};
use uom::si::length::centimeter;

use crate::types::{tenth_of_microdegree, Distance, Latitude, Longitude};

pub mod btp;
pub mod geonet;

/// Uppertester result values.
pub enum Result {
    Failure = 0x00,
    Success = 0x01,
}

enum_with_unknown! {
   /// Uppertester message type.
   /// Only supported (ie: where uppertester primitives are implemented)
   /// types are present.
   pub enum MessageType(u8) {
      // Basic Uppertester types.
      UtInitialize = 0x00,
      UtInitializeResult = 0x01,
      UtChangePosition = 0x02,
      UtChangePositionResult = 0x03,
      UtChangePseudonym = 0x04,
      UtChangePseudonymResult = 0x05,

      // Geonetworking types.
      UtGnTriggerResult = 0x41,
      UtGnTriggerGeoUnicast = 0x50,
      UtGnTriggerGeoBroadcast = 0x51,
      UtGnTriggerGeoAnycast = 0x52,
      UtGnTriggerShb = 0x53,
      UtGnTriggerTsb = 0x54,
      UtGnEventInd = 0x55,

      // BTP types.
      UtBtpTriggerA = 0x70,
      UtBtpTriggerResult = 0x71,
      UtBtpTriggerB = 0x72,
      UtBtpEventInd = 0x73,
   }
}

// See ETSI TR 103 099 V1.5.1 annex C for details about fields
mod field {
    use crate::wire::field::*;

    /// 1-octet Uppertester message type.
    pub const MSG_TYPE: Field = 0..1;

    /// 1-octet Uppertester return code field.
    pub const RES_CODE: usize = 1;

    /// UtInitialize fields.
    /// HashedId8 indicates the AT certificate digest to be used by the IUT.
    /// In case PICS_GN_SECURITY is set to FALSE, then HashedId8 is set to 0
    pub const HASHED_ID8: Field = 0..8;

    /// UtChangePosition fields.
    /// The latitude, longitude and altitude parameters are relative to the current position of IUT.
    /// They are NOT absolute position.
    /// Latitude offset (multiples of 0,1 microdegree)
    pub const C_POS_DELTA_LAT: Field = 0..4;
    /// Longitude offset (multiples of 0,1 microdegree)
    pub const C_POS_DELTA_LON: Field = 4..8;
    /// Altitude offset (centimetre)
    pub const C_POS_DELTA_ELV: Field = 8..12;
}

/// A read/write wrapper around an Uppertester packet.
#[derive(Debug, PartialEq)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a raw octet buffer with an Uppertester packet structure.
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[inline]
    pub fn message_type(&self) -> MessageType {
        let data = self.buffer.as_ref();
        MessageType::from(data[field::MSG_TYPE.start])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::MSG_TYPE.end..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[inline]
    pub fn set_message_type(&mut self, value: MessageType) {
        let data = self.buffer.as_mut();
        data[field::MSG_TYPE.start] = value.into();
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::MSG_TYPE.end..]
    }

    /// Set the result code.
    #[inline]
    pub fn set_result(&mut self, rc: Result) {
        let data = self.buffer.as_mut();
        data[field::RES_CODE] = rc as u8;
    }
}

/// A read/write wrapper around an UtInitialize packet.
#[derive(Debug, PartialEq)]
pub struct UtInitialize<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtInitialize<T> {
    /// Zero HashedId8.
    pub const ZERO_HASHEDID8: [u8; 8] = [0; 8];

    /// Create a raw octet buffer with an UtInitialize packet structure.
    pub fn new(buffer: T) -> UtInitialize<T> {
        UtInitialize { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the hashedId8 field.
    #[inline]
    pub fn hashed_id8(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::HASHED_ID8]
    }
}

/// A read/write wrapper around an UtChangePosition packet.
#[derive(Debug, PartialEq)]
pub struct UtChangePosition<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtChangePosition<T> {
    /// Create a raw octet buffer with an UtChangePosition packet structure.
    pub fn new(buffer: T) -> UtChangePosition<T> {
        UtChangePosition { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the delta latitude field.
    #[inline]
    pub fn delta_latitude(&self) -> Latitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::C_POS_DELTA_LAT]);
        Latitude::new::<tenth_of_microdegree>(raw as f32)
    }

    /// Return the delta longitude field.
    #[inline]
    pub fn delta_longitude(&self) -> Longitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::C_POS_DELTA_LON]);
        Longitude::new::<tenth_of_microdegree>(raw as f32)
    }

    /// Return the delta elevation field.
    #[inline]
    pub fn delta_elevation(&self) -> Distance {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::C_POS_DELTA_ELV]);
        Distance::new::<centimeter>(raw as f32)
    }
}
