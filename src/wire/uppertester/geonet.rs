use byteorder::{ByteOrder, NetworkEndian};
use uom::si::{angle::degree, f32::Angle, length::meter};

use crate::{
    common::geo_area::{Circle, Ellipse, GeoArea, GeoPosition, Rectangle, Shape},
    time::Duration,
    types::{tenth_of_microdegree, Distance, Latitude, Longitude},
    wire::{GnAddress, GnTrafficClass},
};

mod field {
    #![allow(unused)]

    use crate::wire::field::*;

    /// UtGnTriggerGeoUnicast fields.
    /// Destination GN Address.
    pub const GEN_GUC_DST_ADR: Field = 0..8;
    /// Packet lifetime in milliseconds.
    pub const GEN_GUC_LIFETIME: Field = 8..10;
    /// Packet traffic class.
    pub const GEN_GUC_TC: usize = 10;
    /// Length of 'Payload' field.
    pub const GEN_GUC_PAYLOAD_LEN: Field = 11..13;
    /// Packet Payload.
    pub const GEN_GUC_PAYLOAD: Rest = 13..;

    /// UtGnTriggerGeoAnycast and UtGnTriggerGeoBroadcast fields.
    /// Zone shape.
    pub const GEN_GABC_SHAPE: usize = 0;
    /// Packet lifetime in milliseconds.
    pub const GEN_GABC_LIFETIME: Field = 1..3;
    /// Packet Packet traffic class.
    pub const GEN_GABC_TC: usize = 3;
    /// Reserved.
    pub const GEN_GABC_RES: Field = 4..7;
    /// Destination area latitude (1/10 degrees).
    pub const GEN_GABC_LAT: Field = 7..11;
    /// Destination area longitude (1/10 degrees).
    pub const GEN_GABC_LON: Field = 11..15;
    /// Destination area distance A.
    pub const GEN_GABC_DIST_A: Field = 15..17;
    /// Destination area distance B.
    pub const GEN_GABC_DIST_B: Field = 17..19;
    /// Destination area angle.
    pub const GEN_GABC_ANGLE: Field = 19..21;
    /// Length of 'Payload' field.
    pub const GEN_GABC_PAYLOAD_LEN: Field = 21..23;
    /// Packet Payload.
    pub const GEN_GABC_PAYLOAD: Rest = 23..;

    /// UtGnTriggerShb fields.
    /// Packet traffic class.
    pub const GEN_SHB_TC: usize = 0;
    /// Length of 'Payload' field.
    pub const GEN_SHB_PAYLOAD_LEN: Field = 1..3;
    /// Packet Payload.
    pub const GEN_SHB_PAYLOAD: Rest = 3..;

    /// UtGnTriggerTsb fields.
    /// Number of hops.
    pub const GEN_TSB_HOPS: usize = 0;
    /// Packet lifetime in milliseconds.
    pub const GEN_TSB_LIFETIME: Field = 1..3;
    /// Packet traffic class.
    pub const GEN_TSB_TC: usize = 3;
    /// Length of 'Payload' field.
    pub const GEN_TSB_PAYLOAD_LEN: Field = 4..6;
    /// Packet Payload.
    pub const GEN_TSB_PAYLOAD: Rest = 6..;

    /// UtGnEventInd fields.
    /// Length of 'Packet' field.
    pub const GN_IND_PAYLOAD_LEN: Field = 0..2;
    /// Packet Payload.
    pub const GN_IND_PAYLOAD: Rest = 2..;
}

/// A read/write wrapper around an UtGnTriggerGeoUnicast packet.
#[derive(Debug, PartialEq)]
pub struct UtGnTriggerGeoUnicast<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtGnTriggerGeoUnicast<T> {
    /// Create a raw octet buffer with an UtGnTriggerGeoUnicast packet structure.
    pub fn new(buffer: T) -> UtGnTriggerGeoUnicast<T> {
        UtGnTriggerGeoUnicast { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> GnAddress {
        let data = self.buffer.as_ref();
        GnAddress::from_bytes(&data[field::GEN_GUC_DST_ADR])
    }

    /// Return the lifetime field.
    #[inline]
    pub fn lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::GEN_GUC_LIFETIME]);
        Duration::from_millis(raw.into())
    }

    /// Return the traffic class field.
    #[inline]
    pub fn traffic_class(&self) -> GnTrafficClass {
        let data = self.buffer.as_ref();
        GnTrafficClass::from_byte(&data[field::GEN_GUC_TC])
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_len(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::GEN_GUC_PAYLOAD_LEN]).into()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> UtGnTriggerGeoUnicast<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::GEN_GUC_PAYLOAD]
    }
}

/// A read/write wrapper around an UtGnTriggerGeoBroadcast packet.
#[derive(Debug, PartialEq)]
pub struct UtGnTriggerGeoBroadcast<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtGnTriggerGeoBroadcast<T> {
    /// Create a raw octet buffer with an UtGnTriggerGeoBroadcast packet structure.
    pub fn new(buffer: T) -> UtGnTriggerGeoBroadcast<T> {
        UtGnTriggerGeoBroadcast { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the area contained in the packet.
    #[inline]
    pub fn area(&self) -> GeoArea {
        let data = self.buffer.as_ref();
        let shape = match data[field::GEN_GABC_SHAPE] {
            0 => Shape::Circle(Circle {
                radius: self.distance_a(),
            }),
            1 => Shape::Rectangle(Rectangle {
                a: self.distance_a(),
                b: self.distance_b(),
            }),
            2 => Shape::Ellipse(Ellipse {
                a: self.distance_a(),
                b: self.distance_b(),
            }),
            _ => todo!(),
        };

        GeoArea {
            shape,
            position: GeoPosition {
                latitude: self.latitude(),
                longitude: self.longitude(),
            },
            angle: self.angle(),
        }
    }

    #[inline]
    fn latitude(&self) -> Latitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::GEN_GABC_LAT]);
        Latitude::new::<tenth_of_microdegree>(raw as f32)
    }

    #[inline]
    fn longitude(&self) -> Longitude {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_i32(&data[field::GEN_GABC_LON]);
        Longitude::new::<tenth_of_microdegree>(raw as f32)
    }

    #[inline]
    fn distance_a(&self) -> Distance {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::GEN_GABC_DIST_A]);
        Distance::new::<meter>(raw as f32)
    }

    #[inline]
    fn distance_b(&self) -> Distance {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::GEN_GABC_DIST_B]);
        Distance::new::<meter>(raw as f32)
    }

    #[inline]
    fn angle(&self) -> Angle {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::GEN_GABC_ANGLE]);
        Angle::new::<degree>(raw as f32)
    }

    /// Return the lifetime field.
    #[inline]
    pub fn lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::GEN_GABC_LIFETIME]);
        Duration::from_millis(raw.into())
    }

    /// Return the traffic class field.
    #[inline]
    pub fn traffic_class(&self) -> GnTrafficClass {
        let data = self.buffer.as_ref();
        GnTrafficClass::from_byte(&data[field::GEN_GABC_TC])
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_len(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::GEN_GABC_PAYLOAD_LEN]).into()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> UtGnTriggerGeoBroadcast<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::GEN_GABC_PAYLOAD]
    }
}

/// A read/write wrapper around an UtGnTriggerShb packet.
#[derive(Debug, PartialEq)]
pub struct UtGnTriggerShb<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtGnTriggerShb<T> {
    /// Create a raw octet buffer with an UtGnTriggerShb packet structure.
    pub fn new(buffer: T) -> UtGnTriggerShb<T> {
        UtGnTriggerShb { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the traffic class field.
    #[inline]
    pub fn traffic_class(&self) -> GnTrafficClass {
        let data = self.buffer.as_ref();
        GnTrafficClass::from_byte(&data[field::GEN_SHB_TC])
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_len(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::GEN_SHB_PAYLOAD_LEN]).into()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> UtGnTriggerShb<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::GEN_SHB_PAYLOAD]
    }
}

/// A read/write wrapper around an UtGnTriggerTsb packet.
#[derive(Debug, PartialEq)]
pub struct UtGnTriggerTsb<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtGnTriggerTsb<T> {
    /// Create a raw octet buffer with an UtGnTriggerTsb packet structure.
    pub fn new(buffer: T) -> UtGnTriggerTsb<T> {
        UtGnTriggerTsb { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the hops field.
    #[inline]
    pub fn hops(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::GEN_TSB_HOPS]
    }

    /// Return the lifetime field.
    #[inline]
    pub fn lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::GEN_TSB_LIFETIME]);
        Duration::from_millis(raw.into())
    }

    /// Return the traffic class field.
    #[inline]
    pub fn traffic_class(&self) -> GnTrafficClass {
        let data = self.buffer.as_ref();
        GnTrafficClass::from_byte(&data[field::GEN_TSB_TC])
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_len(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::GEN_TSB_PAYLOAD_LEN]).into()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> UtGnTriggerTsb<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::GEN_TSB_PAYLOAD]
    }
}

/// A read/write wrapper around an UtGnEventInd packet.
#[derive(Debug, PartialEq)]
pub struct UtGnEventInd<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UtGnEventInd<T> {
    /// Set the payload length.
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::GN_IND_PAYLOAD_LEN], value);
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::GN_IND_PAYLOAD]
    }
}
