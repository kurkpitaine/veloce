use crate::wire::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{
    long_position_vector::{Header as LPVBuf, Repr as LongPositionVector},
    Address,
};

/// A read/write wrapper around a Geonetworking Single Hop Broadcast Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.8.3.2 for details about fields
mod field {
    use crate::wire::field::*;

    // 24-octet Source Position Vector of the Geonetworking Single Hop Broadcast Header.
    pub const SO_PV: Field = 0..24;
    // 4-octet Reserved field of the Geonetworking Single Hop Broadcast Header.
    pub const RESERVED: Field = 24..28;
}

// The Geonetworking Single Hop Broadcast Header length.
pub const HEADER_LEN: usize = field::RESERVED.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a Geonetworking Single Hop Broadcast Header structure.
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

        if len < HEADER_LEN {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the source position vector.
    #[inline]
    pub fn source_position_vector(&self) -> Result<LongPositionVector> {
        let data = self.buffer.as_ref();
        let spv_buf = LPVBuf::new_unchecked(&data[field::SO_PV]);
        LongPositionVector::parse(&spv_buf)
    }

    /// Return the reserved field as [`DccMco`].
    #[inline]
    pub fn dcc_mco(&self) -> DccMco {
        let data = self.buffer.as_ref();
        DccMco::from_bytes(&data[field::RESERVED])
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
    /// Set the source position vector field.
    #[inline]
    pub fn set_source_position_vector(&mut self, value: LongPositionVector) {
        let data = self.buffer.as_mut();
        let mut spv_buf = LPVBuf::new_unchecked(&mut data[field::SO_PV]);
        value.emit(&mut spv_buf);
    }

    /// Clear the reserved field.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::RESERVED], 0);
    }

    /// Set the reserved field as [`DccMco`].
    #[inline]
    pub fn set_dcc_mco(&mut self, value: DccMco) {
        let data = self.buffer.as_mut();
        data.copy_from_slice(value.as_bytes());
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "Single Hop Broadcast Header ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of a Single Hop Broadcast header.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Repr {
    /// The Source Position Vector contained inside the Single Hop Broadcast header.
    pub source_position_vector: LongPositionVector,
}

impl Repr {
    /// Parse a Single Hop Broadcast Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            source_position_vector: header.source_position_vector()?,
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a Single Hop Broadcast Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_source_position_vector(self.source_position_vector);
    }

    /// Returns the source Geonetworking address contained inside the
    /// source position vector of the Single Hop Broadcast header.
    pub const fn src_addr(&self) -> Address {
        self.source_position_vector.address
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Single Hop Broadcast Header so_pv={}",
            self.source_position_vector
        )
    }
}

/// An four-octet DCC-MCO extension field.
#[derive(Default, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct DccMco(pub [u8; 4]);

impl DccMco {
    /// Constructs a DCC MCO field.
    pub fn new(cbr_l0_hop: f32, cbr_l1_hop: f32, tx_power: u8) -> DccMco {
        let cbr_l0_hop = (cbr_l0_hop * 255.0).floor() as u8;
        let cbr_l1_hop = (cbr_l1_hop * 255.0).floor() as u8;
        let tx_power = tx_power.clamp(0, 31) & 0x1f;

        DccMco([cbr_l0_hop, cbr_l1_hop, tx_power, 0])
    }

    /// Constructs a DCC MCO field from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not 4 octets long.
    pub fn from_bytes(data: &[u8]) -> DccMco {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(data);
        DccMco(bytes)
    }

    /// Return a DCC MCO field as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the `cbr_l0_hop` field.
    pub fn cbr_l0_hop(&self) -> f32 {
        f32::from(self.0[0]) / 255.0
    }

    /// Returns the `cbr_l1_hop` field.
    pub fn cbr_l1_hop(&self) -> f32 {
        f32::from(self.0[1]) / 255.0
    }

    /// Returns the `tx_power` field, in dBm units.
    pub fn tx_power(&self) -> u8 {
        self.0[2]
    }

    /// Sets the `cbr_l0_hop` field.
    pub fn set_cbr_l0_hop(&mut self, value: f32) {
        let value = (value * 255.0).floor() as u8;
        self.0[0] = value;
    }

    /// Sets the `cbr_l1_hop` field.
    pub fn set_cbr_l1_hop(&mut self, value: f32) {
        let value = (value * 255.0).floor() as u8;
        self.0[1] = value;
    }

    /// Sets the `tx_power` field, in dBm units.
    pub fn set_tx_power(&mut self, value: u8) {
        let value = value.clamp(0, 31);
        let raw = self.0[2] & !0x1f;
        self.0[2] = raw | (value & 0x1f);
    }
}

impl fmt::Display for DccMco {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DccMco  cbr_l0_hop={:.2} cbr_l1_hop={:.2} tx_power={} dBm EIRP",
            self.cbr_l0_hop(),
            self.cbr_l1_hop(),
            self.tx_power()
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::*;
    use crate::wire::ethernet::Address as MacAddress;
    use crate::wire::geonet::{Address as GnAddress, PositionVectorTimestamp, StationType};

    static BYTES_HEADER: [u8; 28] = [
        0xbc, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x00, 0x00, 0x00, 0x78, 0x1c, 0xc6, 0x66,
        0x60, 0xfd, 0xe2, 0x03, 0xd4, 0x80, 0x18, 0x0b, 0x2c, 0x00, 0x00, 0x00, 0x00,
    ];

    fn lpv_repr() -> LongPositionVector {
        LongPositionVector {
            address: GnAddress::new(
                true,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
            ),
            timestamp: PositionVectorTimestamp(120),
            latitude: Latitude::new::<tenth_of_microdegree>(482764384.0),
            longitude: Longitude::new::<tenth_of_microdegree>(-35519532.0),
            is_accurate: true,
            speed: Speed::new::<centimeter_per_second>(24.0),
            heading: Heading::new::<decidegree>(2860.0),
        }
    }

    #[test]
    fn test_check_len() {
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_HEADER[..HEADER_LEN - 1]).check_len()
        );

        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(header.source_position_vector().unwrap(), lpv_repr());
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                source_position_vector: lpv_repr(),
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            source_position_vector: lpv_repr(),
        };
        let mut bytes = [0u8; HEADER_LEN];
        let mut long = Header::new_unchecked(&mut bytes);
        repr.emit(&mut long);
        assert_eq!(long.into_inner(), &BYTES_HEADER);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_HEADER.len());
    }
}
