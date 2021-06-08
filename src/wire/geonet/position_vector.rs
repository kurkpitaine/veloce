use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use crate::wire::geonet::Address as GnAddress;

/// A Geonetworking Position Vector.
pub enum PositionVector {
    /// A Long Position Vector.
    Long(LongVector),
    /// A Short Position Vector.
    Short(ShortVector),
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

/// A Geonetworking Long Position Vector.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct LongVector(pub [u8; 24]);

impl LongVector {
    /// Construct a Geonetworking Long Position Vector
    pub fn new(
        address: GnAddress,
        timestamp: u32,
        latitude: i32,
        longitude: i32,
        accuracy: bool,
        speed: i16,
        heading: u16,
    ) -> LongVector {
        let mut lpv = [0u8; 24];
        lpv[field::GN_ADDR].copy_from_slice(address.as_bytes());
        NetworkEndian::write_u32(&mut lpv[field::TIMESTAMP], timestamp);
        NetworkEndian::write_i32(&mut lpv[field::LATITUDE], latitude);
        NetworkEndian::write_i32(&mut lpv[field::LONGITUDE], longitude);

        let mut pai_speed: u16 = if accuracy { 0x8000 } else { 0 };
        pai_speed = pai_speed | (speed as u16 & !0x8000);
        NetworkEndian::write_u16(&mut lpv[field::PAI_SPEED], pai_speed);

        NetworkEndian::write_u16(&mut lpv[field::HEADING], heading);
        LongVector(lpv)
    }

    /// Construct a Long Position Vector from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not twenty-four octets long.
    pub fn from_bytes(data: &[u8]) -> LongVector {
        let mut bytes = [0; 24];
        bytes.copy_from_slice(data);
        LongVector(bytes)
    }

    /// Return an Long Position Vector as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the Address field.
    pub fn address(&self) -> GnAddress {
        GnAddress::from_bytes(&self.0[field::GN_ADDR])
    }

    /// Return the Timestamp field.
    pub fn timestamp(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[field::TIMESTAMP])
    }

    /// Return the Latitude field.
    pub fn latitude(&self) -> i32 {
        NetworkEndian::read_i32(&self.0[field::LATITUDE])
    }

    /// Return the Latitude field.
    pub fn longitude(&self) -> i32 {
        NetworkEndian::read_i32(&self.0[field::LONGITUDE])
    }

    /// Query whether the position is accurate.
    pub fn is_accurate(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.0[field::PAI_SPEED]);
        (raw & 0x8000) != 0
    }

    /// Return the Speed field.
    pub fn speed(&self) -> i16 {
        let raw = NetworkEndian::read_u16(&self.0[field::PAI_SPEED]);
        (raw & !0x8000) as i16
    }

    /// Return the Heading field.
    pub fn heading(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::HEADING])
    }
}

impl fmt::Display for LongVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Long Position Vector  gn_addr={} tst={} lat={} lon={} pai={} spd={} hdg={}",
            self.address(),
            self.timestamp(),
            self.latitude(),
            self.longitude(),
            self.is_accurate(),
            self.speed(),
            self.heading(),
        )
    }
}

/// A Geonetworking Short Position Vector.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ShortVector(pub [u8; 20]);

impl ShortVector {
    /// Construct a Geonetworking Long Position Vector
    pub fn new(address: GnAddress, timestamp: u32, latitude: i32, longitude: i32) -> ShortVector {
        let mut spv = [0u8; 20];
        spv[field::GN_ADDR].copy_from_slice(address.as_bytes());
        NetworkEndian::write_u32(&mut spv[field::TIMESTAMP], timestamp);
        NetworkEndian::write_i32(&mut spv[field::LATITUDE], latitude);
        NetworkEndian::write_i32(&mut spv[field::LONGITUDE], longitude);
        ShortVector(spv)
    }

    /// Construct a Short Position Vector from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not twenty-four octets long.
    pub fn from_bytes(data: &[u8]) -> ShortVector {
        let mut bytes = [0; 20];
        bytes.copy_from_slice(data);
        ShortVector(bytes)
    }

    /// Return a Short Position Vector as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the Address field.
    pub fn address(&self) -> GnAddress {
        GnAddress::from_bytes(&self.0[field::GN_ADDR])
    }

    /// Return the Timestamp field.
    pub fn timestamp(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[field::TIMESTAMP])
    }

    /// Return the Latitude field.
    pub fn latitude(&self) -> i32 {
        NetworkEndian::read_i32(&self.0[field::LATITUDE])
    }

    /// Return the Latitude field.
    pub fn longitude(&self) -> i32 {
        NetworkEndian::read_i32(&self.0[field::LONGITUDE])
    }
}

impl fmt::Display for ShortVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Short Position Vector  gn_addr={} tst={} lat={} lon={}",
            self.address(),
            self.timestamp(),
            self.latitude(),
            self.longitude(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::ethernet::Address as MacAddress;
    use crate::wire::geonet::{Address as GnAddress, StationType};

    static BYTES_LPV: [u8; 24] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x4d, 0x01, 0x7b, 0x0d, 0x4e, 0x80, 0x18, 0x0b, 0x2c,
    ];

    static BYTES_SPV: [u8; 20] = [
        0x3c, 0x00, 0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1, 0x12, 0x5b, 0x43, 0x44, 0x1d, 0x11, 0x37,
        0x4d, 0x01, 0x7b, 0x0d, 0x4e,
    ];

    #[test]
    fn test_lpv_new() {
        let lpv = LongVector::new(
            GnAddress::new(
                false,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
            ),
            307970884,
            487667533,
            24841550,
            true,
            24,
            2860,
        );

        assert_eq!(
            lpv.as_bytes(),
            &BYTES_LPV
        );
    }

    #[test]
    fn test_spv_new() {
        let spv = ShortVector::new(
            GnAddress::new(
                false,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1]),
            ),
            307970884,
            487667533,
            24841550,
        );

        assert_eq!(
            spv.as_bytes(),
            &BYTES_SPV
        );
    }

    #[test]
    fn test_lpv_from_bytes() {
        let lpv = LongVector::from_bytes(&BYTES_LPV);
        assert_eq!(
            lpv.address(),
            GnAddress::new(
                false,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])
            )
        );
        assert_eq!(lpv.timestamp(), 307970884);
        assert_eq!(lpv.latitude(), 487667533);
        assert_eq!(lpv.longitude(), 24841550);
        assert_eq!(lpv.is_accurate(), true);
        assert_eq!(lpv.speed(), 24);
        assert_eq!(lpv.heading(), 2860);
    }

    #[test]
    fn test_spv_from_bytes() {
        let spv = ShortVector::from_bytes(&BYTES_SPV);
        assert_eq!(
            spv.address(),
            GnAddress::new(
                false,
                StationType::RoadSideUnit,
                MacAddress([0x9a, 0xf3, 0xd8, 0x02, 0xfb, 0xd1])
            )
        );
        assert_eq!(spv.timestamp(), 307970884);
        assert_eq!(spv.latitude(), 487667533);
        assert_eq!(spv.longitude(), 24841550);
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_lpv_from_bytes_too_long() {
        let _ = LongVector::from_bytes(&[0u8; 25]);
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_spv_from_bytes_too_long() {
        let _ = ShortVector::from_bytes(&[0u8; 21]);
    }
}
