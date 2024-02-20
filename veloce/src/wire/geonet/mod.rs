use crate::{time::TAI2004, wire::ethernet::Address as MacAddress};
use byteorder::{ByteOrder, NetworkEndian};
use core::{cmp, fmt, ops, u16};

pub mod anycast_broadcast_header;
pub mod basic_header;
pub mod beacon_header;
pub mod common_header;
pub mod geonet;
pub mod location_service_req_header;
pub mod long_position_vector;
pub mod short_position_vector;
pub mod single_hop_header;
pub mod topo_header;
pub mod unicast_header;

/// Position vector timestamp.
///
/// Number of elapsed TAI milliseconds since
/// 2004-01-01 00:00:00.000 UTC.
#[derive(Debug, PartialEq, Eq, PartialOrd, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PositionVectorTimestamp(pub u32);

impl fmt::Display for PositionVectorTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ms", self.0)
    }
}

impl From<TAI2004> for PositionVectorTimestamp {
    fn from(value: TAI2004) -> Self {
        let modulo = value.total_millis() & 0xffff_ffff;
        PositionVectorTimestamp(modulo as u32)
    }
}

impl From<PositionVectorTimestamp> for TAI2004 {
    fn from(value: PositionVectorTimestamp) -> Self {
        TAI2004::from_millis(value.0)
    }
}

impl ops::Sub<PositionVectorTimestamp> for PositionVectorTimestamp {
    type Output = PositionVectorTimestamp;

    fn sub(self, rhs: PositionVectorTimestamp) -> PositionVectorTimestamp {
        PositionVectorTimestamp(self.0 - rhs.0)
    }
}

/// A Geonetworking sequence number.
///
/// A sequence number is a monotonically incrementing integer modulo 2<sup>16</sup>.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SequenceNumber(pub u16);

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 as u16)
    }
}

impl ops::Add<usize> for SequenceNumber {
    type Output = SequenceNumber;

    fn add(self, rhs: usize) -> SequenceNumber {
        SequenceNumber(self.0.wrapping_add(rhs as u16))
    }
}

impl ops::Sub<usize> for SequenceNumber {
    type Output = SequenceNumber;

    fn sub(self, rhs: usize) -> SequenceNumber {
        SequenceNumber(self.0.wrapping_sub(rhs as u16))
    }
}

impl ops::AddAssign<usize> for SequenceNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

/* impl ops::Sub for SequenceNumber {
    type Output = usize;

    fn sub(self, rhs: SequenceNumber) -> usize {
        let result = self.0.wrapping_sub(rhs.0);
        if result < 0 {
            panic!("attempt to subtract sequence numbers with underflow")
        }
        result as usize
    }
} */

impl cmp::PartialOrd for SequenceNumber {
    fn partial_cmp(&self, other: &SequenceNumber) -> Option<cmp::Ordering> {
        self.0.wrapping_sub(other.0).partial_cmp(&0)
    }
}

enum_with_unknown! {
   /// Geonetworking station type.
   pub enum StationType(u16) {
        // Unknown = 0,
        Pedestrian = 1,
        Cyclist = 2,
        Moped = 3,
        Motorcycle = 4,
        PassengerCar = 5,
        Bus = 6,
        LightTruck = 7,
        HeavyTruck = 8,
        Trailer = 9,
        SpecialVehicle = 10,
        Tram = 11,
        LightVruVehicle = 12,
        Animal = 13,
        Agricultural = 14,
        RoadSideUnit = 15,
   }
}

impl fmt::Display for StationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StationType::Pedestrian => write!(f, "Pedestrian"),
            StationType::Cyclist => write!(f, "Cyclist"),
            StationType::Moped => write!(f, "Moped"),
            StationType::Motorcycle => write!(f, "Motorcycle"),
            StationType::PassengerCar => write!(f, "PassengerCar"),
            StationType::Bus => write!(f, "Bus"),
            StationType::LightTruck => write!(f, "LightTruck"),
            StationType::HeavyTruck => write!(f, "HeavyTruck"),
            StationType::Trailer => write!(f, "Trailer"),
            StationType::SpecialVehicle => write!(f, "SpecialVehicle"),
            StationType::Tram => write!(f, "Tram"),
            StationType::LightVruVehicle => write!(f, "LightVruVehicle"),
            StationType::Animal => write!(f, "Animal"),
            StationType::Agricultural => write!(f, "Agricultural"),
            StationType::RoadSideUnit => write!(f, "RoadSideUnit"),
            StationType::Unknown(id) => write!(f, "0x{:02x}", id),
        }
    }
}

#[cfg(feature = "asn1")]
use veloce_asn1::e_t_s_i__i_t_s__c_d_d::TrafficParticipantType;

#[cfg(feature = "asn1")]
impl From<TrafficParticipantType> for StationType {
    fn from(value: TrafficParticipantType) -> Self {
        match value.0 {
            0 => StationType::Unknown(0),
            1 => StationType::Pedestrian,
            2 => StationType::Cyclist,
            3 => StationType::Moped,
            4 => StationType::Motorcycle,
            5 => StationType::PassengerCar,
            6 => StationType::Bus,
            7 => StationType::LightTruck,
            8 => StationType::HeavyTruck,
            9 => StationType::Trailer,
            10 => StationType::SpecialVehicle,
            11 => StationType::Tram,
            12 => StationType::LightVruVehicle,
            13 => StationType::Animal,
            14 => StationType::Agricultural,
            15 => StationType::RoadSideUnit,
            _ => StationType::Unknown(value.0.into()),
        }
    }
}

/// An eight-octet Geonetworking address.
#[derive(Default, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Address(pub [u8; 8]);

mod field {
    use crate::wire::field::*;

    pub const M_ST_RES: Field = 0..2;
    pub const MAC_ADDR: Field = 2..8;
}

impl Address {
    /// Construct a Geonetworking address.
    /// The `reserved` field of the address is set to 0.
    pub fn new(manual: bool, station_type: StationType, mac_addr: MacAddress) -> Address {
        let mut addr = [0u8; 8];
        let m_st_r = u16::from(station_type) << 10;
        let m_st_r = if manual {
            m_st_r | 0x8000
        } else {
            m_st_r & !0x8000
        };

        NetworkEndian::write_u16(&mut addr[field::M_ST_RES], m_st_r);
        addr[field::MAC_ADDR].copy_from_slice(mac_addr.as_bytes());
        Address(addr)
    }

    /// Construct a Geonetworking address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not 8 octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return a Geonetworking address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the Geonetworking address has manual configuration.
    pub fn is_manual(&self) -> bool {
        NetworkEndian::read_u16(&self.0[field::M_ST_RES]) & 0x8000 != 0
    }

    /// Return the station type field.
    pub fn station_type(&self) -> StationType {
        let raw = NetworkEndian::read_u16(&self.0[field::M_ST_RES]);
        StationType::from((raw & 0x7c00) >> 10)
    }

    /// Sets the station type field.
    pub fn set_station_type(&mut self, station_type: StationType) {
        let raw = NetworkEndian::read_u16(&self.0[field::M_ST_RES]) & !0x7c00;
        let raw = raw | (u16::from(station_type) << 10);
        NetworkEndian::write_u16(&mut self.0[field::M_ST_RES], raw);
    }

    /// Return the reserved field.
    pub fn reserved(&self) -> u16 {
        NetworkEndian::read_u16(&self.0[field::M_ST_RES]) & 0x03ff
    }

    /// Return the mac address field.
    pub fn mac_addr(&self) -> MacAddress {
        MacAddress::from_bytes(&self.0[field::MAC_ADDR])
    }

    /// Sets the mac address field.
    pub fn set_mac_addr(&mut self, mac_address: MacAddress) {
        self.0[field::MAC_ADDR].copy_from_slice(mac_address.as_bytes());
        MacAddress::from_bytes(&self.0[field::MAC_ADDR]);
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Address  m={} st={} mid={}",
            self.is_manual(),
            self.station_type(),
            self.mac_addr()
        )
    }
}

/// The Geonetworking traffic class.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TrafficClass(pub u8);

impl TrafficClass {
    /// Construct a Geonetworking traffic class
    pub const fn new(store_carry_forward: bool, id: u8) -> TrafficClass {
        let mut tc = id & 0x3f;
        tc = if store_carry_forward {
            tc | 0x80
        } else {
            tc & !0x80
        };

        TrafficClass(tc)
    }

    /// Construct a Geonetworking traffic class from an octet.
    pub const fn from_byte(data: &u8) -> TrafficClass {
        TrafficClass(*data)
    }

    /// Return a Geonetworking traffic class as an octet.
    pub const fn as_byte(&self) -> &u8 {
        &self.0
    }

    /// Return the store carry forward field.
    pub const fn store_carry_forward(&self) -> bool {
        (self.0 & 0x80) != 0
    }

    /// Return the traffic class id field.
    pub const fn id(&self) -> u8 {
        self.0 & 0x3F
    }
}

impl fmt::Display for TrafficClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrafficClass  scf={} id={}",
            self.store_carry_forward(),
            self.id()
        )
    }
}

#[cfg(test)]
mod test {
    use super::{Address, StationType, TrafficClass};
    use crate::wire::ethernet::Address as MacAddress;

    #[test]
    fn test_address_new() {
        let addr = Address::new(
            false,
            StationType::PassengerCar,
            MacAddress([0x16, 0x33, 0x12, 0x28, 0x26, 0x45]),
        );

        assert_eq!(
            addr.as_bytes(),
            [0x14, 0x00, 0x16, 0x33, 0x12, 0x28, 0x26, 0x45]
        );
    }

    #[test]
    fn test_address_from_bytes() {
        let bytes: [u8; 8] = [0x84, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45];
        let addr = Address::from_bytes(&bytes);
        assert_eq!(addr.is_manual(), true);
        assert_eq!(addr.station_type(), StationType::Pedestrian);
        assert_eq!(addr.reserved(), 0);
        assert_eq!(
            addr.mac_addr(),
            MacAddress([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45])
        );
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_address_from_bytes_too_long() {
        let _ = Address::from_bytes(&[0u8; 15]);
    }

    #[test]
    fn test_traffic_class_new() {
        let tc = TrafficClass::new(true, 61);
        let raw: u8 = 0xbd;
        assert_eq!(tc.as_byte(), &raw);
    }

    #[test]
    fn test_traffic_class_from_byte() {
        let byte: u8 = 0xa5;
        let tc = TrafficClass::from_byte(&byte);
        assert_eq!(tc.store_carry_forward(), true);
        assert_eq!(tc.id(), 37);
    }

    #[test]
    fn test_change_station_type() {
        let mut addr = Address::new(
            true,
            StationType::RoadSideUnit,
            MacAddress([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]),
        );

        assert_eq!(addr.station_type(), StationType::RoadSideUnit);

        addr.set_station_type(StationType::PassengerCar);

        assert_eq!(addr.is_manual(), true);
        assert_eq!(addr.station_type(), StationType::PassengerCar);
        assert_eq!(
            addr.mac_addr(),
            MacAddress([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45])
        );
    }
}
