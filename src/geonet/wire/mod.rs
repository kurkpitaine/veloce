mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

pub mod ethernet;
pub mod geonet;

pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    Repr as EthernetRepr, HEADER_LEN as ETHERNET_HEADER_LEN,
};

pub use self::geonet::{
    anycast_broadcast_header::{
        Header as GeoAnycastHeader, Header as GeoBroadcastHeader, Repr as GeoAnycastRepr,
        Repr as GeoBroadcastRepr, HEADER_LEN as GEO_ANYCAST_HEADER_LEN,
        HEADER_LEN as GEO_BROADCAST_HEADER_LEN,
    },
    basic_header::{
        Header as BasicHeader, NextHeader as BHNextHeader, Repr as BasicHeaderRepr,
        HEADER_LEN as BASIC_HEADER_LEN,
    },
    beacon_header::{
        Header as BeaconHeader, Repr as BeaconHeaderRepr, HEADER_LEN as BEACON_HEADER_LEN,
    },
    common_header::{
        Header as CommonHeader, HeaderType as GeonetPacketType, NextHeader as CHNextHeader,
        Repr as CommonHeaderRepr, HEADER_LEN as COMMON_HEADER_LEN,
    },
    location_service_req_header::{
        Header as LocationServiceRequestHeader, Repr as LocationServiceRequestRepr,
        HEADER_LEN as LOCATION_SERVICE_REQ_HEADER_LEN,
    },
    long_position_vector::{
        Header as LongPositionVectorHeader, Repr as LongPositionVectorRepr,
        HEADER_LEN as LONG_POSITION_VECTOR_HEADER_LEN,
    },
    short_position_vector::{
        Header as ShortPositionVectorHeader, Repr as ShortPositionVectorRepr,
        HEADER_LEN as SHORT_POSITION_VECTOR_HEADER_LEN,
    },
    single_hop_header::{
        Header as SingleHopHeader, Repr as SingleHopHeaderRepr, HEADER_LEN as SINGLE_HOP_HEADER_LEN,
    },
    topo_header::{
        Header as TopoBroadcastHeader, Repr as TopoBroadcastRepr,
        HEADER_LEN as TOPO_BROADCAST_HEADER_LEN,
    },
    unicast_header::{
        Header as UnicastHeader, Header as LocationServiceReplyHeader, Repr as UnicastRepr,
        Repr as LocationServiceReplyRepr, HEADER_LEN as UNICAST_HEADER_LEN,
        HEADER_LEN as LOCATION_SERVICE_REP_HEADER_LEN,
    },
    Address as GnAddress, SequenceNumber, TrafficClass as GnTrafficClass,
};

pub use self::pc5::Layer2Address as PC5Address;

mod pc5 {
    use super::HardwareAddress;

    /// A PC5 Layer 2 address.
    #[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    pub struct Layer2Address(pub [u8; 3]);

    impl Layer2Address {
        /// The broadcast address.
        pub const BROADCAST: Layer2Address = Layer2Address([0xff; 3]);

        /// Construct a Layer 2 address from parts.
        pub const fn new(a0: u8, a1: u8, a2: u8) -> Layer2Address {
            Layer2Address([a0, a1, a2])
        }

        /// Query whether the address is an unicast address.
        pub fn is_unicast(&self) -> bool {
            !self.is_broadcast()
        }

        /// Query whether this address is the broadcast address.
        pub fn is_broadcast(&self) -> bool {
            *self == Self::BROADCAST
        }

        /// Construct a new Layer 2 Address from bytes.
        /// # Panics
        /// This method will panic if the provided slice is not 3 bytes long.
        pub fn from_bytes(a: &[u8]) -> Self {
            if a.len() == 3 {
                let mut b = [0u8; 3];
                b.copy_from_slice(a);
                Layer2Address(b)
            } else {
                panic!("Not a PC5 Layer 2 address");
            }
        }

        /// Return Layer 2 Address as bytes.
        pub const fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        /// Convert to an [`HardwareAddress`].
        ///
        /// Same as `.into()`, but works in `const`.
        pub const fn into_hardware_address(self) -> HardwareAddress {
            HardwareAddress::PC5(self)
        }
    }

    impl core::fmt::Display for Layer2Address {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "{:02x}:{:02x}:{:02x}", self.0[0], self.0[1], self.0[2])
        }
    }
}

/// Representation of an Hardware Address, such as Ethernet or PC5 Layer 2 ID.
pub enum HardwareAddress {
    /// Ethernet hardware address, known as MAC Address.
    Ethernet(EthernetAddress),
    /// LTE PC5 hardware address, aka Layer 2 ID.
    PC5(PC5Address),
}

impl HardwareAddress {
    /// Create an address wrapping an Ethernet address with the given octets.
    pub const fn ethernet(a0: u8, a1: u8, a2: u8, a3: u8, a4: u8, a5: u8) -> HardwareAddress {
        HardwareAddress::Ethernet(EthernetAddress::new(a0, a1, a2, a3, a4, a5))
    }

    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            HardwareAddress::Ethernet(addr) => addr.as_bytes(),
            HardwareAddress::PC5(addr) => addr.as_bytes(),
        }
    }

    /// Query wether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            HardwareAddress::Ethernet(addr) => addr.is_unicast(),
            HardwareAddress::PC5(addr) => addr.is_unicast(),
        }
    }

    /// Query wether the address is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            HardwareAddress::Ethernet(addr) => addr.is_broadcast(),
            HardwareAddress::PC5(addr) => addr.is_broadcast(),
        }
    }
}

impl core::fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HardwareAddress::Ethernet(addr) => write!(f, "{addr}"),
            HardwareAddress::PC5(addr) => write!(f, "{addr}"),
        }
    }
}

impl From<EthernetAddress> for HardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        HardwareAddress::Ethernet(addr)
    }
}

impl From<PC5Address> for HardwareAddress {
    fn from(addr: PC5Address) -> Self {
        HardwareAddress::PC5(addr)
    }
}