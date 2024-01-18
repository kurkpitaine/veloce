pub mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

pub mod btp;
pub mod ethernet;
pub mod etsi_its;
pub mod geonet;
pub mod ieee80211;
pub mod llc;
pub mod nxp;
pub mod pretty_print;
pub mod uppertester;

use core::fmt;

pub use ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    Repr as EthernetRepr, HEADER_LEN as ETHERNET_HEADER_LEN,
};

pub use geonet::{
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
        Header as CommonHeader, HeaderType as GeonetPacketType, Repr as CommonHeaderRepr,
        HEADER_LEN as COMMON_HEADER_LEN,
    },
    geonet::{
        GeonetBeacon, GeonetGeoAnycast, GeonetGeoBroadcast, GeonetLocationServiceReply,
        GeonetLocationServiceRequest, GeonetSingleHop, GeonetTopoBroadcast, GeonetUnicast,
        Protocol as GnProtocol, Repr as GeonetRepr,
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
    Address as GnAddress, SequenceNumber, StationType, TrafficClass as GnTrafficClass,
};

pub use ieee80211::{
    Header as Ieee80211Frame, Repr as Ieee80211Repr, HEADER_LEN as IEEE_80211_HEADER_LEN,
};

pub use llc::{
    Header as LlcFrame, Repr as LlcRepr, HEADER_LEN as LLC_HEADER_LEN,
};

pub use btp::{
    ports,
    type_a::{Header as BtpAHeader, Repr as BtpARepr, HEADER_LEN as BTP_A_HEADER_LEN},
    type_b::{Header as BtpBHeader, Repr as BtpBRepr, HEADER_LEN as BTP_B_HEADER_LEN},
};

pub use uppertester::{
    geonet::{
        UtGnEventInd, UtGnTriggerGeoBroadcast, UtGnTriggerGeoBroadcast as UtGnTriggerGeoAnycast,
        UtGnTriggerGeoUnicast, UtGnTriggerShb, UtGnTriggerTsb,
    },
    MessageType as UtMessageType, Packet as UtPacket, Result as UtResult, UtChangePosition,
    UtInitialize,
};

pub use nxp::{
    rx_packet::RxPacketRepr as NxpRxPacketRepr, tx_packet::TxPacketRepr as NxpTxPacketRepr,
    Header as NxpHeader,
};

/// Parsing a packet failed.
///
/// Either it is malformed, or it is not supported by Veloce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Error;

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire::Error")
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub use self::pc5::Layer2Address as PC5Address;

use super::phy::Medium;

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
#[cfg(any(
    feature = "medium-ethernet",
    feature = "medium-ieee80211p",
    feature = "medium-pc5"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HardwareAddress {
    /// Ethernet hardware address, known as MAC Address.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
    Ethernet(EthernetAddress),
    /// LTE PC5 hardware address, aka Layer 2 ID.
    #[cfg(feature = "medium-pc5")]
    PC5(PC5Address),
}

impl HardwareAddress {
    /// Create an address wrapping an Ethernet address with the given octets.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
    pub const fn ethernet(a0: u8, a1: u8, a2: u8, a3: u8, a4: u8, a5: u8) -> HardwareAddress {
        HardwareAddress::Ethernet(EthernetAddress::new(a0, a1, a2, a3, a4, a5))
    }

    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
            HardwareAddress::Ethernet(addr) => addr.as_bytes(),
            #[cfg(feature = "medium-pc5")]
            HardwareAddress::PC5(addr) => addr.as_bytes(),
        }
    }

    /// Query wether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
            HardwareAddress::Ethernet(addr) => addr.is_unicast(),
            #[cfg(feature = "medium-pc5")]
            HardwareAddress::PC5(addr) => addr.is_unicast(),
        }
    }

    /// Query wether the address is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
            HardwareAddress::Ethernet(addr) => addr.is_broadcast(),
            #[cfg(feature = "medium-pc5")]
            HardwareAddress::PC5(addr) => addr.is_broadcast(),
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
    pub(crate) fn ethernet_or_panic(&self) -> EthernetAddress {
        match self {
            HardwareAddress::Ethernet(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("HardwareAddress is not Ethernet."),
        }
    }

    #[cfg(feature = "medium-pc5")]
    #[allow(unused)]
    pub(crate) fn pc5_or_panic(&self) -> PC5Address {
        match self {
            HardwareAddress::PC5(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("HardwareAddress is not PC5."),
        }
    }

    #[inline]
    pub(crate) fn medium(&self) -> Medium {
        match self {
            #[cfg(feature = "medium-pc5")]
            HardwareAddress::PC5(_) => Medium::PC5,
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(_) => Medium::Ethernet,
            #[cfg(all(feature = "medium-ieee80211p", not(feature = "medium-ethernet")))]
            HardwareAddress::Ethernet() => Medium::Ieee80211p,
        }
    }
}

#[cfg(any(
    feature = "medium-ethernet",
    feature = "medium-ieee80211p",
    feature = "medium-pc5"
))]
impl core::fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
            HardwareAddress::Ethernet(addr) => write!(f, "{addr}"),
            #[cfg(feature = "medium-pc5")]
            HardwareAddress::PC5(addr) => write!(f, "{addr}"),
        }
    }
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
impl From<EthernetAddress> for HardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        HardwareAddress::Ethernet(addr)
    }
}

#[cfg(feature = "medium-pc5")]
impl From<PC5Address> for HardwareAddress {
    fn from(addr: PC5Address) -> Self {
        HardwareAddress::PC5(addr)
    }
}
