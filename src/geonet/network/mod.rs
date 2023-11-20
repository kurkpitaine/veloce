/*! Networking layer logic.

The `Network` module implements the Geonetworking protocol logic. It provides the maintenance of the
mandatory data structures of a Geonetworking router and handles the incoming and outgoing packets.
*/
pub mod core;
pub mod request;

use crate::geonet::common::geo_area::GeoArea;
use crate::geonet::time::Duration;
use crate::geonet::wire::GnProtocol;
use crate::geonet::wire::{GnAddress, GnTrafficClass};
pub use core::Config as GnCoreGonfig;
pub use core::Core as GnCore;
pub use request::{AddressableRequest, GeoZonableRequest, HoppableRequest};

use super::config;

/// Upper protocol type.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UpperProtocol {
    /// Upper protocol is ANY.
    Any,
    /// Upper protocol is BTP-A.
    BtpA,
    /// Upper protocol is BTP-B.
    BtpB,
    /// Upper protocol is IPv6.
    Ipv6,
}

impl From<GnProtocol> for UpperProtocol {
    fn from(value: GnProtocol) -> Self {
        match value {
            GnProtocol::Any => UpperProtocol::Any,
            GnProtocol::BtpA => UpperProtocol::BtpA,
            GnProtocol::BtpB => UpperProtocol::BtpB,
            GnProtocol::Ipv6 => UpperProtocol::Ipv6,
            GnProtocol::Unknown(_) => UpperProtocol::Any,
        }
    }
}

impl Into<GnProtocol> for UpperProtocol {
    fn into(self) -> GnProtocol {
        match self {
            UpperProtocol::Any => GnProtocol::Any,
            UpperProtocol::BtpA => GnProtocol::BtpA,
            UpperProtocol::BtpB => GnProtocol::BtpB,
            UpperProtocol::Ipv6 => GnProtocol::Ipv6,
        }
    }
}

/// Data request, aka `TRANSP_CORE.request` in ETSI
/// TS 103 836-4-1 v2.1.1 paragraph J.2.
/// Represents metadata associated with a packet transmit
/// request to the Geonetworking router.
/// Used in interfaces between the router and the upper layers.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct Request {
    /// Protocol above Geonetworking layer.
    pub upper_proto: UpperProtocol,
    /// Geonetworking transport type. See [`Transport`].
    pub transport: Transport,
    /// Access layer identifier.
    pub ali_id: (),
    /// ITS Application Identifier.
    pub its_aid: (),
    /// Maximum lifetime of the packet.
    pub max_lifetime: Duration,
    /// Maximum hop limit of the packet.
    pub max_hop_limit: u8,
    /// Traffic class.
    pub traffic_class: GnTrafficClass,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            upper_proto: UpperProtocol::Any,
            transport: Transport::TopoBroadcast,
            ali_id: Default::default(),
            its_aid: Default::default(),
            max_lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
        }
    }
}

/// Data indication, aka `TRANSP_CORE.indication` in ETSI
/// TS 103 836-4-1 v2.1.1 paragraph J.4.
/// Represents metadata associated with a received packet
/// after it has been processed by the Geonetworking router.
/// Used in interfaces between the router and the upper layers.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct Indication {
    /// Protocol above Geonetworking layer.
    pub upper_proto: UpperProtocol,
    /// Geonetworking transport type. See [`Transport`].
    pub transport: Transport,
    /// Access layer identifier.
    pub ali_id: (),
    /// ITS Application Identifier.
    pub its_aid: (),
    /// Certificate ID.
    pub cert_id: (),
    /// Remaining lifetime of the packet.
    pub rem_lifetime: Duration,
    /// Remaining hop limit of the packet.
    pub rem_hop_limit: u8,
    /// Traffic class.
    pub traffic_class: GnTrafficClass,
}

/// Types of packet transport.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum Transport {
    /// Unicast transport.
    Unicast(GnAddress),
    ///Anycast transport.
    Anycast(GeoArea),
    /// Broadcast transport.
    Broadcast(GeoArea),
    /// Single Hop Broadcast transport.
    SingleHopBroadcast,
    /// Topologically Scoped Broadcast transport.
    TopoBroadcast,
}

pub type UnicastReqMeta = AddressableRequest<UnicastTransport>;
pub type TopoScopedReqMeta = HoppableRequest<TopoBroadcastTransport>;
pub type SingleHopReqMeta = HoppableRequest<SingleHopBroadcastTransport>;
pub type GeoAnycastReqMeta = GeoZonableRequest<GeoAnycastTransport>;
pub type GeoBroadcastReqMeta = GeoZonableRequest<GeoBroadcastTransport>;

pub trait Addressable {}
pub trait GeoZonable {}
pub trait Hoppable {}

pub struct UnicastTransport {}
pub struct SingleHopBroadcastTransport {}
pub struct TopoBroadcastTransport {}
pub struct GeoBroadcastTransport {}
pub struct GeoAnycastTransport {}

impl Addressable for UnicastTransport {}
impl GeoZonable for GeoBroadcastTransport {}
impl GeoZonable for GeoAnycastTransport {}
impl Hoppable for SingleHopBroadcastTransport {}
impl Hoppable for TopoBroadcastTransport {}
