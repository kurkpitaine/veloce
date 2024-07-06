pub mod type_a;
pub mod type_b;

use core::fmt;

pub use type_a as a;
pub use type_a::Socket as SocketA;
pub use type_b as b;
pub use type_b::Socket as SocketB;

use crate::{
    config,
    network::Transport,
    time::Duration,
    wire::{GnAddress, GnTrafficClass},
};

#[cfg(feature = "proto-security")]
use crate::security::{permission::Permission, HashedId8};

/// Data request, aka `BTP-Data.request` in ETSI
/// EN 302 636-5-1 v2.2.1 paragraph A.2.
/// Represents metadata associated with a packet transmit
/// request to the BTP socket.
/// Used in interfaces between a BTP socket and the
/// user application layers.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone)]
pub struct Request {
    /// Geonetworking transport type. See [`Transport`].
    pub transport: Transport,
    /// Access layer identifier.
    pub ali_id: (),
    #[cfg(feature = "proto-security")]
    /// ITS Application Identifier.
    pub its_aid: Permission,
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
            transport: Transport::TopoBroadcast,
            ali_id: Default::default(),
            #[cfg(feature = "proto-security")]
            its_aid: Default::default(),
            max_lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
        }
    }
}

/// Data indication, aka `BTP-Data.indication` in ETSI
/// EN 302 636-5-1 v2.2.1 paragraph A.3.
/// Represents metadata associated with a packet after
/// it has been processed by the Geonetworking router
/// and the BTP layer.
/// Used in interfaces between a BTP socket and the
/// user application layers.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone)]
pub struct Indication {
    /// Geonetworking transport type. See [`Transport`].
    pub transport: Transport,
    /// Access layer identifier.
    pub ali_id: (),
    #[cfg(feature = "proto-security")]
    /// ITS Application Identifier.
    pub its_aid: Permission,
    #[cfg(feature = "proto-security")]
    /// Certificate ID.
    pub cert_id: HashedId8,
    /// Remaining lifetime of the packet.
    pub rem_lifetime: Duration,
    /// Remaining hop limit of the packet.
    pub rem_hop_limit: u8,
    /// Traffic class.
    pub traffic_class: GnTrafficClass,
}

/// Error returned by [`Socket::bind`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BindError {
    InvalidState,
    Unaddressable,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BindError {}

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    Unaddressable,
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecvError {
    Exhausted,
    Truncated,
}

impl core::fmt::Display for RecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecvError {}

/// A Geonetworking BTP-A endpoint address.
///
/// `Endpoint` always fully specifies both the address and the port.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Endpoint {
    pub addr: GnAddress,
    pub port: u16,
}

impl Endpoint {
    /// Create an endpoint address from given address and port.
    pub const fn new(addr: GnAddress, port: u16) -> Endpoint {
        Endpoint { addr: addr, port }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Endpoint {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{:?}:{=u16}", self.addr, self.port);
    }
}

impl<T: Into<GnAddress>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint {
            addr: addr.into(),
            port,
        }
    }
}

/// A Geonetworking BTP-A endpoint address for listening.
///
/// In contrast with [`Endpoint`], `ListenEndpoint` allows not specifying the address,
/// in order to listen on a given port at all our addresses.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct ListenEndpoint {
    pub addr: Option<GnAddress>,
    pub port: u16,
}

impl ListenEndpoint {
    /// Query whether the endpoint has a specified address and port.
    pub const fn is_specified(&self) -> bool {
        self.addr.is_some() && self.port != 0
    }
}

impl fmt::Display for ListenEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(addr) = self.addr {
            write!(f, "{}:{}", addr, self.port)
        } else {
            write!(f, "*:{}", self.port)
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ListenEndpoint {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{:?}:{=u16}", self.addr, self.port);
    }
}

impl From<u16> for ListenEndpoint {
    fn from(port: u16) -> ListenEndpoint {
        ListenEndpoint { addr: None, port }
    }
}

impl From<Endpoint> for ListenEndpoint {
    fn from(endpoint: Endpoint) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(endpoint.addr),
            port: endpoint.port,
        }
    }
}

impl<T: Into<GnAddress>> From<(T, u16)> for ListenEndpoint {
    fn from((addr, port): (T, u16)) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(addr.into()),
            port,
        }
    }
}
