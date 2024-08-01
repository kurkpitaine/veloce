/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

#[cfg(feature = "proto-geonet")]
mod congestion;

mod interface;
#[cfg(feature = "proto-geonet")]
mod location_service;
#[cfg(feature = "proto-geonet")]
mod location_table;
mod socket_set;

pub(crate) mod packet;

pub(crate) use self::congestion::Congestion;
pub use self::interface::{
    congestion::CongestionControl, Config, Interface, InterfaceInner as Context,
};

#[cfg(all(test, feature = "proto-security", feature = "socket-denm"))]
pub(crate) use self::interface::DecapContext;
pub(crate) use self::interface::InterfaceContext as ContextMeta;
pub use self::socket_set::{SocketHandle, SocketSet, SocketStorage};
