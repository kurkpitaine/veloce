/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod interface;
//mod interface_set;
#[cfg(feature = "proto-geonet")]
mod location_service;
#[cfg(feature = "proto-geonet")]
mod location_table;
mod socket_set;

mod v2x_packet;

pub use self::interface::{
    Config, Interface, InterfaceInner as Context, InterfaceServices as ContextMeta,
};
pub use self::socket_set::{SocketHandle, SocketSet, SocketStorage};
pub(crate) use self::v2x_packet::{GeonetPacket, GeonetPayload};
