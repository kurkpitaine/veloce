use crate::geonet::config::{GN_LOC_TABLE_ENTRY_COUNT, GN_LOC_TABLE_ENTRY_LIFETIME};
use crate::geonet::time::Instant;
use crate::geonet::wire::EthernetAddress as MacAddress;
use crate::geonet::wire::GnAddress;
use crate::geonet::wire::LongPositionVectorRepr as LongPositionVector;
use heapless::LinearMap;

/// A location table entry.
///
/// A neighbor mapping translates from a Geonetworking address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone, Copy)]
pub struct LocationTableEntry {
    /// Geonetworking address of the station.
    geonet_addr: GnAddress,
    /// Geonetworking protocol version of the station.
    geonet_version: u8,
    /// Geonetworking Long Position Vector of the station.
    position_vector: LongPositionVector,
    /// Flag indicating if the Location Service is pending for the station.
    ls_pending: bool,
    /// Flag indicating if the station is a neighbour.
    is_neighbour: bool,
    /// Duplicate packet list received from the station.
    dup_packet_list: (),
    /// Packet data rate as Exponential Moving Average.
    packet_data_rate: f32,
    /// Extensions for the station.
    extensions: Option<()>,
    /// Time point at which this entry expires.
    expires_at: Instant,
}

/// Location Table backed by a map.
pub struct LocationTable {
    storage: LinearMap<MacAddress, LocationTableEntry, GN_LOC_TABLE_ENTRY_COUNT>,
}

impl LocationTable {
    /// Create a Location Table.
    pub fn new() -> Self {
        Self {
            storage: LinearMap::new(),
        }
    }

    /// Removes all the entries of the Location Table.
    pub fn flush(&mut self) {
        self.storage.clear()
    }
}
