use crate::geonet::config::{
    GN_LOC_TABLE_ENTRY_COUNT, GN_LOC_TABLE_ENTRY_LIFETIME, GN_MAX_PACKET_DATA_RATE_EMA_BETA,
};
use crate::geonet::time::Instant;
use crate::geonet::wire::EthernetAddress as MacAddress;
use crate::geonet::wire::GnAddress;
use crate::geonet::wire::LongPositionVectorRepr as LongPositionVector;
use crate::geonet::{Error, Result};
use heapless::FnvIndexMap;
pub use uom::si::f32::InformationRate;
pub use uom::si::information_rate::{byte_per_second, kilobit_per_second};

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
    packet_data_rate: InformationRate,
    /// Packet data rate last update time point.
    packet_data_rate_updated_at: Instant,
    /// Extensions for the station.
    extensions: Option<()>,
    /// Time point at which this entry expires.
    expires_at: Instant,
}

/// Location Table backed by a map.
pub struct LocationTable {
    storage: FnvIndexMap<MacAddress, LocationTableEntry, GN_LOC_TABLE_ENTRY_COUNT>,
}

impl LocationTable {
    /// Create a Location Table.
    pub fn new() -> Self {
        Self {
            storage: FnvIndexMap::new(),
        }
    }

    /// Updates or insert a `LocationTableEntry` for the given station.
    /// Geonetworking address and Link Layer address are carried inside `position_vector`.
    pub fn update(
        &mut self,
        timestamp: Instant,
        position_vector: LongPositionVector,
        protocol_version: u8,
    ) {
        if let Some(entry) = self.storage.get_mut(&position_vector.address.mac_addr()) {
            /* Entry exists, update it with the given position vector. */
            entry.position_vector = position_vector;
            entry.expires_at = timestamp + GN_LOC_TABLE_ENTRY_LIFETIME;
        } else {
            /* Entry does not exist. Insert a new one inside storage. */
            let mut entry = LocationTableEntry {
                geonet_addr: position_vector.address,
                geonet_version: protocol_version,
                position_vector,
                ls_pending: false,
                is_neighbour: false,
                dup_packet_list: (),
                packet_data_rate: InformationRate::new::<kilobit_per_second>(0.0),
                packet_data_rate_updated_at: timestamp,
                extensions: None,
                expires_at: timestamp + GN_LOC_TABLE_ENTRY_LIFETIME,
            };

            /* Check if storage is full */
            if self.storage.len() == self.storage.capacity() {
                /* Storage is full: we remove the oldest entry. */
                let old_addr = match self
                    .storage
                    .iter()
                    .min_by_key(|(_, neighbour)| neighbour.expires_at)
                {
                    Some((a, _)) => *a,
                    None => unreachable!(),
                };

                self.storage.remove(&old_addr);
            }

            /* Insert the entry in the storage */
            self.storage
                .insert(position_vector.address.mac_addr(), entry)
                .ok();
        }
    }

    /// Updates the Packet Data Rate for the given station.
    pub fn update_pdr(
        &mut self,
        position_vector: LongPositionVector,
        packet_size: usize,
        timestamp: Instant,
    ) -> Result<()> {
        if let Some(entry) = self.storage.get_mut(&position_vector.address.mac_addr()) {
            if timestamp > entry.packet_data_rate_updated_at {
                let measure_period = timestamp - entry.packet_data_rate_updated_at;
                let instant_pdr = packet_size as f32 / measure_period.secs() as f32;
                entry.packet_data_rate *= GN_MAX_PACKET_DATA_RATE_EMA_BETA;
                entry.packet_data_rate += InformationRate::new::<byte_per_second>(
                    (1.0 - GN_MAX_PACKET_DATA_RATE_EMA_BETA) * instant_pdr,
                );
            }
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Updates the Packet Data Rate for the given station.
    pub fn update_neighbour_flag(
        &mut self,
        position_vector: LongPositionVector,
        neighbour_flag: bool,
    ) -> Result<()> {
        if let Some(entry) = self.storage.get_mut(&position_vector.address.mac_addr()) {
            entry.is_neighbour = neighbour_flag;
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Removes all the entries of the Location Table.
    pub fn flush(&mut self) {
        self.storage.clear();
    }
}
