use crate::geonet::common::geo_area::GeoPosition;
use crate::geonet::config::{
    GN_DPL_LENGTH, GN_LOC_TABLE_ENTRY_COUNT, GN_LOC_TABLE_ENTRY_LIFETIME,
    GN_MAX_PACKET_DATA_RATE_EMA_BETA,
};

use crate::geonet::time::Instant;
use crate::geonet::wire::geonet::PositionVectorTimestamp;
use crate::geonet::wire::GnAddress;
use crate::geonet::wire::{
    EthernetAddress as MacAddress, LongPositionVectorRepr as LongPositionVector, SequenceNumber,
};
use heapless::{FnvIndexMap, HistoryBuffer, Vec};
pub use uom::si::f32::InformationRate;
pub use uom::si::information_rate::{byte_per_second, kilobit_per_second};

use super::location_service::LocationServiceRequestHandle;

/// A location table entry.
///
/// A neighbor mapping translates from a Geonetworking address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone)]
pub(super) struct LocationTableEntry {
    /// Geonetworking Long Position Vector of the station.
    /// Contains the Geonetworking address.
    pub position_vector: LongPositionVector,
    /// Handle of the Location Service request for the station.
    pub ls_pending: Option<LocationServiceRequestHandle>,
    /// Flag indicating if the station is a neighbour.
    pub is_neighbour: bool,
    /// Duplicate packet list received from the station.
    pub dup_packet_list: HistoryBuffer<SequenceNumber, GN_DPL_LENGTH>,
    /// Packet data rate as Exponential Moving Average.
    pub packet_data_rate: InformationRate,
    /// Packet data rate last update time point.
    pub packet_data_rate_updated_at: Instant,
    /// Extensions for the station.
    pub extensions: Option<()>,
    /// Time point at which this entry expires.
    pub expires_at: Instant,
}

impl LocationTableEntry {
    /// Returns the position for the given station.
    pub fn position(&self) -> GeoPosition {
        GeoPosition {
            latitude: self.position_vector.latitude,
            longitude: self.position_vector.longitude,
        }
    }

    /// Updates the position vector for the given station.
    /// Applies the algorithm defined in ETSI 103 836-4-1 V2.1.1 clause C.2.
    pub fn update_position_vector(
        &mut self,
        position_vector: &LongPositionVector,
        timestamp: Instant,
    ) -> bool {
        if compare_position_vector_freshness(position_vector, &self.position_vector) {
            self.position_vector = *position_vector;
            self.expires_at = timestamp + GN_LOC_TABLE_ENTRY_LIFETIME;
            return true;
        }

        false
    }

    /// Updates the Packet Data Rate for the given station.
    pub fn update_pdr(&mut self, packet_size: usize, timestamp: Instant) {
        if timestamp > self.packet_data_rate_updated_at {
            let measure_period = timestamp - self.packet_data_rate_updated_at;
            let instant_pdr = packet_size as f32 / measure_period.secs() as f32;
            self.packet_data_rate *= GN_MAX_PACKET_DATA_RATE_EMA_BETA;
            self.packet_data_rate += InformationRate::new::<byte_per_second>(
                (1.0 - GN_MAX_PACKET_DATA_RATE_EMA_BETA) * instant_pdr,
            );
        }
    }

    /// Updates the `is_neighbour` flag for the given station.
    pub fn update_neighbour_flag(&mut self, neighbour_flag: bool) {
        self.is_neighbour = neighbour_flag;
    }

    /// Check if `seq_number` is present in the Duplicate Packet List.
    /// `seq_number` is inserted in the Duplicate Packet List if not found.
    pub fn check_duplicate(&mut self, seq_number: SequenceNumber) -> bool {
        let duplicate = self
            .dup_packet_list
            .oldest_ordered()
            .find(|s| **s == seq_number)
            .is_some();

        if !duplicate {
            self.dup_packet_list.write(seq_number);
        }

        duplicate
    }
}

/// Location Table backed by a map.
#[derive(Debug)]
pub(super) struct LocationTable {
    storage: FnvIndexMap<MacAddress, LocationTableEntry, GN_LOC_TABLE_ENTRY_COUNT>,
}

impl LocationTable {
    /// Create a Location Table.
    pub const fn new() -> Self {
        Self {
            storage: FnvIndexMap::new(),
        }
    }

    /// Remove the LocationTable entry for the given `ll_addr` [`MacAddress`].
    /// Return `None` if `ll_addr` is not in the LocationTable.
    pub fn remove(&mut self, ll_addr: &MacAddress) -> Option<LocationTableEntry> {
        self.storage.remove(ll_addr)
    }

    /// Finds the LocationTable entry for the given `ll_addr` [`MacAddress`].
    /// Returns a reference on the element.
    pub fn find(&self, ll_addr: &MacAddress) -> Option<&LocationTableEntry> {
        self.storage.get(ll_addr)
    }

    /// Finds the LocationTable entry for the given `ll_addr` [`MacAddress`].
    /// Returns a mutable reference on the element.
    pub fn find_mut(&mut self, ll_addr: &MacAddress) -> Option<&mut LocationTableEntry> {
        self.storage.get_mut(ll_addr)
    }

    /// Updates or insert a `LocationTableEntry` for the given station.
    /// Geonetworking address and Link Layer address are carried inside `position_vector`.
    /// Returns a reference on the inserted/updated element.
    pub fn update(
        &mut self,
        timestamp: Instant,
        position_vector: &LongPositionVector,
    ) -> &LocationTableEntry {
        self.update_mut(timestamp, position_vector)
    }

    /// Updates or insert a `LocationTableEntry` for the given station.
    /// Geonetworking address and Link Layer address are carried inside `position_vector`.
    /// Returns a mutable reference on the inserted/updated element.
    pub fn update_mut(
        &mut self,
        timestamp: Instant,
        position_vector: &LongPositionVector,
    ) -> &mut LocationTableEntry {
        if let Some(entry) = self.storage.get_mut(&position_vector.address.mac_addr()) {
            /* Entry exists, update it with the given position vector. */
            entry.update_position_vector(position_vector, timestamp);
        } else {
            /* Entry does not exist. Insert a new one inside storage. */
            let new_entry = LocationTableEntry {
                position_vector: *position_vector,
                ls_pending: None,
                is_neighbour: false,
                dup_packet_list: HistoryBuffer::new(),
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
                .insert(position_vector.address.mac_addr(), new_entry)
                .ok();
        };

        self.storage
            .get_mut(&position_vector.address.mac_addr())
            .unwrap()
    }

    /// Updates only if the the provided function returns true.
    /// If the station does not exists, a `LocationTableEntry` in inserted.
    /// Geonetworking address and Link Layer address are carried inside `position_vector`.
    /// Returns a reference on the inserted/updated element.
    pub fn update_if<F>(
        &mut self,
        timestamp: Instant,
        position_vector: &LongPositionVector,
        f: F,
    ) -> &LocationTableEntry
    where
        F: FnMut(&mut LocationTableEntry) -> bool,
    {
        self.update_if_mut(timestamp, position_vector, f)
    }

    /// Updates only if the the provided function returns true.
    /// If the station does not exists, a `LocationTableEntry` in inserted.
    /// Geonetworking address and Link Layer address are carried inside `position_vector`.
    /// Returns a reference on the inserted/updated element.
    pub fn update_if_mut<F>(
        &mut self,
        timestamp: Instant,
        position_vector: &LongPositionVector,
        mut f: F,
    ) -> &mut LocationTableEntry
    where
        F: FnMut(&mut LocationTableEntry) -> bool,
    {
        if let Some(entry) = self.storage.get_mut(&position_vector.address.mac_addr()) {
            if f(entry) {
                entry.update_position_vector(position_vector, timestamp);
            }
        } else {
            /* Entry does not exist. Insert a new one inside storage. */
            let new_entry = LocationTableEntry {
                position_vector: *position_vector,
                ls_pending: None,
                is_neighbour: false,
                dup_packet_list: HistoryBuffer::new(),
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
                .insert(position_vector.address.mac_addr(), new_entry)
                .ok();
        }

        self.storage
            .get_mut(&position_vector.address.mac_addr())
            .unwrap()
    }

    /// Get the Location Table Entries where the `is_neighbour` flag is set.
    pub fn neighbour_list(&self) -> Vec<LocationTableEntry, GN_LOC_TABLE_ENTRY_COUNT> {
        self.storage
            .values()
            .filter(|e| e.is_neighbour)
            .cloned()
            .collect()
    }

    /// Query wether the Location Table contains at least one entry where
    /// the ìs_neighbour` flag is set.
    pub fn has_neighbour(&self) -> bool {
        self.storage.iter().find(|(_, v)| v.is_neighbour).is_some()
    }

    /// Performs the duplicate packet detection for an incoming packet from `address` with sequence number `seq_number`.
    /// In case `address` in unknown, `None` is returned.
    pub fn duplicate_packet_detection(
        &mut self,
        address: GnAddress,
        seq_number: SequenceNumber,
    ) -> Option<bool> {
        if let Some(entry) = self.storage.get_mut(&address.mac_addr()) {
            // Address found, execute duplicate packet detection.
            Some(entry.check_duplicate(seq_number))
        } else {
            // Address not found
            None
        }
    }

    /// Removes all the entries of the Location Table.
    pub fn flush(&mut self) {
        self.storage.clear();
    }
}

/// Determine if `left` [`LongPositionVector`] is more fresh than `right` [`LongPositionVector`].
#[inline]
pub fn compare_position_vector_freshness(
    left: &LongPositionVector,
    right: &LongPositionVector,
) -> bool {
    let tst_left = left.timestamp;
    let tst_right = right.timestamp;
    let half_tst_max = PositionVectorTimestamp(0x7fff_ffff);
    (tst_left > tst_right) && ((tst_left - tst_right) <= half_tst_max)
        || ((tst_right > tst_left) && ((tst_right - tst_left) > half_tst_max))
}
