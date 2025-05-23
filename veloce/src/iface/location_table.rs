use crate::common::geo_area::GeoPosition;
use crate::config::{
    GN_DPL_LENGTH, GN_LOC_TABLE_ENTRY_COUNT, GN_LOC_TABLE_ENTRY_LIFETIME,
    GN_MAX_PACKET_DATA_RATE_EMA_BETA,
};

#[cfg(feature = "medium-ieee80211p")]
use crate::{phy::ChannelBusyRatio, time::TAI2004, types::Power};

use crate::time::Instant;
use crate::wire::geonet::PositionVectorTimestamp;
use crate::wire::GnAddress;
use crate::wire::{
    EthernetAddress as MacAddress, LongPositionVectorRepr as LongPositionVector, SequenceNumber,
};
use heapless::{FnvIndexMap, HistoryBuffer, Vec};
pub use uom::si::f64::InformationRate;
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
    #[allow(unused)]
    pub extensions: Option<LocationTableAnyExtension>,
    /// Time point at which this entry expires.
    pub expires_at: Instant,
}

impl LocationTableEntry {
    /// Returns the position for the given station.
    pub fn geo_position(&self) -> GeoPosition {
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
            let instant_pdr = packet_size as f64 / measure_period.secs() as f64;
            self.packet_data_rate *= GN_MAX_PACKET_DATA_RATE_EMA_BETA;
            self.packet_data_rate += InformationRate::new::<byte_per_second>(
                (1.0 - GN_MAX_PACKET_DATA_RATE_EMA_BETA) * instant_pdr,
            );
        }
    }

    /// Updates the `is_neighbour` flag for the given station.
    #[allow(unused)]
    pub fn update_neighbour_flag(&mut self, neighbour_flag: bool) {
        self.is_neighbour = neighbour_flag;
    }

    /// Check if `seq_number` is present in the Duplicate Packet List.
    /// `seq_number` is inserted in the Duplicate Packet List if not found.
    pub fn check_duplicate(&mut self, seq_number: SequenceNumber) -> bool {
        let duplicate = self
            .dup_packet_list
            .oldest_ordered()
            .any(|s| *s == seq_number);

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
    #[allow(unused)]
    pub fn find_mut(&mut self, ll_addr: &MacAddress) -> Option<&mut LocationTableEntry> {
        self.storage.get_mut(ll_addr)
    }

    /// Updates or insert a `LocationTableEntry` for the given station.
    /// Geonetworking address and Link Layer address are carried inside `position_vector`.
    /// Returns a reference on the inserted/updated element.
    #[allow(unused)]
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

    /// Query whether the Location Table contains at least one entry where
    /// the ìs_neighbour` flag is set.
    pub fn has_neighbour(&self) -> bool {
        self.storage.iter().any(|(_, v)| v.is_neighbour)
    }

    /// Performs the duplicate packet detection for an incoming packet from `address` with sequence number `seq_number`.
    /// In case `address` in unknown, `None` is returned.
    pub fn duplicate_packet_detection(
        &mut self,
        address: GnAddress,
        seq_number: SequenceNumber,
    ) -> Option<bool> {
        self.storage
            .get_mut(&address.mac_addr())
            .map(|entry| entry.check_duplicate(seq_number))
    }

    /// Removes all the entries of the Location Table.
    #[cfg(feature = "conformance")]
    pub fn clear(&mut self) {
        self.storage.clear();
    }

    /// Returns the valid (in time) local an one hop CBR values.
    #[cfg(feature = "medium-ieee80211p")]
    pub fn local_one_hop_cbr_values(
        &self,
        timestamp: Instant,
    ) -> Vec<(ChannelBusyRatio, ChannelBusyRatio), GN_LOC_TABLE_ENTRY_COUNT> {
        use crate::config::GN_LIFETIME_LOC_TE_X;

        // Filter entries without extension and expired values.
        self.storage
            .values()
            .filter_map(|e| match &e.extensions {
                Some(ext) => {
                    let g5_ext = ext.g5_extension_or_panic();
                    if g5_ext.local_update_tst + GN_LIFETIME_LOC_TE_X > timestamp {
                        Some((g5_ext.local_cbr, g5_ext.one_hop_cbr))
                    } else {
                        None
                    }
                }
                None => None,
            })
            .collect()
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

/// Location table entry extension.
#[derive(Debug, Clone)]
pub enum LocationTableAnyExtension {
    /// No extension.
    #[allow(unused)]
    None,
    /// DCC G5 Extension.
    #[cfg(feature = "medium-ieee80211p")]
    G5(LocationTableG5Extension),
}

impl LocationTableAnyExtension {
    #[cfg(feature = "medium-ieee80211p")]
    pub fn g5_extension_or_panic(&self) -> LocationTableG5Extension {
        match self {
            LocationTableAnyExtension::G5(e) => e.to_owned(),
            #[allow(unreachable_patterns)]
            _ => panic!("Location Table extension is not a LocationTableG5Extension type."),
        }
    }
}

#[cfg(feature = "medium-ieee80211p")]
impl From<LocationTableG5Extension> for LocationTableAnyExtension {
    fn from(value: LocationTableG5Extension) -> Self {
        LocationTableAnyExtension::G5(value)
    }
}

/// Decentralized Congestion Control for G5 (802.11p) Medium Location Table extension.
#[cfg(feature = "medium-ieee80211p")]
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct LocationTableG5Extension {
    /// Local timestamp of the last update of this extension.
    pub local_update_tst: Instant,
    /// Station source position vector timestamp of last received
    /// SHB packet.
    pub station_pv_tst: TAI2004,
    /// Local CBR.
    pub local_cbr: ChannelBusyRatio,
    /// Maximum CBR measurement from 1-hop reachable neighbors.
    pub one_hop_cbr: ChannelBusyRatio,
    /// Transmit power of the packet that updated the entry.
    pub tx_power: Power,
    /// Reception power of the packet that updated the entry.
    pub rx_power: Option<Power>,
}
