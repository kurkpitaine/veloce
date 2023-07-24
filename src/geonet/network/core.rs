/// This module implements the GN Core functions, ie:
/// - Geonetworking Address
/// - Maintenance of the Ego Position Vector
use crate::geonet::config;
use crate::geonet::rand::Rand;
use crate::geonet::wire::{EthernetAddress, HardwareAddress};
use crate::geonet::wire::{GnAddress, LongPositionVectorRepr as LongPositionVector};

use super::access_handler::AccessHandler;

/// Geonetworking Core.
pub struct Core<'a> {
    /// Ego Position Vector which includes the local Geonetworking address.
    ego_position_vector: LongPositionVector,
    /// List of access handlers.
    access_handler: AccessHandler<'a>,
}

impl Core<'_> {
    /// Sets the Geonetworking address.
    pub fn set_address(&mut self, address: GnAddress) {
        self.ego_position_vector.address = address;
    }

    /// Performs the Duplicate Address Detection algorithm specified in
    /// ETSI TS 103 836-4-1 V2.1.1 chapter 10.2.1.5.
    pub fn duplicate_address_detection(&mut self, sender: HardwareAddress, source: GnAddress) {
        // Duplicate address detection is only applied for Auto.
        if let config::GnAddrConfMethod::Auto = config::GN_LOCAL_ADDR_CONF_METHOD {
            let ego_addr = self.ego_position_vector.address;
            let sender_addr = match sender {
                HardwareAddress::Ethernet(a) => a,
                HardwareAddress::PC5(b) => b.into(),
            };

            if ego_addr.mac_addr() == sender_addr || ego_addr == source {
                // Addresses are equal, we have to generate a new Mac Address.
                // We use the timestamp of the Ego Position Vector as a seed for the generator.
                let mut generator = Rand::new(self.ego_position_vector.timestamp.secs() as u64);
                // TODO : check which access technology we are using to generate a correct Mac Address for PC5.
                let new_address = EthernetAddress::from_bytes(&generator.rand_mac_addr());
                self.ego_position_vector.address.set_mac_addr(new_address);
            }
        }
    }
}
