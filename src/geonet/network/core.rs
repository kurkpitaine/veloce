/// This module implements the GN Core functions, ie:
/// - Geonetworking Address
/// - Maintenance of the Ego Position Vector
use crate::geonet::common::area::GeoPosition;
use crate::geonet::config::GnAddrConfMethod;
use crate::geonet::rand::Rand;
use crate::geonet::time::Instant;
use crate::geonet::types::{degree, kilometer_per_hour, Heading, Latitude, Longitude, Speed};
use crate::geonet::wire::{
    EthernetAddress, GnAddress, LongPositionVectorRepr as LongPositionVector,
};

// For tests only. Duplicate Address Detection only works with Auto mode.
#[cfg(test)]
const GN_LOCAL_ADDR_CONF_METHOD: GnAddrConfMethod = GnAddrConfMethod::Auto;
#[cfg(not(test))]
use crate::geonet::config::GN_LOCAL_ADDR_CONF_METHOD;

#[derive(Debug)]
pub struct Config {
    /// Random seed.
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,
    /// The Geonetworking address the local router will use.
    pub geonet_addr: GnAddress,
    /// Latitude of the Geonetworking router.
    pub latitude: Latitude,
    /// Longitude of the Geonetworking router.
    pub longitude: Longitude,
    /// Position accuracy flag.
    pub position_accurate: bool,
    /// Speed of the Geonetworking router.
    pub speed: Speed,
    /// Heading of the Geonetworking router.
    pub heading: Heading,
}

impl Config {
    /// Constructs a new [Config] with default values.
    pub fn new(geonet_addr: GnAddress) -> Self {
        Config {
            random_seed: 0,
            geonet_addr: geonet_addr,
            latitude: Latitude::new::<degree>(0.0),
            longitude: Longitude::new::<degree>(0.0),
            position_accurate: false,
            speed: Speed::new::<kilometer_per_hour>(0.0),
            heading: Heading::new::<degree>(0.0),
        }
    }
}

/// Geonetworking Core.
#[derive(Debug)]
pub struct Core {
    /// Now timestamp.
    pub now: Instant,
    /// Random number generator.
    pub rand: Rand,
    /// Ego Position Vector which includes the local Geonetworking address.
    pub ego_position_vector: LongPositionVector,
}

impl Core {
    pub fn new(config: Config, now: Instant) -> Self {
        let rand = Rand::new(config.random_seed);
        let ego_position_vector = LongPositionVector {
            address: config.geonet_addr,
            timestamp: now,
            latitude: config.latitude,
            longitude: config.longitude,
            is_accurate: config.position_accurate,
            speed: config.speed,
            heading: config.heading,
        };

        Core {
            now,
            rand,
            ego_position_vector,
        }
    }

    /// Returns the Ego Position Vector as a [`LongPositionVector`].
    pub fn ego_position_vector(&self) -> LongPositionVector {
        self.ego_position_vector.clone()
    }

    /// Returns the position carried inside the Ego Position Vector
    /// as a [`GeoPosition`].
    pub fn position(&self) -> GeoPosition {
        GeoPosition {
            latitude: self.ego_position_vector.latitude,
            longitude: self.ego_position_vector.longitude,
        }
    }

    /// Returns the Geonetworking address.
    pub fn address(&self) -> GnAddress {
        self.ego_position_vector.address
    }

    /// Sets the Geonetworking address.
    pub fn set_address(&mut self, address: GnAddress) {
        self.ego_position_vector.address = address;
    }

    /// Performs the Duplicate Address Detection algorithm specified in
    /// ETSI TS 103 836-4-1 V2.1.1 chapter 10.2.1.5.
    pub fn duplicate_address_detection(&mut self, sender_addr: EthernetAddress, source: GnAddress) {
        // Duplicate address detection is only applied for Auto.
        if let GnAddrConfMethod::Auto = GN_LOCAL_ADDR_CONF_METHOD {
            let ego_addr = self.ego_position_vector.address;

            if ego_addr.mac_addr() == sender_addr || ego_addr == source {
                // Addresses are equal, we have to generate a new Mac Address.
                // We use the timestamp of the Ego Position Vector as a seed for the generator.
                //let mut generator = Rand::new(self.ego_position_vector.timestamp.secs() as u64);
                let new_address = EthernetAddress::from_bytes(&self.rand.rand_mac_addr());
                self.ego_position_vector.address.set_mac_addr(new_address);
            }
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::geonet::time::Instant;
    use crate::geonet::types::*;
    use crate::geonet::wire::GnAddress;

    static ADDR: GnAddress = GnAddress([0x84, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);

    #[test]
    fn test_dad_source() {
        let mut core = Core {
            ego_position_vector: LongPositionVector {
                address: ADDR,
                timestamp: Instant::from_secs(10),
                latitude: Latitude::new::<degree>(48.276446),
                longitude: Longitude::new::<degree>(-3.551753),
                is_accurate: true,
                speed: Speed::new::<kilometer_per_hour>(50.0),
                heading: Heading::new::<degree>(155.0),
            },
            now: Instant::from_secs(10),
            rand: Rand::new(0xfadecafe),
        };

        let eth_addr = EthernetAddress::new(0, 1, 2, 3, 4, 5);
        core.duplicate_address_detection(eth_addr, ADDR);

        assert_ne!(core.address().mac_addr(), ADDR.mac_addr());
    }

    #[test]
    fn test_dad_sender() {
        let mut core = Core {
            ego_position_vector: LongPositionVector {
                address: ADDR,
                timestamp: Instant::from_secs(10),
                latitude: Latitude::new::<degree>(48.276446),
                longitude: Longitude::new::<degree>(-3.551753),
                is_accurate: true,
                speed: Speed::new::<kilometer_per_hour>(50.0),
                heading: Heading::new::<degree>(155.0),
            },
            now: Instant::from_secs(10),
            rand: Rand::new(0xcafefade),
        };

        core.duplicate_address_detection(
            ADDR.mac_addr(),
            GnAddress([0x84, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
        );

        assert_ne!(core.address().mac_addr(), ADDR.mac_addr());
    }
}
