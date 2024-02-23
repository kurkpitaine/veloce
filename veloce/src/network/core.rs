use uom::si::length::meter;
use uom::si::velocity::meter_per_second;

/// This module implements the GN Core functions, ie:
/// - Geonetworking Address
/// - Maintenance of the Ego Position Vector
use crate::common::geo_area::GeoPosition;
use crate::common::{Poti, PotiFix};
use crate::config::{self, GnAddrConfMethod};
use crate::rand::Rand;
use crate::time::{Instant, TAI2004};
use crate::types::{degree, kilometer_per_hour, Heading, Latitude, Longitude, Pseudonym, Speed};
use crate::wire::{
    EthernetAddress, GnAddress, LongPositionVectorRepr as LongPositionVector, StationType,
};

// For tests only. Duplicate Address Detection only works with Auto mode.
#[cfg(test)]
const GN_LOCAL_ADDR_CONF_METHOD: GnAddrConfMethod = GnAddrConfMethod::Auto;
#[cfg(not(test))]
use crate::config::GN_LOCAL_ADDR_CONF_METHOD;

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
    /// Pseudonym aka. StationId of the Geonetworking router.
    pub pseudonym: Pseudonym,
}

impl Config {
    /// Constructs a new [Config] with default values.
    pub fn new(geonet_addr: GnAddress, pseudonym: Pseudonym) -> Self {
        Config {
            random_seed: 0,
            geonet_addr: geonet_addr,
            latitude: Latitude::new::<degree>(0.0),
            longitude: Longitude::new::<degree>(0.0),
            position_accurate: false,
            speed: Speed::new::<kilometer_per_hour>(0.0),
            heading: Heading::new::<degree>(0.0),
            pseudonym,
        }
    }
}

/// Geonetworking Core.
#[derive(Debug)]
pub struct Core {
    /// Now timestamp.
    pub(crate) now: Instant,
    /// Random number generator.
    pub(crate) rand: Rand,
    /// Ego Position Vector which includes the local Geonetworking address.
    pub(crate) ego_position_vector: LongPositionVector,
    /// Pseudonym aka. StationId of the Geonetworking router.
    pub(crate) pseudonym: Pseudonym,
    /// Poti for position and timing.
    pub(crate) poti: Poti,
}

impl Core {
    pub fn new(config: Config, now: Instant) -> Self {
        let rand = Rand::new(config.random_seed);
        let ego_position_vector = LongPositionVector {
            address: config.geonet_addr,
            timestamp: TAI2004::from_unix_instant(now).into(),
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
            pseudonym: config.pseudonym,
            poti: Poti::new(),
        }
    }

    /// Returns the Ego Position Vector as a [`LongPositionVector`].
    pub fn ego_position_vector(&self) -> LongPositionVector {
        self.ego_position_vector.clone()
    }

    /// Returns the position carried inside the Ego Position Vector
    /// as a [`GeoPosition`].
    pub fn geo_position(&self) -> GeoPosition {
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

    /// Returns the type of the local ITS Station.
    pub fn station_type(&self) -> StationType {
        self.ego_position_vector.address.station_type()
    }

    /// Set the type of the local ITS Station.
    pub fn set_station_type(&mut self, station_type: StationType) {
        self.ego_position_vector
            .address
            .set_station_type(station_type);
    }

    /// Returns the pseudonym of the local ITS Station.
    pub fn pseudonym(&self) -> Pseudonym {
        self.pseudonym
    }

    /// Set the pseudonym of the local ITS Station.
    pub fn set_pseudonym(&mut self, pseudo: Pseudonym) {
        self.pseudonym = pseudo
    }

    /// Returns the timestamp of the local ITS Station.
    pub fn timestamp(&self) -> Instant {
        self.now
    }

    /// Set the timestamp of the local ITS Station.
    pub fn set_timestamp(&mut self, now: Instant) {
        self.now = now;
    }

    /// Returns the position of the local ITS Station.
    pub fn position(&self) -> PotiFix {
        self.poti.fix
    }

    /// Set the position of the local ITS Station.
    pub fn set_position(&mut self, fix: PotiFix) {
        self.poti.fix = fix;
        self.ego_position_vector.timestamp = TAI2004::now().into();
        self.ego_position_vector.latitude = fix
            .position
            .latitude
            .map_or(Latitude::new::<degree>(0.0), |lat| lat);
        self.ego_position_vector.longitude = fix
            .position
            .longitude
            .map_or(Longitude::new::<degree>(0.0), |lon| lon);
        self.ego_position_vector.heading = fix
            .motion
            .heading
            .map_or(Heading::new::<degree>(0.0), |hdg| hdg);

        self.ego_position_vector.speed = fix
            .motion
            .speed
            .map_or(Speed::new::<meter_per_second>(0.0), |spd| spd);

        if let Some(major_confidence) = fix.confidence.position.semi_major {
            if major_confidence.get::<meter>() < (config::GN_PAI_INTERVAL / 2.0) {
                self.ego_position_vector.is_accurate = true;
            } else {
                self.ego_position_vector.is_accurate = false;
            }
        } else {
            self.ego_position_vector.is_accurate = false;
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::time::Instant;
    use crate::types::*;
    use crate::wire::GnAddress;

    static ADDR: GnAddress = GnAddress([0x84, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);

    #[test]
    fn test_dad_source() {
        let mut core = Core {
            ego_position_vector: LongPositionVector {
                address: ADDR,
                timestamp: TAI2004::from_secs(10).into(),
                latitude: Latitude::new::<degree>(48.276446),
                longitude: Longitude::new::<degree>(-3.551753),
                is_accurate: true,
                speed: Speed::new::<kilometer_per_hour>(50.0),
                heading: Heading::new::<degree>(155.0),
            },
            now: Instant::from_secs(10),
            rand: Rand::new(0xfadecafe),
            pseudonym: Pseudonym(123456789),
            poti: Poti::new(),
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
                timestamp: TAI2004::from_secs(10).into(),
                latitude: Latitude::new::<degree>(48.276446),
                longitude: Longitude::new::<degree>(-3.551753),
                is_accurate: true,
                speed: Speed::new::<kilometer_per_hour>(50.0),
                heading: Heading::new::<degree>(155.0),
            },
            now: Instant::from_secs(10),
            rand: Rand::new(0xcafefade),
            pseudonym: Pseudonym(123456789),
            poti: Poti::new(),
        };

        core.duplicate_address_detection(
            ADDR.mac_addr(),
            GnAddress([0x84, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
        );

        assert_ne!(core.address().mac_addr(), ADDR.mac_addr());
    }
}
