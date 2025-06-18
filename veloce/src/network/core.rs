use uom::si::length::meter;
use uom::si::velocity::meter_per_second;

/// This module implements the GN Core functions, ie:
/// - Geonetworking Address
/// - Maintenance of the Ego Position Vector
use crate::common::geo_area::GeoPosition;
use crate::common::{Poti, PotiError, PotiFix, PotiPositionHistory};
use crate::config;
use crate::iface::Interface;
use crate::rand::Rand;
use crate::time::{Duration, Instant, TAI2004};
use crate::types::{degree, kilometer_per_hour, Heading, Latitude, Longitude, Pseudonym, Speed};
use crate::wire::{
    EthernetAddress, GnAddress, LongPositionVectorRepr as LongPositionVector, StationType,
};

#[cfg(feature = "proto-security")]
use crate::security::{
    privacy::PrivacyStrategy, SecurityBackend, SecurityService, SecurityServicePollEvent,
    TrustChain,
};

/// Core module poll event.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollEvent {
    /// No event.
    None,
    /// Security service has emitted an event.
    #[cfg(feature = "proto-security")]
    SecurityService(SecurityServicePollEvent),
}

/// Geonetworking local address configuration mode. If Geonetworking security is enabled,
/// configuration mode will be forced to Anonymous mode.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddrConfigMode {
    /// Geonetworking address is automatically generated from a random seed.
    Auto,
    /// Geonetworking address is manually set by the user.
    Managed(EthernetAddress),
    /// Geonetworking address is derived from security certificate.
    Anonymous,
}

#[cfg(feature = "proto-security")]
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityConfig {
    /// Security backend.
    pub security_backend: SecurityBackend,
    /// Own trust chain of the local ITS station.
    pub own_trust_chain: TrustChain,
    /// Privacy strategy.
    pub privacy_strategy: PrivacyStrategy,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Config {
    /// Random seed.
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,
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
    /// Geonetworking station type.
    pub station_type: StationType,
    /// Geonetworking address config mode.
    pub addr_config_mode: AddrConfigMode,
    #[cfg(feature = "proto-security")]
    /// Security backend. Set to None to disable security.
    pub security: Option<SecurityConfig>,
}

impl Config {
    /// Constructs a new [Config] with default values.
    pub fn new(station_type: StationType, pseudonym: Pseudonym) -> Self {
        Config {
            random_seed: 0,
            latitude: Latitude::new::<degree>(0.0),
            longitude: Longitude::new::<degree>(0.0),
            position_accurate: false,
            speed: Speed::new::<kilometer_per_hour>(0.0),
            heading: Heading::new::<degree>(0.0),
            pseudonym,
            station_type,
            addr_config_mode: AddrConfigMode::Auto,
            #[cfg(feature = "proto-security")]
            security: None,
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
    /// Address automatic configuration flag.
    pub(crate) addr_auto_mode: bool,
    /// Ego Position Vector which includes the local Geonetworking address.
    pub(crate) ego_position_vector: LongPositionVector,
    /// Pseudonym aka. StationId of the Geonetworking router.
    pub(crate) pseudonym: Pseudonym,
    /// Poti for position and timing.
    pub(crate) poti: Poti,
    #[cfg(feature = "proto-security")]
    /// Security service.
    pub(crate) security: Option<SecurityService>,
}

impl Core {
    pub fn new(config: Config, now: Instant) -> Self {
        let mut rand = Rand::new(config.random_seed);

        #[cfg(feature = "proto-security")]
        let security = config.security.map(|s| {
            SecurityService::new(s.own_trust_chain, s.security_backend, s.privacy_strategy)
        });

        #[cfg(feature = "proto-security")]
        let (address, addr_auto_mode) = match (config.addr_config_mode, &security) {
            (_, Some(sec)) => {
                let mac_addr = sec.hardware_address().unwrap_or_else(|_| {
                    net_debug!("Cannot get hardware address from security service - using random");
                    EthernetAddress::from_bytes(&rand.rand_mac_addr())
                });
                (GnAddress::new(false, config.station_type, mac_addr), false)
            }
            (AddrConfigMode::Auto, None) => {
                let mac_addr = EthernetAddress::from_bytes(&rand.rand_mac_addr());
                (GnAddress::new(false, config.station_type, mac_addr), true)
            }
            (AddrConfigMode::Managed(mac_addr), None) => {
                (GnAddress::new(true, config.station_type, mac_addr), false)
            }
            (AddrConfigMode::Anonymous, None) => {
                panic!("Anonymous address mode is not supported when security is disabled")
            }
        };

        #[cfg(not(feature = "proto-security"))]
        let (address, addr_auto_mode) = match config.addr_config_mode {
            AddrConfigMode::Auto => {
                let mac_addr = EthernetAddress::from_bytes(&rand.rand_mac_addr());
                (GnAddress::new(false, config.station_type, mac_addr), true)
            }
            AddrConfigMode::Managed(mac_addr) => {
                (GnAddress::new(true, config.station_type, mac_addr), false)
            }
            AddrConfigMode::Anonymous => unimplemented!(),
        };

        #[cfg(feature = "proto-security")]
        let pseudonym = security
            .as_ref()
            .and_then(|s| s.pseudonym().ok())
            .unwrap_or(config.pseudonym);

        #[cfg(not(feature = "proto-security"))]
        let pseudonym = config.pseudonym;

        let ego_position_vector = LongPositionVector {
            address,
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
            addr_auto_mode,
            ego_position_vector,
            pseudonym,
            poti: Poti::new(),
            #[cfg(feature = "proto-security")]
            security,
        }
    }

    /// Returns the Ego Position Vector as a [`LongPositionVector`].
    pub fn ego_position_vector(&self) -> LongPositionVector {
        self.ego_position_vector
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
    /// Changes the local Geonetworking address mac address if duplicate.
    /// Returns an option containing the mac address part of the new address if duplicate.
    pub fn duplicate_address_detection(
        &mut self,
        sender_addr: EthernetAddress,
        source: GnAddress,
    ) -> Option<EthernetAddress> {
        // Duplicate address detection is only applied for Auto.
        if self.addr_auto_mode {
            let ego_addr = self.address();

            if ego_addr.mac_addr() == sender_addr || ego_addr == source {
                // Addresses are equal, we have to generate a new Mac Address.
                let new_address = EthernetAddress::from_bytes(&self.rand.rand_mac_addr());
                self.ego_position_vector.address.set_mac_addr(new_address);
                return Some(new_address);
            }
        }

        None
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
        self.poti.fix().to_owned()
    }

    /// Returns the position of the local ITS Station, along with the path history.
    pub fn position_and_history(&self) -> (PotiFix, PotiPositionHistory) {
        (
            self.poti.fix().to_owned(),
            self.poti.path_history().to_owned(),
        )
    }

    /// Set the position of the local ITS Station.
    pub fn set_position(&mut self, fix: PotiFix, timestamp: Instant) -> Result<(), PotiError> {
        self.poti.push_fix(fix).map(|fix| {
            self.ego_position_vector.timestamp = TAI2004::from_unix_instant(timestamp).into();
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
                self.ego_position_vector.is_accurate =
                    major_confidence.get::<meter>() < (config::GN_PAI_INTERVAL / 2.0);
            } else {
                self.ego_position_vector.is_accurate = false;
            }

            // Notify the security service about the new position, if any.
            if let Some(s) = &mut self.security {
                s.notify_position(fix, timestamp);
            }
        })
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    pub fn poll_delay(&self, timestamp: Instant) -> Option<Duration> {
        #[cfg(feature = "proto-security")]
        let res = self.security.as_ref().and_then(|s| match s.poll_at() {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::ZERO),
            _ => None,
        });

        #[cfg(not(feature = "proto-security"))]
        let res = None;

        res
    }

    /// Poll the Core module for internal processing.
    pub fn poll(&mut self, iface: &mut Interface, timestamp: Instant) -> PollEvent {
        #[cfg(feature = "proto-security")]
        if let Some(s) = &mut self.security {
            s.poll(timestamp)
                .map(|sec_evt| {
                    match sec_evt {
                        SecurityServicePollEvent::PrivacyATCertificateRotation(_, h)
                        | SecurityServicePollEvent::ATCertificateExpiration(_, h) => {
                            // Change the pseudonym to the new certificate.
                            self.pseudonym = h.into_pseudonym();

                            // Same for the hardware address.
                            let eth_addr = h.into_ethernet_address();
                            self.ego_position_vector.address.set_mac_addr(eth_addr);
                            iface
                                .inner
                                .set_hardware_addr(eth_addr.into_hardware_address());

                            // Car 2 Car Vehicle C-ITS station profile, requirement RS_BSP_182.
                            // Set sequence number to 0.
                            iface.inner.reset_sequence_number();
                            // Clear the path history.
                            self.poti.clear_path_history();

                            // Sync elections statistics.
                            // s.at_certs_stats()

                            PollEvent::SecurityService(sec_evt)
                        }
                    }
                })
                .unwrap_or(PollEvent::None)
        } else {
            PollEvent::None
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
            addr_auto_mode: true,
            #[cfg(feature = "proto-security")]
            security: None,
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
            addr_auto_mode: true,
            #[cfg(feature = "proto-security")]
            security: None,
        };

        core.duplicate_address_detection(
            ADDR.mac_addr(),
            GnAddress([0x84, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
        );

        assert_ne!(core.address().mac_addr(), ADDR.mac_addr());
    }
}
