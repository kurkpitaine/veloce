use core::fmt;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
    str::FromStr,
};

use log::{error, warn};
use macaddr::MacAddr;
use secrecy::{CloneableSecret, SecretBox, SerializableSecret, zeroize::Zeroize};
use serde::{Deserialize, Serialize};
use veloce::{
    security::{
        permission::Permission,
        privacy::PrivacyStrategy,
        ssp::{
            SspTrait,
            cam::{CamPermission, CamSsp},
            denm::{DenmPermission, DenmSsp, DenmSspV1, DenmSspV2},
        },
    },
    types::Power,
    wire::{EthernetAddress, StationType},
};
use veloce_nxp_phy::{NxpChannel, NxpConfig, NxpRadio, NxpWirelessChannel};

use crate::utils::{UtilError, load_file};

pub type ConfigResult<T> = core::result::Result<T, ConfigError>;

#[derive(Debug)]
pub enum ConfigError {
    /// Error while deserializing a TOML file.
    TomlDecode(String),
    /// Error while reading a file.
    FileLoad(UtilError),
    /// Malformed LL address.
    MalformedLLAddress(macaddr::ParseError),
    /// Unsupported LL address.
    UnsupportedLLAddress,
    /// Invalid station type.
    InvalidStationType,
    /// No replay file provided.
    NoGnssReplayFile,
    /// Invalid NXP slot.
    InvalidNxpSlot,
    /// Invalid NXP wireless channel number.
    InvalidNxpWirelessChannel,
    /// No Ethernet PHY name provided.
    NoEthernetPhyName,
    /// No local UDP address provided.
    NoUdpAddress,
    /// No peer UDP address provided.
    NoUdpPeerAddress,
    /// No TunTap interface name provided.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    NoTunTapName,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::TomlDecode(e) => write!(f, "Error while deserializing TOML file: {}", e),
            ConfigError::FileLoad(e) => {
                write!(f, "File load error: {}", e)
            }
            ConfigError::MalformedLLAddress(e) => write!(f, "Malformed LL address: {}", e),
            ConfigError::UnsupportedLLAddress => write!(f, "Unsupported LL address format"),
            ConfigError::InvalidStationType => write!(f, "Invalid station type"),
            ConfigError::NoGnssReplayFile => write!(f, "No GNSS replay file provided"),
            ConfigError::InvalidNxpSlot => write!(f, "Invalid NXP channel slot. Should be 0 or 1"),
            ConfigError::InvalidNxpWirelessChannel => {
                write!(f, "Invalid NXP wireless channel number")
            }
            ConfigError::NoEthernetPhyName => write!(f, "No Ethernet interface name provided"),
            ConfigError::NoUdpAddress => write!(f, "No local UDP address provided"),
            ConfigError::NoUdpPeerAddress => write!(f, "No peer UDP address provided"),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            ConfigError::NoTunTapName => write!(f, "No TunTap interface name provided"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl CloneableSecret for Secret {}
impl SerializableSecret for Secret {}

/* impl FromStr for Password {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 6 {
            return Err(anyhow!("Password must be at least 6 characters long"));
        }

        Ok(Self(s.to_string()))
    }
} */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum NxpPhyConfigMode {
    Usb,
    Llc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(deny_unknown_fields)]
pub enum FileNxpPhyConfigRadio {
    A,
    B,
}

impl From<NxpRadio> for FileNxpPhyConfigRadio {
    fn from(value: NxpRadio) -> Self {
        match value {
            NxpRadio::A => FileNxpPhyConfigRadio::A,
            NxpRadio::B => FileNxpPhyConfigRadio::B,
        }
    }
}

impl From<FileNxpPhyConfigRadio> for NxpRadio {
    fn from(value: FileNxpPhyConfigRadio) -> Self {
        match value {
            FileNxpPhyConfigRadio::A => NxpRadio::A,
            FileNxpPhyConfigRadio::B => NxpRadio::B,
        }
    }
}

/// Configuration values for the NXP driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileNxpPhyConfig {
    /// Mode of the NXP driver, either "usb" or "llc".
    /// Default is "llc"
    pub mode: Option<NxpPhyConfigMode>,
    /// The name of the interface to use, generally cw-llc0.
    /// For SAF5100, this will always be cw-llc or cw-llc0 depending on the driver version.
    /// For SAF5400, in a single radio configuration: cw-llc0. In a dual radio configuration:
    /// cw-llc0 or cw-llc1.
    pub interface_name: Option<String>,
    /// The name of the radio to use, either "A" or "B".
    /// SAF5100 supports "A" only or "A" and "B".
    /// SAF5400 supports "A" only. When paired with a second radio, it supports "A" and "B",
    /// with the driver automatically opening the second radio interface.
    pub radio: Option<FileNxpPhyConfigRadio>,
    /// Logical channel slot to use on the radio. "0" or "1". NXP chips support channel switching on
    /// the same radio, going from 0 to 1, then back to 0 every 50ms. We don't support this and
    /// stick transmitting and receiving on the same `channel`.
    pub slot: Option<u8>,
    /// Center frequency of the radio, using the WLAN channel identifier. We only support 10MHz channels.
    /// Accepted values are: 172, 174, 176, 178, 180, 182, 184.
    pub wireless_channel: Option<u8>,
    /// Default transmit power in dBm. Minimum is -10dBm and maximum is 26dBm. Values outside this range
    /// are not supported by the NXP chips and will be clamped to the minimum or maximum value by the radio.
    pub tx_power: Option<i8>,
}

/// Configuration values for the UDP interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileUdpPhyConfig {
    /// Local UDP IP address + port to bind to.
    pub local_addr: Option<SocketAddr>,
    /// Peer UDP IP address + port to send to.
    pub peer_addr: Option<SocketAddr>,
}

/// Configuration values for the Raw Ethernet interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEthernetPhyConfig {
    /// Name of the network interface to use.
    pub name: Option<String>,
}

/// Configuration values for the TunTap interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTunTapPhyConfig {
    /// Name of the TunTap interface to use or create
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum FileGnssConfigMode {
    Fixed,
    Gpsd,
    Replay,
}

/// Configuration values for the GNSS client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileGnssConfig {
    /// GNSS client driver mode. Either "fixed", "gpsd" or "replay".
    /// Default is "gpsd".
    /// Use "replay" to replay previously recorded GPS positions in `replay_file`.
    /// Use "fixed" to use a fixed position with `latitude`, `longitude` and `altitude`
    /// values below.
    pub mode: Option<FileGnssConfigMode>,
    /// GPSD server address and port. Default is "127.0.0.1:2947".
    pub gpsd_address: Option<SocketAddr>,
    /// Path of the replay file containing NMEA sentences.
    pub replay_file: Option<String>,
    /// Latitude in degrees of the fixed position. Default is 0.0°
    pub fixed_position_latitude: Option<f64>,
    /// Longitude in degrees of the fixed position. Default is 0.0°
    pub fixed_position_longitude: Option<f64>,
    /// Altitude in meters of the fixed position. Default is 0.0m
    pub fixed_position_altitude: Option<f64>,
}

/// Configuration values for the Geonetworking layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileGeonetConfig {
    /// Link layer (MAC) address of the Geonetworking interface, when not running with security activated.
    /// Ignored if security is enabled.
    /// Expected format is "xx:xx:xx:xx:xx:xx", in hexadecimal.
    /// Default value is:
    ///  - a randomly generated value if security is disabled
    ///  - derived from AT certificate if security is enabled
    pub ll_address: Option<String>,
    /// Pseudonym, aka Station Id, when not running with security activated.
    /// Ignored if security is enabled.
    /// Default value is:
    ///  - a randomly generated value if security is disabled
    ///  - derived from AT certificate if security is enabled
    pub pseudonym: Option<u32>,
    /// Station type. Default is "unknown".
    pub station_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum SSPConfigType {
    Geonet,
    Denm,
    Cam,
}

/// Configuration values for en SSP entry in the configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSSPConfig {
    /// Type of the SSP.
    pub r#type: SSPConfigType,
    /// Version of the SSP. Could be 1 or 2 depending on the type.
    pub version: Option<u8>,
    /// SSP permissions. Not necessary for all SSP types.
    pub permissions: Option<Vec<String>>,
}

/// Configuration values parsed from the TOML config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum FilePrivacyStrategy {
    No,
    Threshold,
    C2c,
}

/// Configuration values for the security layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSecurityConfig {
    /// Security master switch. Default is false.
    #[serde(default)]
    pub enable: bool,
    /// Privacy strategy. Default is 'no'.
    pub privacy: Option<FilePrivacyStrategy>,
    /// Threshold value for threshold privacy strategy. Default is 2_000_000.
    pub privacy_threshold: Option<u32>,
    /// Canonical identifier. Default is empty string.
    pub canonical_identifier: Option<String>,
    /// Service Specific Permissions (SSP) to include into certificates requests.
    pub permissions: Option<Vec<FileSSPConfig>>,
    /// Root certificate identifier in ECTL. Default is empty string.
    pub root_cert_id: Option<String>,
    /// European C-ITS Point Of Contact URL. Default is "https://cpoc.jrc.ec.europa.eu/L0/".
    pub cpoc_url: Option<String>,
    /// Enrollment Authority URL. Default is empty string.
    pub ea_url: Option<String>,
    /// Authentication Authority URL. Default is empty string.
    pub aa_url: Option<String>,
    /// Request timeout in seconds. Default is 5 seconds.
    pub timeout: Option<u32>,
    /// Secure storage path.
    pub storage_path: Option<String>,
    /// Private keys secret.
    pub secret: Option<SecretBox<Secret>>,
}

/// Configuration values parsed from the TOML config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum InterfaceType {
    Nxp,
    Ethernet,
    Udp,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    TunTap,
}

/// Configuration values parsed from the TOML config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    /// Network interface type
    pub phy: InterfaceType,
    /// Configuration values for the NXP driver. See [`FileNxpPhyConfig`] for more information.
    pub nxp_phy: FileNxpPhyConfig,
    /// Configuration values for the Raw Ethernet interface. See [`FileEthernetPhyConfig`] for more information.
    pub ethernet_phy: FileEthernetPhyConfig,
    /// Configuration values for the UDP interface. See [`FileUdpPhyConfig`] for more information.
    pub udp_phy: FileUdpPhyConfig,
    /// Configuration values for the TunTap interface. See [`FileTunTapPhyConfig`] for more information.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub tuntap_phy: FileTunTapPhyConfig,
    /// Configuration values for the Geonetworking layer. See [`FileGeonetConfig`] for more information.
    pub geonet: FileGeonetConfig,
    /// Configuration values for the security layer. See [`FileSecurityConfig`] for more information.
    pub security: FileSecurityConfig,
    /// Configuration values for the GNSS client. See [`FileGnssConfig`] for more information.
    pub gnss: FileGnssConfig,
    /// TCP port binded by the IPC publisher. Default port is 45556.
    pub ipc_publisher_port: Option<u16>,
    /// TCP port binded by the IPC replier. Default port is 45557.
    pub ipc_replier_port: Option<u16>,
    /// Path of the UNIX domain socket file to send commands to the Veloce stack.
    /// Default is "/var/run/veloceCommand.sock"
    pub command_socket: Option<String>,
    /// Absolute path of the PID file.
    pub pid_file_path: Option<String>,
    /// Log level. Default is "info".
    pub log_level: Option<String>,
}

impl FileConfig {
    /// Loads the configuration from the given file at `path`.
    pub fn load(path: &str) -> Result<FileConfig, ConfigError> {
        let data = load_file(path).map_err(ConfigError::FileLoad)?;

        let config = match toml::from_str(&data) {
            Ok(config) => config,
            Err(e) => {
                Self::display_toml_error(&data, &e);
                return Err(ConfigError::TomlDecode(e.to_string()));
            }
        };

        Ok(config)
    }

    fn display_toml_error(file: &str, error: &toml::de::Error) {
        error!("error parsing config file '{file}': {error}");
        if let Some(Range { start, end }) = error.span() {
            error!("error parsing config file '{file}' at position: {start}, {end}");
        }
    }
}

/// Acts as a middleware between the TOML configuration file and the inner configuration struct.
/// It allows bidirectional conversion between the two types, while checking for errors and filling
/// default values where necessary.
#[allow(unused)]
pub struct ConfigBuilder {
    /// The TOML deserialized configuration file.
    toml: FileConfig,
    /// The inner configuration struct.
    inner: Config,
}

impl ConfigBuilder {
    /// Parse a TOML configuration file and return a [ConfigBuilder] instance.
    pub fn from_toml(toml: FileConfig) -> ConfigResult<Self> {
        let mut rng = veloce::rand::Rand::new(rand::random());

        let ll_address = toml
            .geonet
            .ll_address
            .as_ref()
            .map(|addr| Self::parse_ll_address(addr.to_owned()))
            .transpose()?;

        let station_type = toml.geonet.station_type.as_ref().map_or_else(
            || Ok(StationType::Unknown(0)),
            |st| Self::parse_station_type(st.to_owned()),
        )?;

        let inner = Config {
            ll_address,
            pseudonym: toml.geonet.pseudonym.unwrap_or_else(|| rng.rand_u32()),
            station_type,
            interface: Self::parse_interface_config(&toml)?,
            gnss: Self::parse_gnss_config(&toml.gnss)?,
            security: Self::parse_security_config(&toml.security)?,
            ipc_publisher_port: toml.ipc_publisher_port.unwrap_or(45556),
            ipc_replier_port: toml.ipc_replier_port.unwrap_or(45557),
            command_socket: toml
                .command_socket
                .clone()
                .unwrap_or("/var/run/veloceCommand.sock".to_string()),
            pid_file_path: toml.pid_file_path.clone(),
            log_level: toml.log_level.clone().unwrap_or("info".to_string()),
        };

        Ok(ConfigBuilder { toml, inner })
    }

    /// Consume the [ConfigBuilder] and return the built [Config].
    pub fn into_inner(self) -> Config {
        self.inner
    }

    /// Parse a string containing a MAC address into an EthernetAddress.
    fn parse_ll_address(ll_address: String) -> ConfigResult<EthernetAddress> {
        let res = match macaddr::MacAddr::from_str(&ll_address) {
            Ok(MacAddr::V6(addr)) => EthernetAddress(addr.into_array()),
            Ok(_) => return Err(ConfigError::UnsupportedLLAddress),
            Err(e) => return Err(ConfigError::MalformedLLAddress(e)),
        };

        Ok(res)
    }

    /// Parse a string containing a station type into a StationType.
    fn parse_station_type(station_type: String) -> ConfigResult<StationType> {
        match station_type.as_str() {
            "unknown" => Ok(StationType::Unknown(0)),
            "pedestrian" => Ok(StationType::Pedestrian),
            "cyclist" => Ok(StationType::Cyclist),
            "moped" => Ok(StationType::Moped),
            "motorcycle" => Ok(StationType::Motorcycle),
            "passenger_car" => Ok(StationType::PassengerCar),
            "bus" => Ok(StationType::Bus),
            "light_truck" => Ok(StationType::LightTruck),
            "heavy_truck" => Ok(StationType::HeavyTruck),
            "trailer" => Ok(StationType::Trailer),
            "special_vehicle" => Ok(StationType::SpecialVehicle),
            "tram" => Ok(StationType::Tram),
            "light_vru_vehicle" => Ok(StationType::LightVruVehicle),
            "animal" => Ok(StationType::Animal),
            "agricultural" => Ok(StationType::Agricultural),
            "roadside_unit" => Ok(StationType::RoadSideUnit),
            _ => Err(ConfigError::InvalidStationType),
        }
    }

    fn parse_gnss_config(toml: &FileGnssConfig) -> ConfigResult<GnssConfig> {
        let mode = toml.mode.unwrap_or(FileGnssConfigMode::Gpsd);

        let res = match mode {
            FileGnssConfigMode::Fixed => {
                let latitude = toml.fixed_position_latitude.unwrap_or(0.0);
                let longitude = toml.fixed_position_longitude.unwrap_or(0.0);
                let altitude = toml.fixed_position_altitude.unwrap_or(0.0);
                GnssConfig::FixedPosition {
                    latitude,
                    longitude,
                    altitude,
                }
            }
            FileGnssConfigMode::Gpsd => {
                let addr = toml.gpsd_address.unwrap_or_else(|| {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 2947))
                });
                GnssConfig::Gpsd(addr)
            }
            FileGnssConfigMode::Replay => {
                if let Some(path) = &toml.replay_file {
                    GnssConfig::Replay(path.clone())
                } else {
                    return Err(ConfigError::NoGnssReplayFile);
                }
            }
        };

        Ok(res)
    }

    pub fn parse_interface_config(toml: &FileConfig) -> ConfigResult<InterfaceConfig> {
        let res = match toml.phy {
            InterfaceType::Nxp => {
                #[cfg(all(feature = "nxp-phy-r17", not(feature = "nxp-phy-r16")))]
                let name = toml
                    .nxp_phy
                    .interface_name
                    .clone()
                    .unwrap_or("cw-llc0".to_string());
                #[cfg(all(feature = "nxp-phy-r16", not(feature = "nxp-phy-r17")))]
                let name = toml
                    .nxp_phy
                    .interface_name
                    .clone()
                    .unwrap_or("cw-llc".to_string());

                let radio = toml.nxp_phy.radio.map_or(NxpRadio::A, Into::into);
                let channel = match toml.nxp_phy.slot {
                    Some(0) => NxpChannel::Zero,
                    Some(1) => NxpChannel::One,
                    Some(_) => return Err(ConfigError::InvalidNxpSlot),
                    None => NxpChannel::Zero,
                };

                let frequency = match toml.nxp_phy.wireless_channel {
                    Some(172) => NxpWirelessChannel::Chan172,
                    Some(174) => NxpWirelessChannel::Chan174,
                    Some(176) => NxpWirelessChannel::Chan176,
                    Some(178) => NxpWirelessChannel::Chan178,
                    Some(180) => NxpWirelessChannel::Chan180,
                    Some(182) => NxpWirelessChannel::Chan182,
                    Some(184) => NxpWirelessChannel::Chan184,
                    Some(_) => return Err(ConfigError::InvalidNxpWirelessChannel),
                    None => NxpWirelessChannel::Chan180,
                };

                let tx_power = toml
                    .nxp_phy
                    .tx_power
                    .map_or(Power::from_dbm_i32(23), |p| Power::from_dbm_i32(p.into()));
                let filter_addr =
                    EthernetAddress::from_bytes(&[0x04, 0xe5, 0x48, 0x00, 0x00, 0x00]);

                let config = NxpConfig::new(radio, channel, frequency, tx_power, filter_addr);

                InterfaceConfig::Nxp(NxpPhyConfig {
                    mode: toml.nxp_phy.mode.unwrap_or(NxpPhyConfigMode::Llc),
                    name,
                    config,
                })
            }
            InterfaceType::Ethernet => toml.ethernet_phy.name.clone().map_or_else(
                || Err(ConfigError::NoEthernetPhyName),
                |n| Ok(InterfaceConfig::Ethernet(n)),
            )?,
            InterfaceType::Udp => {
                let local_addr = toml.udp_phy.local_addr.ok_or(ConfigError::NoUdpAddress)?;
                let peer_addr = toml
                    .udp_phy
                    .peer_addr
                    .ok_or(ConfigError::NoUdpPeerAddress)?;

                InterfaceConfig::Udp(UdpPhyConfig {
                    local_addr,
                    peer_addr,
                })
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            InterfaceType::TunTap => toml.tuntap_phy.name.clone().map_or_else(
                || Err(ConfigError::NoTunTapName),
                |n| Ok(InterfaceConfig::TunTap(n)),
            )?,
        };

        Ok(res)
    }

    fn parse_security_config(toml: &FileSecurityConfig) -> ConfigResult<SecurityConfig> {
        let res = SecurityConfig {
            enable: toml.enable,
            privacy_strategy: toml.privacy.map_or_else(
                || PrivacyStrategy::NoStrategy,
                |s| match s {
                    FilePrivacyStrategy::No => PrivacyStrategy::NoStrategy,
                    FilePrivacyStrategy::Threshold => {
                        PrivacyStrategy::Threshold(toml.privacy_threshold.unwrap_or(2_000_000))
                    }
                    FilePrivacyStrategy::C2c => PrivacyStrategy::Car2Car(rand::random()),
                },
            ),
            canonical_identifier: toml.canonical_identifier.clone().unwrap_or("".to_string()),
            root_cert_id: toml.root_cert_id.clone().unwrap_or("".to_string()),
            permissions: toml
                .permissions
                .as_ref()
                .map_or_else(Vec::new, Self::parse_ssp),
            cpoc_url: toml
                .cpoc_url
                .clone()
                .unwrap_or("https://cpoc.jrc.ec.europa.eu/L0/".to_string()),
            ea_url: toml.ea_url.clone(),
            aa_url: toml.aa_url.clone(),
            timeout: toml.timeout.unwrap_or(5),
            storage_path: toml.storage_path.clone(),
            secret: toml
                .secret
                .clone()
                .unwrap_or_else(|| SecretBox::new(Box::new(Secret("".to_string())))),
        };

        Ok(res)
    }

    /// Parse the SSP permissions.
    fn parse_ssp(ssp_vec: &Vec<FileSSPConfig>) -> Vec<Permission> {
        let mut res = Vec::new();

        for ssp in ssp_vec {
            match (ssp.r#type, ssp.version) {
                (SSPConfigType::Geonet, _) => res.push(Permission::GnMgmt),
                (SSPConfigType::Cam, Some(version)) => {
                    if version == 1 {
                        let Some(perms) = &ssp.permissions else {
                            warn!("Skipping CAM SSP without permissions");
                            continue;
                        };

                        let mut cam_ssp = CamSsp::new();

                        perms.iter().for_each(|p| {
                            Self::parse_cam_ssp_string(p).and_then(|e| {
                                cam_ssp.set_permission(e);
                                None::<CamPermission>
                            });
                        });

                        res.push(Permission::CAM(cam_ssp.into()));
                    } else {
                        warn!("Skipping unsupported CAM SSP version {}", version);
                        continue;
                    }
                }
                (SSPConfigType::Denm, Some(version)) => {
                    let mut denm_ssp: DenmSsp = match version {
                        1 => DenmSspV1::new().into(),
                        2 => DenmSspV2::new().into(),
                        _ => {
                            warn!("Skipping unsupported DENM SSP version {}", version);
                            continue;
                        }
                    };

                    let Some(perms) = &ssp.permissions else {
                        warn!("Skipping DENM SSP version {} without permissions", version);
                        continue;
                    };

                    perms.iter().for_each(|p| {
                        Self::parse_denm_ssp_string(p, version).and_then(|e| {
                            denm_ssp.set_permission(e);
                            None::<DenmPermission>
                        });
                    });

                    res.push(Permission::DENM(denm_ssp.into()));
                }
                (SSPConfigType::Cam, None) => {
                    warn!("Skipping CAM SSP without version specified");
                    continue;
                }
                (SSPConfigType::Denm, None) => {
                    warn!("Skipping DENM SSP without version specified");
                    continue;
                }
            }
        }

        res
    }

    fn parse_cam_ssp_string(str: &String) -> Option<CamPermission> {
        let res = match str.as_str() {
            "SAFETY_CAR" => CamPermission::SafetyCar,
            "EMERGENCY" => CamPermission::Emergency,
            "RESCUE" => CamPermission::Rescue,
            "ROADWORK" => CamPermission::Roadwork,
            "DANGEROUS_GOODS" => CamPermission::DangerousGoods,
            "SPECIAL_TRANSPORT" => CamPermission::SpecialTransport,
            "PUBLIC_TRANSPORT" => CamPermission::PublicTransport,
            "TOLLING_ZONE" => CamPermission::CenDsrcTollingZoneOrProtectedCommunicationZonesRSU,
            "SPEED_LIMIT" => CamPermission::SpeedLimit,
            "NO_TRUCKS" => CamPermission::NoPassingForTrucks,
            "NO_PASSING" => CamPermission::NoPassing,
            "FREE_CROSSING_REQ" => CamPermission::RequestForFreeCrossingAtATrafficLight,
            "RIGHT_OF_WAY_REQ" => CamPermission::RequestForRightOfWay,
            "CLOSED_LANES" => CamPermission::ClosedLanes,
            _ => {
                warn!("Unknown CAM SSP permission {}", str);
                return None;
            }
        };

        Some(res)
    }

    fn parse_denm_ssp_string(str: &String, version: u8) -> Option<DenmPermission> {
        let res = match str.as_str() {
            "HUMAN_ON_ROAD" => DenmPermission::HumanPresenceOnTheRoad,
            "ANIMAL_ON_ROAD" => DenmPermission::HazardousLocationAnimalOnTheRoad,
            "OBSTACLE_ON_ROAD" => DenmPermission::HazardousLocationObstacleOnTheRoad,
            "SURFACE_COND" => DenmPermission::HazardousLocationSurfaceCondition,
            "ADHESION" => DenmPermission::AdverseWeatherConditionAdhesion,
            "ROADWORKS" => DenmPermission::Roadworks,
            "ACCIDENT" => DenmPermission::Accident,
            "TRAFFIC_COND" => DenmPermission::TrafficCondition,
            "VEHICLE_BREAKDOWN" => DenmPermission::VehicleBreakdown,
            "END_OF_QUEUE" => DenmPermission::DangerousEndOfQueue,
            "SLOW_VEHICLE" => DenmPermission::SlowVehicle,
            "PRECIPITATION" => DenmPermission::AdverseWeatherConditionPrecipitation,
            "VISIBILITY" => DenmPermission::AdverseWeatherConditionVisibility,
            "EXTREME_WEATHER_COND" => {
                DenmPermission::AdverseWeatherConditionExtremeWeatherCondition
            }
            "RESCUE_AND_RECOVERY" => DenmPermission::RescueAndRecoveryWorkInProgress,
            "WRONG_WAY_DRIVING" => DenmPermission::WrongWayDriving,
            "DANGEROUS_SITUATION" => DenmPermission::DangerousSituation,
            "SIGNAL_VIOLATION" => DenmPermission::SignalViolation,
            "COLLISION_RISK" => DenmPermission::CollisionRisk,
            "DANGEROUS_CURVE" => DenmPermission::HazardousLocationDangerousCurve,
            "EMERGENCY_VEHICLE_APPROACHING" => DenmPermission::EmergencyVehicleApproaching,
            "STATIONARY_VEHICLE" => DenmPermission::StationaryVehicle,
            "HUMAN_PROBLEM" => DenmPermission::HumanProblem,
            "POST_CRASH" => DenmPermission::PostCrash,
            "RAILWAY_LEVEL_CROSSING" if version >= 2 => DenmPermission::RailwayLevelCrossing,
            "PUBLIC_TRANSPORT_VEHICLE_APPROACHING" if version >= 2 => {
                DenmPermission::PublicTransportVehicleApproaching
            }
            "AQUAPLANING" if version >= 2 => DenmPermission::Aquaplaning,
            "IMPASSABILITY" if version >= 2 => DenmPermission::Impassability,
            _ => {
                warn!("Unknown DENM SSP version {} permission {}", version, str);
                return None;
            }
        };

        Some(res)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NxpPhyConfig {
    pub mode: NxpPhyConfigMode,
    pub name: String,
    pub config: NxpConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UdpPhyConfig {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceConfig {
    Nxp(NxpPhyConfig),
    Ethernet(String),
    Udp(UdpPhyConfig),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    TunTap(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum GnssConfig {
    FixedPosition {
        latitude: f64,
        longitude: f64,
        altitude: f64,
    },
    Gpsd(SocketAddr),
    Replay(String),
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub struct SecurityConfig {
    pub enable: bool,
    pub privacy_strategy: PrivacyStrategy,
    pub canonical_identifier: String,
    pub root_cert_id: String,
    pub permissions: Vec<Permission>,
    pub cpoc_url: String,
    pub ea_url: Option<String>,
    pub aa_url: Option<String>,
    pub timeout: u32,
    pub storage_path: Option<String>,
    pub secret: SecretBox<Secret>,
}

/// Configuration values for the Veloce stack.
#[derive(Debug, Clone)]
#[allow(unused)]
pub struct Config {
    /// Optional as LL address might be fetched from:
    /// - LL address of the network interface
    /// - Derived from the certificate if security is enabled
    pub ll_address: Option<EthernetAddress>,
    pub pseudonym: u32,
    pub station_type: StationType,
    pub interface: InterfaceConfig,
    pub gnss: GnssConfig,
    pub security: SecurityConfig,
    pub ipc_publisher_port: u16,
    pub ipc_replier_port: u16,
    pub command_socket: String,
    pub pid_file_path: Option<String>,
    pub log_level: String,
}

impl Config {
    /// Parse a TOML file and build a config out of it.
    pub fn load(path: &str) -> ConfigResult<Config> {
        let file_config = FileConfig::load(path)?;
        let config = ConfigBuilder::from_toml(file_config)?.into_inner();

        Ok(config)
    }
}
