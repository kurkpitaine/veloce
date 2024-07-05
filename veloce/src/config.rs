use super::time::Duration;
use super::wire::GnTrafficClass;
use core::fmt;

pub(crate) use cfg::*;

/// Maximum number of access handlers.
pub(crate) const VELOCE_MAX_ACCESS_HANDLER_COUNT: usize = 2;
/// Maximum number of retransmissions used in area advanced forwarding.
pub(crate) const VELOCE_CBF_MAX_RETRANSMIT: u8 = 2;
/// Geonetworking protocol version supported by Veloce.
pub(crate) const GN_PROTOCOL_VERSION: u8 = 1;
/// Flag indicating whether the station could move.
pub(crate) const GN_IS_MOBILE: bool = true;
/// Maximum number of Duplicate Packet List (DPL) per source.
pub(crate) const GN_DPL_LENGTH: usize = 8;
/// Maximum number of entries inside the location table.
pub(crate) const GN_LOC_TABLE_ENTRY_COUNT: usize = 16;
/// Lifetime of a location table entry.
pub(crate) const GN_LOC_TABLE_ENTRY_LIFETIME: Duration = Duration::from_secs(20);
/// Beacon packet transmit period.
pub(crate) const GN_BEACON_SERVICE_RETRANSMIT_TIMER: Duration = Duration::from_millis(3000);
/// Maximum beacon jitter. Default value is GN_BEACON_SERVICE_RETRANSMIT_TIMER / 4.
pub(crate) const GN_BEACON_SERVICE_MAX_JITTER: Duration = Duration::from_millis(750);
pub(crate) const GN_DEFAULT_HOP_LIMIT: u8 = 10;
pub(crate) const GN_DEFAULT_TRAFFIC_CLASS: GnTrafficClass = GnTrafficClass::from_byte(&0x00);
pub(crate) const GN_MAX_PACKET_LIFETIME: Duration = Duration::from_secs(600);
pub(crate) const GN_DEFAULT_PACKET_LIFETIME: Duration = Duration::from_secs(60);
pub(crate) const GN_MAX_PACKET_DATA_RATE_KILO_BYTE_PER_SEC: u8 = 100;
pub(crate) const GN_MAX_PACKET_DATA_RATE_EMA_BETA: f32 = 0.9;
/// Maximum segment length carried by a Geonetworking packet.
pub(crate) const GN_MAX_SDU_SIZE: usize = 1398;
pub(crate) const GN_MAX_GEO_NETWORKING_HEADER_SIZE: usize = 88;
/// Location service retransmission period.
pub(crate) const GN_LOCATION_SERVICE_RETRANSMIT_TIMER: Duration = Duration::from_millis(1000);
/// Location service maximum number of retransmissions.
pub(crate) const GN_LOCATION_SERVICE_MAX_RETRANS: u8 = 10;
/// Non area forwarding algorithm executed by the access handlers.
pub(crate) const GN_NON_AREA_FORWARDING_ALGORITHM: GnNonAreaForwardingAlgorithm =
    GnNonAreaForwardingAlgorithm::Greedy;
/// Area forwarding algorithm executed by the access handlers.
pub(crate) const GN_AREA_FORWARDING_ALGORITHM: GnAreaForwardingAlgorithm =
    GnAreaForwardingAlgorithm::Cbf;
/// Minimum duration a GN packet shall be buffered in the CBF packet buffer.
pub(crate) const GN_CBF_MIN_TIME: Duration = Duration::from_millis(1);
/// Maximum duration a GN packet shall be buffered in the CBF packet buffer.
pub(crate) const GN_CBF_MAX_TIME: Duration = Duration::from_millis(100);
/// Default theoretical maximum communication range in meters.
pub(crate) const GN_DEFAULT_MAX_COMMUNICATION_RANGE: f32 = 1000.0;
/// Default threshold angle for area advanced forwarding algorithm in degrees.
pub(crate) const GN_BROADCAST_CBF_DEF_SECTOR_ANGLE: f32 = 30.0;
/// Maximum Geographical area size in square kilometers.
pub(crate) const GN_MAX_GEO_AREA_SIZE: f32 = 10.0;
/// Distance related to the confidence interval for latitude and longitude [m].
pub(crate) const GN_PAI_INTERVAL: f32 = 80.0;

/// Lifetime for the ITS-G5 extensions of the location table entry.
pub(crate) const GN_LIFETIME_LOC_TE_X: Duration = Duration::from_secs(1);
/// Value for the intended global channel busy ratio CBR_Target.
pub(crate) const GN_CBR_TARGET: f32 = 0.62;
/// Trigger interval for calculation of CBR_G.
pub(crate) const GN_CBR_G_TRIGGER_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum payload length carried by a BTP packet.
pub(crate) const BTP_MAX_PL_SIZE: usize = GN_MAX_SDU_SIZE - 4;

/// Maximum size of one DCC queue.
pub(crate) const DCC_QUEUE_SIZE: usize = 10 * 1000;

/// Maximum number of certificates in the security certificate cache.
pub(crate) const SEC_CERT_CACHE_ENTRY_COUNT: usize = 16;
/// Lifetime of a certificate cache entry.
pub(crate) const SEC_CERT_CACHE_ENTRY_LIFETIME: Duration = Duration::from_secs(20);

#[cfg(not(test))]
mod cfg {
    /// Location service maximum concurrent requests.
    pub(crate) const GN_LOCATION_SERVICE_MAX_REQS: usize = 5;
    /// Maximum size of the Location Service buffer.
    pub(crate) const GN_LOCATION_SERVICE_PACKET_BUFFER_SIZE: usize = 1024;
    /// Maximum size of the unicast buffer.
    pub(crate) const GN_UC_FORWARDING_PACKET_BUFFER_SIZE: usize = 256 * 1000;
    /// Maximum size of the broadcast buffer.
    pub(crate) const GN_BC_FORWARDING_PACKET_BUFFER_SIZE: usize = 1024 * 1000;
    /// Maximum size of the contention routing buffer.
    pub(crate) const GN_CBF_PACKET_BUFFER_SIZE: usize = 256 * 1000;
}

#[cfg(test)]
mod cfg {
    /// For tests - Location service maximum concurrent requests.
    pub(crate) const GN_LOCATION_SERVICE_MAX_REQS: usize = 5;
    /// For tests - Maximum size of the Location Service buffer.
    pub(crate) const GN_LOCATION_SERVICE_PACKET_BUFFER_SIZE: usize = 1024;
    /// For tests - Maximum size of the unicast buffer.
    pub(crate) const GN_UC_FORWARDING_PACKET_BUFFER_SIZE: usize = 2048;
    /// For tests - Maximum size of the broadcast buffer.
    pub(crate) const GN_BC_FORWARDING_PACKET_BUFFER_SIZE: usize = 4096;
    /// For tests - Maximum size of the contention routing buffer.
    pub(crate) const GN_CBF_PACKET_BUFFER_SIZE: usize = 2048;
}

/// The GeoNetworking protocol networking interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnIfType {
    /// Networking interface is unspecified.
    Unspecified,
    /// Networking interface is its-g5 type.
    ItsG5,
    /// Networking interface is lte-v2x type.
    LteV2x,
}

impl fmt::Display for GnIfType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GnIfType::Unspecified => write!(f, "unspecified"),
            GnIfType::ItsG5 => write!(f, "its-g5"),
            GnIfType::LteV2x => write!(f, "lte-v2x"),
        }
    }
}

/// The GeoNetworking protocol secured packet handling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnSnDecapResultHandling {
    /// Received GN packets that are not correctly verified and decrypted (service primitive SN-ENCAP.confirm parameter report != CORRECT) are always dropped.
    Strict,
    /// GN packets that are not correctly verified and decrypted can be passed to the upper protocol entity for further processing.
    NonStrict,
}

impl fmt::Display for GnSnDecapResultHandling {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GnSnDecapResultHandling::Strict => write!(f, "strict"),
            GnSnDecapResultHandling::NonStrict => write!(f, "non-strict"),
        }
    }
}

/// The GeoNetworking protocol GeoUnicast forwarding algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnNonAreaForwardingAlgorithm {
    /// Unicast forwarding algorithm is not specified.
    Unspecified,
    /// Greedy unicast forwarding algorithm.
    Greedy,
    /// Contention buffered unicast forwarding algorithm.
    Cbf,
}

impl fmt::Display for GnNonAreaForwardingAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GnNonAreaForwardingAlgorithm::Unspecified => write!(f, "unspecified"),
            GnNonAreaForwardingAlgorithm::Greedy => write!(f, "greedy"),
            GnNonAreaForwardingAlgorithm::Cbf => write!(f, "cbf"),
        }
    }
}

/// The GeoNetworking protocol GeoBroadcast forwarding algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnAreaForwardingAlgorithm {
    /// Broadcast forwarding algorithm is not specified.
    Unspecified,
    /// Simple Broadcast forwarding algorithm.
    Simple,
    /// Contention buffered forwarding algorithm.
    Cbf,
    /// Advanced forwarding algorithm.
    Advanced,
}

impl fmt::Display for GnAreaForwardingAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GnAreaForwardingAlgorithm::Unspecified => write!(f, "unspecified"),
            GnAreaForwardingAlgorithm::Simple => write!(f, "simple"),
            GnAreaForwardingAlgorithm::Cbf => write!(f, "cbf"),
            GnAreaForwardingAlgorithm::Advanced => write!(f, "advanced"),
        }
    }
}

/* /// The Geonetworking protocol Management Information Base.
pub struct Mib {
    /// GeoNetworking address of the GeoAdhoc router.
    its_gn_local_gn_addr: GnAddress,
    ///  GeoNetworking protocol Address configuration method.
    its_gn_local_addr_conf_method: GnAddrConfMethod,
    ///  GeoNetworking protocol version. 0 or 1.
    its_gn_protocol_version: u8,
    /// Indicates whether ITS station is stationary or mobile.
    its_gn_is_mobile: bool,
    /// ITS networking interface type.
    its_gn_if_type: GnIfType,
    /// Minimum update frequency of local position vector (EPV) in ms. 0..65635.
    its_gn_min_update_frequency_epv: u32,
    /// Distance related to the confidence interval of latitude and longitude in m. Used to determine the Position Accuracy Indicator (PAI). 0..100.
    its_gn_pai_interval: u8,
    /// Maximum size of GN-SDU in bytes. 0..65635.
    its_gn_max_sdu_size: u32,
    /// Maximum size of GeoNetworking header in bytes. 0..65635.
    its_gn_max_geo_networking_header_size: u32,
    /// Location table maintenance: Lifetime of an entry in the location table in s. 0..65635.
    its_gn_lifetime_loc_te: u32,
    /// Indicates whether GN security is enabled or disabled.
    its_gn_security: bool,
    /// Indicates the handling of the SN-DECAP result code (service primitive SN-ENCAP.confirm parameter report).
    its_gn_sn_decap_result_handling: GnSnDecapResultHandling,
    /// Location service: Maximum number of retransmissions for a LS Request. 0..255.
    its_gn_location_service_max_retrans: u8,
    /// Location service: Duration of LS request retransmit timer in ms. 0..65535.
    its_gn_location_service_retransmit_timer: Duration,
    /// Location service: Size of LS packet buffer in bytes. 0..65535.
    its_gn_location_service_packet_buffer_size: u16,
    /// Beacon service: Duration of Beacon retransmit timer in ms. 0..65535.
    its_gn_beacon_service_retransmit_timer: Duration,
    /// Beacon service: Maximum Beacon jitter in ms. 0..65535.
    its_gn_beacon_service_max_jitter: Duration,
    /// Default hop limit indicating the maximum number of hops a packet travels. 0..255.
    its_gn_default_hop_limit: u8,
    /// Length of Duplicate Packet List (DPL) per source. 0..65535.
    its_gn_dpl_length: u16,
    /// Upper limit of the maximum lifetime of a packet in s. 0..6300.
    its_gn_max_packet_lifetime: Duration,
    /// Default value of the maximum lifetime of a packet in s. 0..6300.
    its_gn_default_packet_lifetime: Duration,
    /// Maximum packet data rate for a GeoAdhoc router in [kBytes/s].
    its_gn_max_packet_data_rate: i32,
    /// Weight factor for the Exponential Moving Average (EMA) of the packet data rate PDR in percent.
    its_gn_max_packet_data_rate_ema_beta: i32,
    /// Maximum size of the geographical area for a GBC and GAC packet in [km2]
    its_gn_max_geo_area_size: i32,
    /// Lower limit of the packet repetition interval in ms. 0..1000.
    its_gn_min_packet_repetition_interval: Duration,
    /// Default GeoUnicast forwarding algorithm.
    its_gn_non_area_forwarding_algorithm: GnNonAreaForwardingAlgorithm,
    /// Default GeoBroadcast forwarding algorithm.
    its_gn_area_forwarding_algorithm: GnAreaForwardingAlgorithm,
    /// Minimum duration a GeoBroadcast packet shall be buffered in the CBF packet buffer in ms. 0..65635.
    its_gn_cbf_min_time: Duration,
    /// Maximum duration a GeoBroadcast packet shall be buffered in the CBF packet buffer in ms. 0..65635.
    its_gn_cbf_max_time: Duration,
    /// Default theoretical maximum communication range in m. 0..65635.
    its_gn_default_max_communication_range: u32,
    /// Default threshold angle for advanced GeoBroadcast algorithm in degrees. 0..180.
    its_gn_broadcast_c_b_f_def_sector_angle: u8,
    /// Forwarding: Size of UC forwarding packet buffer in kByte. 0..255.
    its_gn_uc_forwarding_packet_buffer_size: u8,
    /// Forwarding: Size of BC forwarding packet buffer in kByte. 0..65535.
    its_gn_bc_forwarding_packet_buffer_size: u16,
    /// Forwarding: Size of CBF packet buffer [Kbytes]. 0..65535.
    its_gn_cbf_packet_buffer_size: u16,
    /// Forwarding: Default traffic class.
    its_gn_default_traffic_class: GnTrafficClass,
} */

/* impl Default for Mib {
   fn default() -> Mib {
      its_gn_local_gn_addr: GnAddress,
      its_gn_local_addr_conf_method: GnAddrConfMethod::Managed,
      its_gn_protocol_version: u8,
      its_gn_is_mobile: bool,
      its_gn_if_type: GnIfType,
      its_gn_min_update_frequency_epv: u16,
      its_gn_pai_interval: u8,
      its_gn_max_sdu_size: u16,
      its_gn_max_geo_networking_header_size: u16,
      its_gn_lifetime_loc_te: u16,
      its_gn_security: bool,
      its_gn_sn_decap_result_handling: GnSnDecapResultHandling,
      its_gn_location_service_max_retrans: u8,
      its_gn_location_service_retransmit_timer: Duration,
      its_gn_location_service_packet_buffer_size: u16,
      its_gn_beacon_service_retransmit_timer: Duration,
      its_gn_beacon_service_max_jitter: Duration,
      its_gn_default_hop_limit: u8,
      its_gn_dpl_length: u16,
      its_gn_max_packet_lifetime: Duration,
      its_gn_default_packet_lifetime: Duration,
      its_gn_max_packet_data_rate: i32,
      its_gn_max_packet_data_rate_ema_beta: i32,
      its_gn_max_geo_area_size: i32,
      its_gn_min_packet_repetition_interval: Duration,
      its_gn_non_area_forwarding_algorithm: GnGnNonAreaForwardingAlgorithm,
      its_gn_area_forwarding_algorithm: GnGnAreaForwardingAlgorithm,
      its_gn_cbf_min_time: Duration,
      its_gn_cbf_max_time: Duration,
      its_gn_default_max_communication_range: u16,
      its_gn_broadcast_c_b_f_def_sector_angle: u8,
      its_gn_uc_forwarding_packet_buffer_size: u8,
      its_gn_bc_forwarding_packet_buffer_size: u16,
      its_gn_cbf_packet_buffer_size: u16,
      its_gn_default_traffic_class: GnTrafficClassRepr
   }
} */
