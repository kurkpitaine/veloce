use crate::wire::{GnAddress, GnTrafficClass};
use core::{fmt, time::Duration};

/// The GeoNetworking protocol Address configuration method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnAddrConfMethod {
    /// Local GN_ADDR is configured from MIB.
    Auto,
    /// Local GN_ADDR is configured via the GN management using the service primitive GN-MGMT.
    Managed,
    /// Local GN_ADDR is configured by the security entity.
    Anonymous,
}

impl fmt::Display for GnAddrConfMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GnAddrConfMethod::Auto => write!(f, "auto"),
            GnAddrConfMethod::Managed => write!(f, "managed"),
            GnAddrConfMethod::Anonymous => write!(f, "anonymous"),
        }
    }
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
pub enum GnGnNonAreaForwardingAlgorithm {
    /// Unicast forwarding algorithm is not specified.
    Unspecified,
    /// Greedy unicast forwarding algorithm.
    Greedy,
    /// Contention buffered unicast forwarding algorithm.
    Cbf,
}

impl fmt::Display for GnGnNonAreaForwardingAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GnGnNonAreaForwardingAlgorithm::Unspecified => write!(f, "unspecified"),
            GnGnNonAreaForwardingAlgorithm::Greedy => write!(f, "greedy"),
            GnGnNonAreaForwardingAlgorithm::Cbf => write!(f, "cbf"),
        }
    }
}

/// The GeoNetworking protocol GeoBroadcast forwarding algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnGnAreaForwardingAlgorithm {
    /// Broadcast forwarding algorithm is not specified.
    Unspecified,
    /// Simple Broadcast forwarding algorithm.
    Simple,
    /// Contention buffered forwarding algorithm.
    Cbf,
}

impl fmt::Display for GnGnAreaForwardingAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GnGnAreaForwardingAlgorithm::Unspecified => write!(f, "unspecified"),
            GnGnAreaForwardingAlgorithm::Simple => write!(f, "simple"),
            GnGnAreaForwardingAlgorithm::Cbf => write!(f, "cbf"),
        }
    }
}

/// The Geonetworking protocol Management Information Base.
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
    its_gn_min_update_frequency_epv: u16,
    /// Distance related to the confidence interval of latitude and longitude in m. Used to determine the Position Accuracy Indicator (PAI). 0..100.
    its_gn_pai_interval: u8,
    /// Maximum size of GN-SDU in bytes. 0..65635.
    its_gn_max_sdu_size: u16,
    /// Maximum size of GeoNetworking header in bytes. 0..65635.
    its_gn_max_geo_networking_header_size: u16,
    /// Location table maintenance: Lifetime of an entry in the location table in s. 0..65635.
    its_gn_lifetime_loc_te: u16,
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
    its_gn_non_area_forwarding_algorithm: GnGnNonAreaForwardingAlgorithm,
    /// Default GeoBroadcast forwarding algorithm.
    its_gn_area_forwarding_algorithm: GnGnAreaForwardingAlgorithm,
    /// Minimum duration a GeoBroadcast packet shall be buffered in the CBF packet buffer in ms. 0..65635.
    its_gn_cbf_min_time: Duration,
    /// Maximum duration a GeoBroadcast packet shall be buffered in the CBF packet buffer in ms. 0..65635.
    its_gn_cbf_max_time: Duration,
    /// Default theoretical maximum communication range in m. 0..65635.
    its_gn_default_max_communication_range: u16,
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
}

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
