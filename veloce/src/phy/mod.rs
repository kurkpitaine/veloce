/*! Access to networking hardware.

The `phy` module deals with the *network devices*. It provides a trait
for transmitting and receiving frames, [Device](trait.Device.html)
and implementations of it:

  * the [_loopback_](struct.Loopback.html), for zero dependency testing;
  * _middleware_ [Tracer](struct.Tracer.html) and
    [FaultInjector](struct.FaultInjector.html), to facilitate debugging;
  * _adapters_ [RawSocket](struct.RawSocket.html) and
    [TunTapInterface](struct.TunTapInterface.html), to transmit and receive frames
    on the host OS.
*/

use crate::{time::Instant, types::Power, wire::HardwareAddress};

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
pub mod sys;

#[cfg(all(feature = "phy-raw_socket", unix))]
mod raw_socket;
mod tracer;
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
mod tuntap_interface;

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
pub use self::sys::{wait, wait_many};

#[cfg(all(feature = "phy-raw_socket", unix))]
pub use self::raw_socket::RawSocket;
pub use self::tracer::Tracer;
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
pub use self::tuntap_interface::TunTapInterface;
#[cfg(feature = "phy-udp")]
pub mod udp;
#[cfg(feature = "phy-udp")]
pub use self::udp::UdpSocket;

/// Metadata associated to a packet.
///
/// The packet metadata is a set of attributes associated to network packets
/// as they travel up or down the stack. The metadata is get/set by the
/// [`Device`] implementations or by the user when sending/receiving packets from a
/// socket.
///
/// Metadata fields are enabled via Cargo features. If no field is enabled, this
/// struct becomes zero-sized, which allows the compiler to optimize it out as if
/// the packet metadata mechanism didn't exist at all.
///
/// This struct is marked as `#[non_exhaustive]`. This means it is not possible to
/// create it directly by specifying all fields. You have to instead create it with
/// default values and then set the fields you want. This makes adding metadata
/// fields a non-breaking change.
///
/// ```rust,ignore
/// let mut meta = PacketMeta::new();
/// meta.id = 15;
/// meta.power = None;
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PacketMeta {
    #[cfg(feature = "packetmeta-id")]
    pub id: u32,
    #[cfg(feature = "packetmeta-power")]
    pub power: Option<Power>,
}

/// A description of filter behavior for every supported protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacFilterCapabilities {
    #[default]
    /// No mac filter capabilities
    None,
    /// A filter that processes Rx packets.
    Rx,
}

impl MacFilterCapabilities {
    /// Behavior that results in not filtering frames.
    pub fn no_filter() -> Self {
        MacFilterCapabilities::None
    }
}

/// A description of radio capabilities for a wireless PHY.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RadioCapabilities {
    /// MAC layer rx frame filter.
    ///
    /// Indicates if the device filters received frames based on the hardware address.
    ///
    /// Such filter has to be updated when the Geonetworking core or security changes the Geonetworking
    /// address, since Geonetworking addresses are based on the hardware addresses.
    pub mac_filter: MacFilterCapabilities,
    /// TX power value of the PHY.
    ///
    /// Indicates the signal power used when transmitting frames over the air.
    pub tx_power: Power,
}

/// A description of device capabilities.
///
/// Higher-level protocols may achieve higher throughput or lower latency if they consider
/// the bandwidth or packet size limitations.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct DeviceCapabilities {
    /// Medium of the device.
    ///
    /// This indicates what kind of packet the sent/received bytes are, and determines
    /// some behaviors of Interface.
    pub medium: Medium,

    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the value returned
    /// by this function.
    ///
    /// For Ethernet devices, this is the maximum Ethernet frame size, including the Ethernet header (14 octets), but
    /// *not* including the Ethernet FCS (4 octets). Therefore, Ethernet MTU = Geonet MTU + 14.
    pub max_transmission_unit: usize,

    /// Radio capabilities.
    ///
    /// When a wireless PHY is used to transmit frames, this capability should be used.
    #[cfg(any(feature = "medium-pc5", feature = "medium-ieee80211p"))]
    pub radio: RadioCapabilities,
}

impl DeviceCapabilities {
    pub fn geonet_mtu(&self) -> usize {
        match self.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
                self.max_transmission_unit - crate::wire::EthernetFrame::<&[u8]>::header_len()
            }
            Medium::Ieee80211p => self.max_transmission_unit,
            Medium::PC5 => self.max_transmission_unit,
        }
    }
}

/// Type of medium of a device.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Medium {
    /// Ethernet medium. Devices of this type send and receive Ethernet frames.
    #[cfg(feature = "medium-ethernet")]
    Ethernet,
    /// Ieee 802.11p medium. Devices of this type send and receive LLC/SNAP frames.
    /// They must implement DCC.
    #[cfg(feature = "medium-ieee80211p")]
    Ieee80211p,
    /// PC5 medium. Devices of this type send and receive PC5 L2 frames.
    #[cfg(feature = "medium-pc5")]
    PC5,
}

impl Default for Medium {
    fn default() -> Medium {
        #[cfg(feature = "medium-ethernet")]
        return Medium::Ethernet;
        #[cfg(all(feature = "medium-ieee80211p", not(feature = "medium-ethernet")))]
        return Medium::Ieee80211p;
        #[cfg(all(
            feature = "medium-pc5",
            not(feature = "medium-ieee80211p"),
            not(feature = "medium-ethernet")
        ))]
        return Medium::PC5;
        #[cfg(all(
            not(feature = "medium-ethernet"),
            not(feature = "medium-ieee80211p"),
            not(feature = "medium-pc5")
        ))]
        return panic!("No medium enabled");
    }
}

/// Channel busy ratio measurement, ie: the ratio of time the channel medium is busy
/// transmitting/receiving frames. Value is stored as a raw percentage between 0.0 and
/// 100.0 inclusive.
#[derive(Debug, PartialEq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelBusyRatio(f64);

impl ChannelBusyRatio {
    /// Build a new [ChannelBusyRatio] from a percentage value.
    /// `val` is clamped between 0.0 and 100.0
    pub fn from_percentage(val: f64) -> Self {
        let val = val.clamp(0.0, 100.0);
        ChannelBusyRatio(val)
    }

    /// Build a new [ChannelBusyRatio] from a ratio value.
    /// `val` is clamped between 0.0 and 1.0
    pub fn from_ratio(val: f64) -> Self {
        let val = (val * 100.0).clamp(0.0, 100.0);
        ChannelBusyRatio(val)
    }

    /// Return the [ChannelBusyRatio] value as a percentage.
    pub fn as_percentage(&self) -> f64 {
        self.0
    }

    /// Return the [ChannelBusyRatio] value as a ratio value
    /// between 0.0 and 1.0.
    pub fn as_ratio(&self) -> f64 {
        self.0 / 100.0
    }
}

/// An interface for sending and receiving raw network frames.
///
/// The interface is based on _tokens_, which are types that allow to receive/transmit a
/// single packet. The `receive` and `transmit` functions only construct such tokens, the
/// real sending/receiving operation are performed when the tokens are consumed.
pub trait Device {
    type RxToken<'a>: RxToken
    where
        Self: 'a;
    type TxToken<'a>: TxToken
    where
        Self: 'a;

    /// Construct a token pair consisting of one receive token and one transmit token.
    ///
    /// The additional transmit token makes it possible to generate a reply packet based
    /// on the contents of the received packet. For example, this makes it possible to
    /// handle arbitrarily large ICMP echo ("ping") requests, where the all received bytes
    /// need to be sent back, without heap allocation.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)>;

    /// Construct a transmit token.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>>;

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities;

    /// Get the Rx filter destination address.
    #[cfg(any(feature = "medium-pc5", feature = "medium-ieee80211p"))]
    fn filter_addr(&self) -> Option<HardwareAddress> {
        None
    }

    /// Set the Rx filter destination address.
    #[cfg(any(feature = "medium-pc5", feature = "medium-ieee80211p"))]
    fn set_filter_addr(&mut self, _addr: Option<HardwareAddress>) {}

    /// Get the CBR value from the device. Measurement should be made on a duration of
    /// 100ms.
    fn channel_busy_ratio(&self) -> ChannelBusyRatio {
        ChannelBusyRatio::from_ratio(0.0)
    }
}

/// A token to receive a single network packet.
pub trait RxToken {
    /// Consumes the token to receive a single network packet.
    ///
    /// This method receives a packet and then calls the given closure `f` with the raw
    /// packet bytes as argument.
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R;

    /// The Packet ID associated with the frame received by this [`RxToken`]
    fn meta(&self) -> PacketMeta {
        PacketMeta::default()
    }
}

/// A token to transmit a single network packet.
pub trait TxToken {
    /// Consumes the token to send a single network packet.
    ///
    /// This method constructs a transmit buffer of size `len` and calls the passed
    /// closure `f` with a mutable reference to that buffer. The closure should construct
    /// a valid network packet (e.g. an ethernet packet) in the buffer. When the closure
    /// returns, the transmit buffer is sent out.
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R;

    /// The Packet ID to be associated with the frame to be transmitted by this [`TxToken`].
    #[allow(unused_variables)]
    fn set_meta(&mut self, meta: PacketMeta) {}
}
