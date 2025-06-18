use core::fmt;

use log::{debug, info};
use veloce::phy::{self};
use veloce_nxp_phy as nxp_phy;

use crate::config::{Config, InterfaceConfig, NxpPhyConfig, NxpPhyConfigMode};

pub type DeviceResult<T> = Result<T, DeviceError>;

#[derive(Debug)]
pub enum DeviceError {
    /// NXP PHY error
    Nxp(nxp_phy::NxpError),
    /// Generic IO error
    Io(std::io::Error),
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceError::Nxp(e) => write!(f, "NXP PHY error: {}", e),
            DeviceError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

/// Underlying Phy device.
/// We cannot use a trait object since [phy::Device] trait is not dyn compatible.
#[derive(Debug)]
pub enum AnyDevice {
    /// NXP LLC PHY device
    NxpLlc(nxp_phy::NxpLlcDevice<nxp_phy::llc::Ready>),
    /// NXP USB PHY device
    NxpUsb(nxp_phy::NxpUsbDevice<nxp_phy::usb::Ready>),
    /// Raw Ethernet PHY device
    RawEthernet(phy::RawSocket),
    /// UDP PHY device
    Udp(phy::UdpSocket<core::net::SocketAddr>),
    /// TUN/TAP PHY device
    #[cfg(any(target_os = "linux", target_os = "android"))]
    TunTap(phy::TunTapInterface),
}

impl AnyDevice {
    /// Create a new [AnyDevice] from `config`.
    pub fn setup_phy_device(config: &Config) -> DeviceResult<Self> {
        let iface_config = config.interface.clone();

        let res = match iface_config {
            InterfaceConfig::Nxp(NxpPhyConfig {
                mode: NxpPhyConfigMode::Llc,
                name,
                config,
            }) => {
                info!("Using NXP LLC interface: {}", name);
                let mut llc_device =
                    nxp_phy::NxpLlcDevice::new(name.as_str(), config).map_err(DeviceError::Nxp)?;
                let inner = llc_device.wait_for_ready().map_err(DeviceError::Nxp)?;
                debug!("NXP LLC device ready");
                inner.commit_config().map_err(DeviceError::Nxp)?;

                AnyDevice::NxpLlc(inner)
            }
            InterfaceConfig::Nxp(NxpPhyConfig {
                mode: NxpPhyConfigMode::Usb,
                name: _,
                config,
            }) => {
                info!("Using NXP USB interface");
                let mut usb_device =
                    nxp_phy::NxpUsbDevice::new(config).map_err(DeviceError::Nxp)?;
                let inner = usb_device.wait_for_ready().map_err(DeviceError::Nxp)?;
                debug!("NXP USB device ready");
                inner.commit_config().map_err(DeviceError::Nxp)?;

                AnyDevice::NxpUsb(inner)
            }
            InterfaceConfig::Ethernet(name) => {
                info!("Using Raw Ethernet interface: {}", name);
                let inner = phy::RawSocket::new(name.as_str(), phy::Medium::Ethernet)
                    .map_err(DeviceError::Io)?;

                AnyDevice::RawEthernet(inner)
            }
            InterfaceConfig::Udp(c) => {
                info!(
                    "Using UDP interface with: local address {} - peer: {}",
                    c.local_addr, c.peer_addr
                );
                let inner = phy::UdpSocket::new(c.local_addr, c.peer_addr, phy::Medium::Ethernet)
                    .map_err(DeviceError::Io)?;

                AnyDevice::Udp(inner)
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            InterfaceConfig::TunTap(name) => {
                info!("Using Tun/Tap interface: {}", name);
                let inner = phy::TunTapInterface::new(name.as_str(), phy::Medium::Ethernet)
                    .map_err(DeviceError::Io)?;

                AnyDevice::TunTap(inner)
            }
        };

        Ok(res)
    }
}
