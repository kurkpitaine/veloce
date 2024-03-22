use crate::iface::*;
use crate::network::GnAddrConfigMode;
use crate::types::Pseudonym;
use crate::wire::*;

pub(crate) fn setup<'a>(medium: Medium) -> (GnCore, Interface, SocketSet<'a>, TestingDevice) {
    let mut device = TestingDevice::new(medium);

    let raw_ll_addr = [0x02, 0x02, 0x02, 0x02, 0x02, 0x02];

    let config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&raw_ll_addr)),
        #[cfg(feature = "medium-ieee80211p")]
        Medium::Ieee80211p => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&raw_ll_addr)),
        #[cfg(feature = "medium-pc5")]
        Medium::PC5 => HardwareAddress::PC5(PC5Address::from_bytes(&raw_ll_addr[3..])),
    });

    let iface = Interface::new(config, &mut device);

    let mut router_config = GnCoreGonfig::new(StationType::RoadSideUnit, Pseudonym(0xabcd));
    router_config.addr_config_mode =
        GnAddrConfigMode::Managed(EthernetAddress::from_bytes(&raw_ll_addr));
    let core = GnCore::new(router_config, Instant::ZERO);

    (core, iface, SocketSet::new(vec![]), device)
}

use heapless::Deque;
use heapless::Vec;

use crate::phy::{self, Device, DeviceCapabilities, Medium};
use crate::time::Instant;

use super::network::GnCore;
use super::network::GnCoreGonfig;

/// A testing device.
#[derive(Debug)]
pub struct TestingDevice {
    pub(crate) queue: Deque<Vec<u8, 1514>, 4>,
    max_transmission_unit: usize,
    medium: Medium,
}

#[allow(clippy::new_without_default)]
impl TestingDevice {
    /// Creates a testing device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new(medium: Medium) -> Self {
        TestingDevice {
            queue: Deque::new(),
            max_transmission_unit: match medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => 1514,
                #[cfg(feature = "medium-ieee80211p")]
                Medium::Ieee80211p => 1500,
                #[cfg(feature = "medium-pc5")]
                Medium::PC5 => 1500,
            },
            medium,
        }
    }
}

impl Device for TestingDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            medium: self.medium,
            max_transmission_unit: self.max_transmission_unit,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer };
            let tx = TxToken {
                queue: &mut self.queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.queue,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8, 1514>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut Deque<Vec<u8, 1514>, 4>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0).unwrap();
        let result = f(&mut buffer);
        self.queue.push_back(buffer).unwrap();
        result
    }
}
