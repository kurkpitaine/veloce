use std::cell::RefCell;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::vec::Vec;

use crate::phy::{self, sys, Device, DeviceCapabilities, Medium};
use crate::time::Instant;
use crate::wire::nxp::{Channel, Radio};
use crate::wire::{NxpHeader, NxpRxPacketRepr, NxpTxPacketRepr};

/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct NxpSocket {
    medium: Medium,
    lower: Rc<RefCell<sys::RawSocketDesc>>,
    mtu: usize,
    ref_num: u16,
}

impl AsRawFd for NxpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl NxpSocket {
    /// Creates an NXP socket, bound to the interface called `name` (generally `cw-llc0`).
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    ///
    /// # Panics
    /// This method panics if medium is not of type [`Ieee80211p`]
    ///
    /// [`Ieee80211p`]: Medium#variant.Ieee80211p
    pub fn new(name: &str) -> io::Result<NxpSocket> {
        let medium = Medium::Ieee80211p;
        let mut lower = sys::RawSocketDesc::new(name, medium)?;
        lower.bind_interface()?;

        // Don't care about resizing MTU for good.
        let mtu = lower.interface_mtu()?;

        Ok(NxpSocket {
            medium,
            lower: Rc::new(RefCell::new(lower)),
            mtu,
            ref_num: 0,
        })
    }
}

impl Device for NxpSocket {
    type RxToken<'a> = RxToken
    where
        Self: 'a;
    type TxToken<'a> = TxToken
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: self.mtu,
            medium: self.medium,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        match lower.recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);

                // Unpack Nxp header.
                let Ok(nxp_header) = NxpHeader::new_checked(&buffer) else {
                    return None;
                };

                // Ignore non-RxPacket types.
                let Ok(_nxp_repr) = NxpRxPacketRepr::parse(&nxp_header) else {
                    return None;
                };
                buffer.drain(..nxp_header.header_len());

                let ref_num = self.ref_num;
                self.ref_num += 1;

                let rx = RxToken { buffer };
                let tx = TxToken {
                    lower: self.lower.clone(),
                    ref_num,
                };
                Some((rx, tx))
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
            Err(err) => panic!("{}", err),
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let ref_num = self.ref_num;
        self.ref_num += 1;

        Some(TxToken {
            lower: self.lower.clone(),
            ref_num,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower: Rc<RefCell<sys::RawSocketDesc>>,
    ref_num: u16,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len + NxpTxPacketRepr::header_len()];

        // Create NxpTxPacket preamble.
        let mut nxp_header = NxpHeader::new_unchecked(&mut buffer);
        let nxp_repr = NxpTxPacketRepr {
            radio: Radio::RadioA,
            channel: Channel::Channel0,
            expiry: 0,
            ..Default::default()
        };
        nxp_repr.emit(&mut nxp_header, 0, self.ref_num, len);

        let result = f(nxp_header.payload_mut());
        match lower.send(&buffer[..]) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                net_debug!("phy: tx failed due to WouldBlock")
            }
            Err(err) => panic!("{}", err),
        }
        result
    }
}
