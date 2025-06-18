use core::cell::RefCell;
use std::{
    io,
    net::{ToSocketAddrs, UdpSocket as UdpSocketInner},
    os::fd::{AsRawFd, RawFd},
    rc::Rc,
};

use mio::{event::Source, unix::SourceFd};

use crate::phy::{self, Device, DeviceCapabilities, Medium};
use crate::time::Instant;

/// A socket that captures or transmits over an UDP socket.
#[derive(Debug)]
pub struct UdpSocket<A: ToSocketAddrs> {
    medium: Medium,
    lower: Rc<RefCell<UdpSocketInner>>,
    dst: A,
}

impl<A: ToSocketAddrs> AsRawFd for UdpSocket<A> {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl<A: ToSocketAddrs> UdpSocket<A> {
    /// Creates an UDP socket, bound to the ip:port `bind_addr`
    /// which sends packets to the ip:port `dst_addr`.
    pub fn new(bind_addr: A, dst_addr: A, medium: Medium) -> io::Result<UdpSocket<A>> {
        let lower = UdpSocketInner::bind(bind_addr)?;
        lower.set_nonblocking(true)?;

        Ok(UdpSocket {
            medium,
            lower: Rc::new(RefCell::new(lower)),
            dst: dst_addr,
        })
    }
}

impl<A: ToSocketAddrs + Clone> Device for UdpSocket<A> {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;

    type TxToken<'a>
        = TxToken<A>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let lower = self.lower.borrow_mut();
        let mut buffer = vec![0; 1500];

        match lower.recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken {
                    lower: self.lower.clone(),
                    destination: self.dst.clone(),
                };
                Some((rx, tx))
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
            Err(err) => panic!("{}", err),
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            lower: self.lower.clone(),
            destination: self.dst.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            medium: self.medium,
            max_transmission_unit: 1500,
            ..DeviceCapabilities::default()
        }
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken<A: ToSocketAddrs> {
    lower: Rc<RefCell<UdpSocketInner>>,
    destination: A,
}

impl<A: ToSocketAddrs> phy::TxToken for TxToken<A> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        match lower.send_to(&buffer[..], self.destination) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                net_debug!("phy: tx failed due to WouldBlock")
            }
            Err(err) => panic!("{}", err),
        }
        result
    }
}

impl<A: ToSocketAddrs> Source for UdpSocket<A> {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).deregister(registry)
    }
}
