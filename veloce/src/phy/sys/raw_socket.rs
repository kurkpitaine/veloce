use super::*;
use crate::phy::Medium;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{io, mem};

#[derive(Debug)]
pub struct RawSocketDesc {
    protocol: libc::c_short,
    lower: libc::c_int,
    ifreq: ifreq,
}

impl AsRawFd for RawSocketDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl RawSocketDesc {
    pub fn new(name: &str, medium: Medium) -> io::Result<RawSocketDesc> {
        let protocol = match medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => imp::ETH_P_ALL,
            #[cfg(feature = "medium-ieee80211p")]
            Medium::Ieee80211p => imp::ETH_P_ALL,
            #[cfg(feature = "medium-pc5")]
            Medium::PC5 => imp::ETH_P_ALL,
        };

        let lower = unsafe {
            let lower = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                protocol.to_be() as i32,
            );
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        Ok(RawSocketDesc {
            protocol,
            lower,
            ifreq: ifreq_for(name),
        })
    }

    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        ifreq_ioctl(self.lower, &mut self.ifreq, imp::SIOCGIFMTU).map(|mtu| mtu as usize)
    }

    pub fn bind_interface(&mut self) -> io::Result<()> {
        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: self.protocol.to_be() as u16,
            sll_ifindex: ifreq_ioctl(self.lower, &mut self.ifreq, imp::SIOCGIFINDEX)?,
            sll_hatype: 1,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };

        unsafe {
            let res = libc::bind(
                self.lower,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    /// Enables the promiscuous mode on the interface
    pub fn promiscuous_mode(&mut self) -> io::Result<()> {
        let mr = libc::packet_mreq {
            mr_ifindex: ifreq_ioctl(self.lower, &mut self.ifreq, imp::SIOCGIFINDEX)?,
            mr_type: libc::PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };

        unsafe {
            let res = libc::setsockopt(
                self.lower,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mr as *const libc::packet_mreq as *const libc::c_void,
                mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            );

            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::recv(
                self.lower,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            );
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::send(
                self.lower,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                0,
            );
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }
}

impl Drop for RawSocketDesc {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.lower);
        }
    }
}
