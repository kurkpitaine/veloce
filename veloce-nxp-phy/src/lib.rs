#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub(crate) mod ffi {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use core::fmt;

pub mod config;
pub mod llc;
pub mod usb;
pub mod usb_phy;

pub use config::{
    Channel as NxpChannel, Config as NxpConfig, Radio as NxpRadio,
    WirelessChannel as NxpWirelessChannel,
};
pub use llc::NxpLlcDevice;
pub use usb::NxpUsbDevice;

/// Max raw frame array size.
pub const RAW_FRAME_LENGTH_MAX: usize = 1518;
/// NXP LLC Tx/Rx buffer length.
pub const LLC_BUFFER_LEN: usize = 4096;

#[derive(Debug)]
pub enum Error {
    /// Operation has expired.
    Timeout,
    /// No Rx packet in buffer.
    NoRxPacket,
    /// An error occured during USB operation.
    USB,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Timeout => f.write_str("timeout"),
            Error::NoRxPacket => f.write_str("no rx packet in buffer"),
            Error::USB => f.write_str("USB error"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
