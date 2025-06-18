#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub(crate) mod ffi {
    #![allow(unused)]
    #![allow(clippy::all)]
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
pub enum NxpError {
    /// Operation has expired.
    Timeout,
    /// No Rx packet in buffer.
    NoRxPacket,
    /// An error occured during USB operation.
    USB,
    /// Radio error. Contains the error code.
    Radio(i16),
    /// IO error.
    IO(std::io::Error),
}

impl fmt::Display for NxpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            NxpError::Timeout => f.write_str("timeout"),
            NxpError::NoRxPacket => f.write_str("no rx packet in buffer"),
            NxpError::USB => f.write_str("USB error"),
            NxpError::Radio(code) => write!(f, "Radio error: {}", code),
            NxpError::IO(ref e) => write!(f, "IO error: {}", e),
        }
    }
}

pub type NxpResult<T> = core::result::Result<T, NxpError>;
