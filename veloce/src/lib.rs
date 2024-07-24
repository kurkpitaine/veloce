#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(unsafe_code)]

#[macro_use]
extern crate uom;

#[macro_use]
pub mod macros;

#[cfg(feature = "conformance")]
pub mod conformance;

pub mod common;
pub mod config;
pub mod iface;
pub mod network;
pub mod phy;
pub mod rand;
pub mod socket;
pub mod storage;
pub mod time;
pub mod types;
pub mod utils;
pub mod wire;

#[cfg(feature = "proto-security")]
pub mod security;

#[cfg(all(
    test,
    any(
        feature = "medium-ethernet",
        feature = "medium-ieee80211p",
        feature = "medium-pc5"
    )
))]
mod tests;
