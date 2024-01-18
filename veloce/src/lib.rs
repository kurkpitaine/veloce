#[macro_use]
extern crate uom;

#[macro_use]
pub mod macros;

#[cfg(feature = "conformance")]
pub mod conformance;

pub mod apps;
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

#[cfg(all(
    test,
    any(
        feature = "medium-ethernet",
        feature = "medium-ieee80211p",
        feature = "medium-pc5"
    )
))]
mod tests;
