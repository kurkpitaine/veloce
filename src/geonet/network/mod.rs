/*! Networking layer logic.

The `Network` module implements the Geonetworking protocol logic. It provides the maintenance of the
mandatory data structures of a Geonetworking router and handles the incoming and outgoing packets.
*/

pub mod access_handler;
pub mod core;
pub mod router;

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                // concat!/stringify! doesn't work with defmt macros
                /* #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed"); */
                println!("network: malformed {} ", stringify!($e));
                return Default::default();
            }
        }
    };
}
use check;
