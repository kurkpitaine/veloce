#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![cfg_attr(not(test), no_std)]

//mod ieee1609dot2_2023;
mod etsi_103097_v211;

// Reexport Rasn
pub mod prelude {
    pub use rasn;
}

pub mod defs {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    // include!(concat!(env!("OUT_DIR"), "/bindings_etsi_103097_v211.rs"));
    // include!(concat!(env!("OUT_DIR"), "/bindings_ieee1609dot2_2023.rs"));
    //pub use super::ieee1609dot2_2023::*;
    /// ECTL viewer available at https://via.teskalabs.com/cits/cpoc-ectl/?tenant=cpoc-ectl-l0#/cits/home
    /// https://2.fr-dc.l1.c-its-pki.fr/
    pub mod etsi_103097_v211 {
        pub use crate::etsi_103097_v211::*;
    }
}
