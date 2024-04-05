#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![cfg_attr(not(test), no_std)]

// Reexport Rasn
pub mod prelude {
    pub use rasn;
}

pub mod defs {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
