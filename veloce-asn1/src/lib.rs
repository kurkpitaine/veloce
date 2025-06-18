#![allow(clippy::large_enum_variant)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![cfg_attr(not(test), no_std)]

#[cfg(feature = "etsi-security-r2")]
mod etsi_103097_v211;

#[cfg(feature = "etsi-pki-r2")]
mod etsi_102941_v221;

#[cfg(any(
    feature = "etsi-cdd-r2",
    feature = "etsi-cam-r2",
    feature = "etsi-denm-r2"
))]
mod etsi_messages_r2;

// Reexport Rasn
pub mod prelude {
    pub use num_traits;
    pub use rasn;
}

pub mod defs {
    #[cfg(feature = "etsi-security-r2")]
    pub mod etsi_103097_v211 {
        pub use crate::etsi_103097_v211::*;
    }

    #[cfg(feature = "etsi-pki-r2")]
    pub mod etsi_102941_v221 {
        pub use crate::etsi_102941_v221::*;
    }

    #[cfg(any(
        feature = "etsi-cdd-r2",
        feature = "etsi-cam-r2",
        feature = "etsi-denm-r2"
    ))]
    pub mod etsi_messages_r2 {
        pub use crate::etsi_messages_r2::*;
    }
}
