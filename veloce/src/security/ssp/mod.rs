//! The `ssp` module implements the ETSI TS 102 941 V2.2.1 annex B
//! relative to the Service Specific Permissions (SSP) definition.
//!
//! The Service Specific Permissions (SSP) is a field that indicates specific sets of permissions within the overall
//! permissions indicated by the ITS-AID. The originating ITS-S shall provide SSP information in its certificate for all
//! generated signed messages.
//! The SSP information for Security Management messages is constructed in a common way, containing 1 or more octets
//! depending of the actual service.
//!
//! The first octet shall control the SSP version and be interpreted in the following way:
//! * 0: No version, length 1 octet; the value shall only be used for testing purposes.
//! * 1: First version, SSP contains information as defined in the present module.
//! * 2 to 255: Reserved for future usage.
//!
//! # Warning
//! Beware of ETSI bit position for SSP bits in their documents! Index 0 is defined as the Most Significant Bit,
//! which is the opposite in our code.

use core::fmt;

pub mod cam;
pub mod crl;
pub mod ctl;
pub mod denm;
pub mod scr;

/// SSP result type.
pub type SspResult<T> = core::result::Result<T, SspError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// SSP error type.
pub enum SspError {
    /// Length mismatch.
    Length,
    /// Unsupported version.
    Version,
    /// Illegal permissions.
    Illegal,
    /// Malformed SSP.
    Malformed,
}

impl fmt::Display for SspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SspError::Length => write!(f, "Length mismatch"),
            SspError::Version => write!(f, "Unsupported version"),
            SspError::Illegal => write!(f, "Illegal permissions"),
            SspError::Malformed => write!(f, "Malformed permissions"),
        }
    }
}

/// SSP version 1.
const SSP_VERSION_1: u8 = 1;
/// SSP version 2.
const SSP_VERSION_2: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Generic Service Specific Permissions container.
pub struct SspContainer<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> SspContainer<N> {
    /// Constructs an SSP container with zero values.
    /// Sets the version byte to `version`.
    pub const fn new(version: u8) -> Self {
        let mut inner = [0u8; N];
        inner[0] = version;

        Self { inner }
    }

    /// Constructs an SSP container from a slice.
    pub const fn from_slice(slice: [u8; N]) -> Self {
        Self { inner: slice }
    }

    /// Constructs an SSP container from the provided `buf`.
    ///
    /// # Panics
    ///
    /// This method panics if `buf` is not the same length as
    /// the generic parameter `N`.
    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut inner = [0u8; N];
        inner.copy_from_slice(buf);
        Self { inner }
    }

    /// Consume the container, returning the underlying buffer.
    pub const fn into_inner(self) -> [u8; N] {
        self.inner
    }

    /// Returns the version field of the SSP.
    pub const fn version(&self) -> u8 {
        self.inner[0]
    }

    /// Reads the value of bit `I` in byte `B`.
    pub const fn read_bit<const B: usize, const I: u8>(&self) -> bool {
        let data = &self.inner;
        (data[B] & (1u8 << I)) != 0
    }

    /// Sets the bit state in byte B at index I.
    pub fn write_bit<const B: usize, const I: u8>(&mut self, value: bool) {
        let mask = 1u8 << I;
        let raw = self.inner[B];
        let raw = if value { raw | mask } else { raw & !mask };
        self.inner[B] = raw;
    }
}

pub trait SspTrait {
    type SspType;
    type PermissionType;

    /// Check if SSP contains the permissions of `other`.
    fn contains_permissions_of(&self, other: &Self::SspType) -> bool;

    /// Query whether the inner SSP contains the provided `permission`.
    fn has_permission(&self, permission: Self::PermissionType) -> bool;

    /// Set the corresponding `permission` bit in the SSP.
    fn set_permission(&mut self, permission: Self::PermissionType);

    /// Clear the corresponding `permission` bit in the SSP.
    fn clear_permission(&mut self, permission: Self::PermissionType);
}
