//! Secured Certificate Request messages SSP definition.
//! See ETSI TS 102 941 V2.2.1 section B.4.

use super::{SspContainer, SspError, SspResult, SspTrait, SSP_VERSION_1};

mod field {
    /// SCR CA Certificate Request signing permission bit position.
    pub const CA_REQ: u8 = 1;
    /// SCR Enrollment Response signing permission bit position.
    pub const ENROLLMENT_RESP: u8 = 2;
    /// SCR Authorization Validation Response signing permission bit position.
    pub const AUTHORIZATION_VAL_RESP: u8 = 3;
    /// SCR Authorization Response signing permission bit position.
    pub const AUTHORIZATION_RESP: u8 = 4;
    /// SCR Authorization Validation Request signing permission bit position.
    pub const AUTHORIZATION_VAL_REQ: u8 = 5;
    /// SCR Authorization Request signing permission bit position.
    pub const AUTHORIZATION_REQ: u8 = 6;
    /// SCR Enrollment Request signing permission bit position.
    pub const ENROLLMENT_REQ: u8 = 7;
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured Certificate Request permissions parameters.
pub enum ScrPermission {
    /// SCR CA Certificate Request signing permission.
    CACertReq,
    /// SCR Enrollment Request signing permission.
    EnrollmentReq,
    /// SCR Enrollment Response signing permission.
    EnrollmentResp,
    /// SCR Authorization Validation Request signing permission.
    AuthorizationValidationReq,
    /// SCR Authorization Validation Response signing permission.
    AuthorizationValidationResp,
    /// SCR Authorization Request signing permission.
    AuthorizationReq,
    /// SCR Authorization Response signing permission.
    AuthorizationResp,
}

/// Length for SCR SSP.
const SCR_SSP_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Secured Certificate Request Service Specific Permissions.
pub struct ScrSsp(SspContainer<SCR_SSP_LEN>);

impl ScrSsp {
    /// Constructs an [ScrSsp].
    pub const fn new() -> ScrSsp {
        ScrSsp(SspContainer::new(SSP_VERSION_1))
    }

    /// Get the size of [ScrSsp] in buffer.
    pub const fn buf_size() -> usize {
        SCR_SSP_LEN
    }

    /// Constructs a [ScrSsp] from the provided `permissions` value.
    pub const fn from_raw_permissions(permissions: u8) -> ScrSsp {
        ScrSsp(SspContainer::from_slice([SSP_VERSION_1, permissions]))
    }

    /// Constructs a [ScrSsp] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<ScrSsp> {
        // Ensure no panics.
        if buf.len() < SCR_SSP_LEN {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION_1 {
            return Err(SspError::Version);
        }

        Ok(ScrSsp(SspContainer::from_bytes(buf)))
    }

    /// Emit the SSP as a byte array, consuming itself.
    pub const fn emit(self) -> [u8; SCR_SSP_LEN] {
        self.0.into_inner()
    }

    /// Verifies the SSP combination for a TLM Secured Certificate Request, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_tlm_issuing_permissions(&self) -> SspResult<()> {
        // No bits should be set.
        if self.0.inner[1] != 0 {
            return Err(SspError::Illegal);
        }

        Ok(())
    }

    /// Verifies the SSP combination for an RCA Secured Certificate Request, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_rca_issuing_permissions(&self) -> SspResult<()> {
        // All combinations are valid.
        Ok(())
    }

    /// Verifies the SSP combination for an EA Secured Certificate Request, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_ea_issuing_permissions(&self) -> SspResult<()> {
        if self.has_permission(ScrPermission::AuthorizationValidationReq)
            || self.has_permission(ScrPermission::AuthorizationResp)
        {
            return Err(SspError::Illegal);
        }

        Ok(())
    }

    /// Verifies the SSP combination for an AA Secured Certificate Request, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_aa_issuing_permissions(&self) -> SspResult<()> {
        if self.has_permission(ScrPermission::EnrollmentReq)
            || self.has_permission(ScrPermission::EnrollmentResp)
            || self.has_permission(ScrPermission::AuthorizationReq)
            || self.has_permission(ScrPermission::AuthorizationValidationResp)
        {
            return Err(SspError::Illegal);
        }

        Ok(())
    }

    /// Verifies the SSP combination for an EC Secured Certificate Request, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_ec_issuing_permissions(&self) -> SspResult<()> {
        if self.has_permission(ScrPermission::CACertReq)
            || self.has_permission(ScrPermission::AuthorizationValidationResp)
            || self.has_permission(ScrPermission::AuthorizationValidationReq)
            || self.has_permission(ScrPermission::AuthorizationResp)
            || self.has_permission(ScrPermission::EnrollmentResp)
        {
            return Err(SspError::Illegal);
        }

        Ok(())
    }

    /// Verifies the SSP combination for an AT Secured Certificate Request, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_at_issuing_permissions(&self) -> SspResult<()> {
        // No bits should be set.
        if self.0.inner[1] != 0 {
            return Err(SspError::Illegal);
        }

        Ok(())
    }
}

impl Default for ScrSsp {
    fn default() -> Self {
        Self::new()
    }
}

impl SspTrait for ScrSsp {
    type SspType = ScrSsp;
    type PermissionType = ScrPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        self.0.inner[1] | other.0.inner[1] == self.0.inner[1]
    }

    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match permission {
            ScrPermission::CACertReq => self.0.read_bit::<1, { field::CA_REQ }>(),
            ScrPermission::EnrollmentReq => self.0.read_bit::<1, { field::ENROLLMENT_REQ }>(),
            ScrPermission::EnrollmentResp => self.0.read_bit::<1, { field::ENROLLMENT_RESP }>(),
            ScrPermission::AuthorizationValidationReq => {
                self.0.read_bit::<1, { field::AUTHORIZATION_VAL_REQ }>()
            }
            ScrPermission::AuthorizationValidationResp => {
                self.0.read_bit::<1, { field::AUTHORIZATION_VAL_RESP }>()
            }
            ScrPermission::AuthorizationReq => self.0.read_bit::<1, { field::AUTHORIZATION_REQ }>(),
            ScrPermission::AuthorizationResp => {
                self.0.read_bit::<1, { field::AUTHORIZATION_RESP }>()
            }
        }
    }

    fn set_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            ScrPermission::CACertReq => self.0.write_bit::<1, { field::CA_REQ }>(true),
            ScrPermission::EnrollmentReq => self.0.write_bit::<1, { field::ENROLLMENT_REQ }>(true),
            ScrPermission::EnrollmentResp => {
                self.0.write_bit::<1, { field::ENROLLMENT_RESP }>(true)
            }
            ScrPermission::AuthorizationValidationReq => self
                .0
                .write_bit::<1, { field::AUTHORIZATION_VAL_REQ }>(true),
            ScrPermission::AuthorizationValidationResp => self
                .0
                .write_bit::<1, { field::AUTHORIZATION_VAL_RESP }>(true),
            ScrPermission::AuthorizationReq => {
                self.0.write_bit::<1, { field::AUTHORIZATION_REQ }>(true)
            }
            ScrPermission::AuthorizationResp => {
                self.0.write_bit::<1, { field::AUTHORIZATION_RESP }>(true)
            }
        }
    }

    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            ScrPermission::CACertReq => self.0.write_bit::<1, { field::CA_REQ }>(false),
            ScrPermission::EnrollmentReq => self.0.write_bit::<1, { field::ENROLLMENT_REQ }>(false),
            ScrPermission::EnrollmentResp => {
                self.0.write_bit::<1, { field::ENROLLMENT_RESP }>(false)
            }
            ScrPermission::AuthorizationValidationReq => self
                .0
                .write_bit::<1, { field::AUTHORIZATION_VAL_REQ }>(false),
            ScrPermission::AuthorizationValidationResp => self
                .0
                .write_bit::<1, { field::AUTHORIZATION_VAL_RESP }>(false),
            ScrPermission::AuthorizationReq => {
                self.0.write_bit::<1, { field::AUTHORIZATION_REQ }>(false)
            }
            ScrPermission::AuthorizationResp => {
                self.0.write_bit::<1, { field::AUTHORIZATION_RESP }>(false)
            }
        }
    }
}
