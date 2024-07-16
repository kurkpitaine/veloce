use super::{SspContainer, SspError, SspResult, SspTrait, SSP_VERSION_1};

/// ECTL permissions.
pub const TLM_CTL: CtlSsp = CtlSsp::from_raw_permissions(0xc8);
/// Root CA CTL permissions.
pub const RCA_CTL: CtlSsp = CtlSsp::from_raw_permissions(0x38);

mod field {
    /// CTL DC signing permission bit position.
    pub const DC: u8 = 3;
    /// CTL AA signing permission bit position.
    pub const AA: u8 = 4;
    /// CTL EA signing permission bit position.
    pub const EA: u8 = 5;
    /// CTL Root CA signing permission bit position.
    pub const RCA: u8 = 6;
    /// CTL TLM signing permission bit position.
    pub const TLM: u8 = 7;
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// CTL permissions parameters.
pub enum CtlPermission {
    /// CTL DC signing permission.
    DistributionCenter,
    /// CTL AA signing permission.
    AuthorizationAuthority,
    /// CTL EA signing permission.
    EnrollmentAuthority,
    /// CTL Root CA signing permission.
    Root,
    /// CTL TLM signing permission.
    TrustedListManager,
}

/// Length for CTL SSP.
const CTL_SSP_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Certificate Trust List Service Specific Permissions.
pub struct CtlSsp(SspContainer<CTL_SSP_LEN>);

impl CtlSsp {
    /// Get the size of [CtlSsp] in buffer.
    pub const fn buf_size() -> usize {
        CTL_SSP_LEN
    }

    /// Constructs a [CtlSsp] from the provided `permissions` value.
    pub const fn from_raw_permissions(permissions: u8) -> CtlSsp {
        CtlSsp(SspContainer::from_slice([SSP_VERSION_1, permissions]))
    }

    /// Constructs a [CtlSsp] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<CtlSsp> {
        // Ensure no panics.
        if buf.len() < CTL_SSP_LEN {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION_1 {
            return Err(SspError::Version);
        }

        Ok(CtlSsp(SspContainer::from_bytes(buf)))
    }

    /// Verifies the SSP combination for a TLM CTL certificate, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_tlm_issuing_permissions(&self) -> SspResult<()> {
        if self.has_permission(CtlPermission::EnrollmentAuthority)
            || self.has_permission(CtlPermission::AuthorizationAuthority)
        {
            return Err(SspError::Illegal);
        }

        Ok(())
    }

    /// Verifies the SSP combination for a RCA CTL certificate, according to the
    /// ETSI TS 102 941 V2.2.1 table B.6.
    pub fn verify_rca_issuing_permissions(&self) -> SspResult<()> {
        if self.has_permission(CtlPermission::TrustedListManager)
            || self.has_permission(CtlPermission::Root)
        {
            return Err(SspError::Illegal);
        }

        Ok(())
    }
}

impl SspTrait for CtlSsp {
    type SspType = CtlSsp;
    type PermissionType = CtlPermission;

    fn contains_permissions_of(&self, other: &Self::SspType) -> bool {
        self.0.inner[1] | other.0.inner[1] == self.0.inner[1]
    }

    /// Query whether the inner SSP contains the provided `permission`.
    fn has_permission(&self, permission: Self::PermissionType) -> bool {
        match permission {
            CtlPermission::DistributionCenter => self.0.read_bit::<1, { field::DC }>(),
            CtlPermission::AuthorizationAuthority => self.0.read_bit::<1, { field::AA }>(),
            CtlPermission::EnrollmentAuthority => self.0.read_bit::<1, { field::EA }>(),
            CtlPermission::Root => self.0.read_bit::<1, { field::RCA }>(),
            CtlPermission::TrustedListManager => self.0.read_bit::<1, { field::TLM }>(),
        }
    }

    /// Set the corresponding `permission` bit in the SSP.
    fn set_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            CtlPermission::DistributionCenter => self.0.write_bit::<1, { field::DC }>(true),
            CtlPermission::AuthorizationAuthority => self.0.write_bit::<1, { field::AA }>(true),
            CtlPermission::EnrollmentAuthority => self.0.write_bit::<1, { field::EA }>(true),
            CtlPermission::Root => self.0.write_bit::<1, { field::RCA }>(true),
            CtlPermission::TrustedListManager => self.0.write_bit::<1, { field::TLM }>(true),
        }
    }

    /// Clear the corresponding `permission` bit in the SSP.
    fn clear_permission(&mut self, permission: Self::PermissionType) {
        match permission {
            CtlPermission::DistributionCenter => self.0.write_bit::<1, { field::DC }>(false),
            CtlPermission::AuthorizationAuthority => self.0.write_bit::<1, { field::AA }>(false),
            CtlPermission::EnrollmentAuthority => self.0.write_bit::<1, { field::EA }>(false),
            CtlPermission::Root => self.0.write_bit::<1, { field::RCA }>(false),
            CtlPermission::TrustedListManager => self.0.write_bit::<1, { field::TLM }>(false),
        }
    }
}
