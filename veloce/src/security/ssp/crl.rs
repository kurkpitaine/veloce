use super::{SspContainer, SspError, SspResult, SspTrait, SSP_VERSION};

/// Length for CRL SSP.
const CRL_SSP_LEN: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Certificate Trust List Service Specific Permissions.
pub struct CrlSsp(SspContainer<CRL_SSP_LEN>);

impl CrlSsp {
    /// Get the size of [CrlSsp] in buffer.
    pub const fn buf_size() -> usize {
        CRL_SSP_LEN
    }

    /// Constructs a [CrlSsp] with default values.
    pub const fn new() -> CrlSsp {
        CrlSsp(SspContainer::new())
    }

    /// Constructs a [CrlSsp] from bytes, ensuring length and
    /// version are supported.
    pub fn parse(buf: &[u8]) -> SspResult<CrlSsp> {
        // Ensure no panics.
        if buf.len() != CRL_SSP_LEN {
            return Err(SspError::Length);
        }

        // Ensure version is supported.
        if buf[0] != SSP_VERSION {
            return Err(SspError::Version);
        }

        Ok(CrlSsp(SspContainer::from_bytes(buf)))
    }
}

impl SspTrait for CrlSsp {
    type SspType = CrlSsp;

    fn contains_permissions_of(&self, _: &Self::SspType) -> bool {
        true
    }
}
