use super::{Ssp, SspError, SspResult, SSP_VERSION};

/// Length for CRL SSP.
const CRL_SSP_LEN: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Certificate Trust List Service Specific Permissions.
pub struct CrlSsp(Ssp<CRL_SSP_LEN>);

impl CrlSsp {
    /// Constructs a [CrlSsp] with default values.
    pub const fn new() -> CrlSsp {
        CrlSsp(Ssp::new())
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

        Ok(CrlSsp(Ssp::from_bytes(buf)))
    }
}
