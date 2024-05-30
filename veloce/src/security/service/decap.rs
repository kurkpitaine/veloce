//! SN-DECAP service as defined in ETSI TS 102 723-8 V1.1.1 paragraph 5.2.13.
//!
//!

use crate::{
    security::{certificate::HashedId8, secured_message::SecuredMessage},
    time::Instant,
};

use super::{SecurityService, SecurityServiceError};

/// Decap service result type.
pub type DecapResult = Result<DecapConfirm, SecurityServiceError>;

/// Decap service confirmation.
pub struct DecapConfirm {
    /// Certificate Id, ie: digest of the certificate
    /// as HashId8.
    pub cert_id: HashedId8,
    /// ITS application ID.
    pub its_aid: (),
    /// Service Specific Permissions.
    pub permissions: (),
}

impl SecurityService {
    pub fn decap_packet(&mut self, packet: &[u8], timestamp: Instant) -> DecapResult {
        let msg =
            SecuredMessage::from_bytes(packet).map_err(SecurityServiceError::InvalidContent)?;
        let _ = self.verify_secured_message(&msg, timestamp);

        Err(SecurityServiceError::DecryptionError)
    }
}
