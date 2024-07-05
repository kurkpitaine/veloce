//! SN-ENCAP service as defined in ETSI TS 102 723-8 V1.1.1 paragraph 5.2.12.

use crate::{
    security::{permission::Permission, secured_message::SecuredMessage},
    time::Instant,
};

use super::{SecurityService, SecurityServiceError};

/// Decap service result type.
pub type EncapResult = Result<EncapConfirm, SecurityServiceError>;

/// Decap service confirmation.
pub type EncapConfirm = Vec<u8>;

impl SecurityService {
    /// Encapsulates the given `packet` into the security envelope.
    /// Message is signed according to the given `permissions` and `timestamp`.
    pub fn encap_packet(
        &mut self,
        packet: &[u8],
        permissions: Permission,
        timestamp: Instant,
    ) -> EncapResult {
        let mut message = SecuredMessage::new(packet);

        self.sign_secured_message(&mut message, permissions, timestamp)?;

        message
            .into_bytes()
            .map_err(SecurityServiceError::InvalidContent)
    }
}
