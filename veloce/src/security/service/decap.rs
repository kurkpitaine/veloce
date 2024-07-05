//! SN-DECAP service as defined in ETSI TS 102 723-8 V1.1.1 paragraph 5.2.13.

use veloce_asn1::prelude::rasn::types::OctetString;

use crate::{
    security::{permission::Permission, secured_message::SecuredMessage, HashedId8},
    time::Instant,
};

use super::{SecurityService, SecurityServiceError};

/// Decap service result type.
pub type DecapResult = Result<(DecapConfirm, OctetString), SecurityServiceError>;

/// Decap service confirmation.
#[derive(Debug, Clone)]
pub struct DecapConfirm {
    /// Deserialized secured message. For forwarding purposes.
    pub secured_message: SecuredMessage,
    /// Size of the secured message over the air.
    pub size: usize,
    /// Certificate Id, ie: digest of the certificate
    /// as HashId8.
    pub cert_id: HashedId8,
    /// Service Specific Permissions.
    pub permissions: Permission,
}

impl SecurityService {
    pub fn decap_packet(&mut self, packet: &[u8], timestamp: Instant) -> DecapResult {
        let msg =
            SecuredMessage::from_bytes(packet).map_err(SecurityServiceError::InvalidContent)?;
        let payload = msg
            .payload()
            .map_err(SecurityServiceError::InvalidContent)?
            .clone();
        let confirm = self.verify_secured_message(&msg, timestamp)?;

        Ok((
            DecapConfirm {
                secured_message: msg,
                size: packet.len(),
                cert_id: confirm.cert_id,
                permissions: confirm.permissions,
            },
            payload,
        ))
    }
}
