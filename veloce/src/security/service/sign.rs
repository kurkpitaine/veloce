use crate::{
    security::{
        certificate::{CertificateTrait, ExplicitCertificate},
        permission::Permission,
        secured_message::{SecuredMessage, SignerIdentifier},
    },
    time::{Instant, TAI2004},
};

use super::{SecurityService, SecurityServiceError};

/// Sign service result type.
pub type SignResult = Result<(), SecurityServiceError>;

impl SecurityService {
    /// Sign `message`. Should contain the data to be signed.
    /// `permission` is the permission requested by the message.
    /// `timestamp` is the timestamp (generation time) of the message.
    pub fn sign_secured_message(
        &mut self,
        message: &mut SecuredMessage,
        permission: Permission,
        timestamp: Instant,
    ) -> SignResult {
        let at = self
            .store
            .own_chain()
            .at_cert()
            .as_ref()
            .ok_or(SecurityServiceError::NoSigningCertificate)?
            .certificate();

        // Check AT is not expired.
        if TAI2004::from_unix_instant(timestamp) > at.validity_period().end {
            return Err(SecurityServiceError::OffValidityPeriod);
        }

        // Check AT has permission to sign aid.
        let at_permissions = at
            .application_permissions()
            .map_err(SecurityServiceError::InvalidCertificate)?;

        match at_permissions.iter().find(|p| p.aid() == permission.aid()) {
            Some(p) if p.contains_permissions_of(&permission) => {}
            _ => return Err(SecurityServiceError::InsufficientPermissions),
        }

        // Set generation time.
        message
            .set_generation_time(TAI2004::from_unix_instant(timestamp))
            .map_err(SecurityServiceError::InvalidContent)?;

        // Set application identifier.
        message
            .set_application_id(permission.aid())
            .map_err(SecurityServiceError::InvalidContent)?;

        // Fill Secured Message with AT certificate.
        let signer = SignerIdentifier::Certificate(at.inner().clone());
        message
            .set_signer_identifier(signer)
            .map_err(SecurityServiceError::InvalidContent)?;

        let signer_data = at.raw_bytes();
        let tbs = message
            .to_be_signed_bytes()
            .map_err(SecurityServiceError::InvalidContent)?;

        let backend = self.backend.inner();
        let hash = [backend.sha256(&tbs), backend.sha256(signer_data)].concat();

        let signature = backend
            .generate_signature(&hash)
            .map_err(|_| SecurityServiceError::Backend)?;

        message
            .set_signature(signature)
            .map_err(SecurityServiceError::InvalidContent)?;

        Ok(())
    }
}
