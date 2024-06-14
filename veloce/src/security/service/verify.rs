use crate::{
    security::{
        backend::Backend,
        certificate::{
            AuthorizationAuthorityCertificate, AuthorizationTicketCertificate, ExplicitCertificate,
        },
        secured_message::{SecuredMessage, SignerIdentifier},
        HashedId8,
    },
    time::Instant,
};

use super::{SecurityService, SecurityServiceError};

/// Verify service result type.
pub type VerifyResult = Result<(), SecurityServiceError>;

impl SecurityService {
    /// Verify the signature of a secured message.
    pub fn verify_secured_message(
        &mut self,
        msg: &SecuredMessage,
        timestamp: Instant,
    ) -> VerifyResult {
        // Retrieve generation time.
        let generation_time = msg
            .generation_time()
            .map_err(SecurityServiceError::InvalidContent)?;

        // Get signature.
        let signature = msg
            .signature()
            .map_err(SecurityServiceError::InvalidContent)?;

        // Get signer identifier.
        let signer = msg
            .signer_identifier()
            .map_err(SecurityServiceError::InvalidContent)?;

        // Get the AT certificate.
        let certificate = match signer {
            SignerIdentifier::Digest(hash) => {
                let digest = HashedId8::from_bytes(hash.0.as_slice());
                match self.cache.lookup(&digest, timestamp) {
                    Some(cert) => cert, // Cached certs are considered trusted.
                    None => {
                        // Per ETSI TS 103 097 v2.1.1, paragraph 7.1, we shall
                        // include the AT certificate in next CAM transmission.
                        self.next_cert_in_cam_at = Instant::ZERO;
                        return Err(SecurityServiceError::SignerCertificateNotFound);
                    }
                }
            }
            SignerIdentifier::Certificate(cert) => {
                let at_cert = AuthorizationTicketCertificate::from_etsi_cert(cert, &self.backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                let at_digest = at_cert
                    .hashed_id8(&self.backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                if self.store.is_revoked(at_digest) {
                    return Err(SecurityServiceError::RevokedCertificate);
                }

                at_cert
                    .check(timestamp, &self.backend, |sh| self.store.lookup_aa(sh))
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                // Certificate has been checked and its trust chain is known.
                self.cache.fill(at_digest, at_cert.clone(), timestamp);

                at_cert
            }
        };

        Ok(())
    }
}
