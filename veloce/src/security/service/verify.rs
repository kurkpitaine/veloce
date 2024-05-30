use crate::{
    security::{
        certificate::{Certificate, HashedId8},
        secured_message::{SecuredMessage, SignerIdentifier},
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

        // Extract signer identifier.
        let signer = msg
            .signer_identifier()
            .map_err(SecurityServiceError::InvalidContent)?;

        let certificate = match signer {
            SignerIdentifier::Digest(hash) => {
                let digest = HashedId8::from_bytes(&hash.0);
                match self.cache.lookup(&digest, timestamp) {
                    Some(cert) => cert,
                    None => {
                        // Per ETSI TS 103 097 v2.1.1, paragraph 7.1, we shall
                        // include the AT certificate in next CAM transmission.
                        self.next_cert_in_cam_at = Instant::ZERO;
                        return Err(SecurityServiceError::SignerCertificateNotFound);
                    }
                }
            }
            SignerIdentifier::Certificate(cert) => {
                //TODO: Verify certificate.
                //TODO: check certificate canonicalization.
                //TODO: fill cache with the received certificate.
                /* let digest = cert.0.
                self.cache.fill(digest, certificate, timestamp)
                Certificate::from_etsi_at(cert) */
                Certificate::from_etsi_certificate(cert)
                    .map_err(|_| SecurityServiceError::InvalidCertificate)?
            }
        };

        Ok(())
    }
}
