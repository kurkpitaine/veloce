use crate::{
    security::{
        certificate::{AuthorizationTicketCertificate, CertificateTrait, ExplicitCertificate},
        secured_message::{SecuredMessage, SignerIdentifier},
        HashAlgorithm, HashedId8,
    },
    time::Instant,
};

use super::{SecurityService, SecurityServiceError};

/// Verify service result type.
pub type VerifyResult = Result<bool, SecurityServiceError>;

impl SecurityService<'_> {
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
        let signer_id = msg
            .signer_identifier()
            .map_err(SecurityServiceError::InvalidContent)?;

        // Get the AT certificate.
        let signer_cert = match signer_id {
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
                let at_cert = AuthorizationTicketCertificate::from_etsi_cert(cert, self.backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                let at_digest = at_cert
                    .hashed_id8(self.backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                if self.store.is_revoked(at_digest) {
                    return Err(SecurityServiceError::RevokedCertificate);
                }

                at_cert
                    .check(timestamp, self.backend, |sh| self.store.lookup_aa(sh))
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                // Certificate has been checked and its trust chain is known.
                self.cache.fill(at_digest, at_cert.clone(), timestamp);

                at_cert
            }
        };

        // Get public verification key.
        let signer_pubkey = signer_cert
            .public_verification_key()
            .map_err(SecurityServiceError::InvalidCertificate)?;
        let signer_data = signer_cert.raw_bytes();

        // Get content to verify.
        let tbs = msg
            .to_be_signed_bytes()
            .map_err(SecurityServiceError::InvalidContent)?;

        let hash = match signature.hash_algorithm() {
            HashAlgorithm::SHA256 => {
                [self.backend.sha256(&tbs), self.backend.sha256(signer_data)].concat()
            }
            HashAlgorithm::SHA384 => {
                [self.backend.sha384(&tbs), self.backend.sha384(signer_data)].concat()
            }
        };

        // Verify AID permission.
        let aid = msg
            .application_id()
            .map_err(SecurityServiceError::InvalidContent)?;
        let signer_permissions = signer_cert
            .application_permissions()
            .map_err(SecurityServiceError::InvalidCertificate)?;
        if signer_permissions.iter().find(|e| e.aid() == aid).is_none() {
            return Err(SecurityServiceError::InsufficientPermissions);
        }

        // Verify generation time vs cert validity period.
        if !signer_cert
            .validity_period()
            .contains_instant(generation_time)
        {
            return Err(SecurityServiceError::OffValidityPeriod);
        }

        let res = self
            .backend
            .verify_signature(signature, signer_pubkey, &hash)
            .map_err(|_| SecurityServiceError::Backend)?;

        Ok(res)
    }
}
