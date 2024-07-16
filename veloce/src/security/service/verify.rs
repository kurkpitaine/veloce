use crate::{
    security::{
        certificate::{AuthorizationTicketCertificate, CertificateTrait, ExplicitCertificate},
        permission::Permission,
        secured_message::{SecuredMessage, SignerIdentifier},
        HashAlgorithm, HashedId8,
    },
    time::Instant,
};

use super::{SecurityService, SecurityServiceError};

/// Verify service confirmation.s
pub struct VerifyConfirm {
    /// Certificate Id, ie: digest of the certificate
    /// as HashId8.
    pub cert_id: HashedId8,
    /// Service Specific Permissions.
    pub permissions: Permission,
}

/// Verify service result type.
pub type VerifyResult = Result<VerifyConfirm, SecurityServiceError>;

impl SecurityService {
    /// Verify the signature of a secured message.
    pub fn verify_secured_message(
        &mut self,
        msg: &SecuredMessage,
        timestamp: Instant,
    ) -> VerifyResult {
        let backend = self.backend.inner();

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
        let (signer_cert, at_digest) = match signer_id {
            SignerIdentifier::Digest(hash) => {
                let at_digest = HashedId8::from(&hash);
                match self.cache.lookup(&at_digest, timestamp) {
                    Some(cert) => (cert, at_digest), // Cached certs are considered trusted.
                    None => {
                        // Per ETSI TS 103 097 v2.1.1, paragraph 7.1, we shall
                        // include the AT certificate in next CAM transmission.
                        self.next_cert_in_cam_at = Instant::ZERO;
                        return Err(SecurityServiceError::SignerCertificateNotFound);
                    }
                }
            }
            SignerIdentifier::Certificate(cert) => {
                let at_cert = AuthorizationTicketCertificate::from_etsi_cert(cert, backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                let at_digest = at_cert
                    .hashed_id8(backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                if self.store.is_revoked(at_digest) {
                    return Err(SecurityServiceError::RevokedCertificate);
                }

                at_cert
                    .check(timestamp, backend, |sh| self.store.lookup_aa(sh))
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                // Certificate has been checked and its trust chain is known.
                self.cache.fill(at_digest, at_cert.clone(), timestamp);

                (at_cert, at_digest)
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
            HashAlgorithm::SHA256 => [backend.sha256(&tbs), backend.sha256(signer_data)].concat(),
            HashAlgorithm::SHA384 => [backend.sha384(&tbs), backend.sha384(signer_data)].concat(),
        };

        // Verify AID permission.
        let aid = msg
            .application_id()
            .map_err(SecurityServiceError::InvalidContent)?;
        let signer_permissions = signer_cert
            .application_permissions()
            .map_err(SecurityServiceError::InvalidCertificate)?;

        let Some(permisssion) = signer_permissions.iter().find(|e| e.aid() == aid) else {
            return Err(SecurityServiceError::InsufficientPermissions);
        };

        // Verify generation time vs cert validity period.
        if !signer_cert
            .validity_period()
            .contains_instant(generation_time)
        {
            return Err(SecurityServiceError::OffValidityPeriod);
        }

        let res = backend
            .verify_signature(signature, signer_pubkey, &hash)
            .map_err(SecurityServiceError::Backend)?;

        if res {
            Ok(VerifyConfirm {
                cert_id: at_digest,
                permissions: permisssion.to_owned(),
            })
        } else {
            Err(SecurityServiceError::FalseSignature)
        }
    }
}
