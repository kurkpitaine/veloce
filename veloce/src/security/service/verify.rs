use crate::{
    security::{
        backend::BackendTrait,
        certificate::{
            AuthorizationTicketCertificate, CertificateError, CertificateTrait, ExplicitCertificate,
        },
        permission::{Permission, AID},
        secured_message::{SecuredMessage, SignerIdentifier},
        HashAlgorithm, HashedId8,
    },
    time::Instant,
};

use super::{SecurityService, SecurityServiceError};

/// Verify service confirmation.
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

        // Get application identifier.
        let aid = msg
            .application_id()
            .map_err(SecurityServiceError::InvalidContent)?;

        // Get requested certificates.
        let p2p_requested_certs = msg
            .p2p_requested_certificates()
            .map_err(SecurityServiceError::InvalidContent)?;

        if aid == AID::CA {
            // Check if our AT certificate is requested.
            let at_requested = self
                .store
                .own_chain()
                .at_cert()
                .as_ref()
                .map_or(false, |at| {
                    p2p_requested_certs.contains(&at.hashed_id8().into())
                });

            // Check if our AA certificate is requested.
            let aa_requested = self
                .store
                .own_chain()
                .aa_cert()
                .as_ref()
                .map_or(false, |aa| {
                    p2p_requested_certs.contains(&aa.hashed_id8().into())
                });

            if at_requested {
                // Per ETSI TS 103 097 v2.1.1, paragraph 7.1.1, we shall
                // include the AT certificate in next CAM transmission if it is
                // included in the requested certificates.
                self.at_cert_in_cam_at = Instant::ZERO;
            }

            if aa_requested {
                // Per ETSI TS 103 097 v2.1.1, paragraph 7.1.1, we shall
                // include the AA certificate in next CAM transmission if it is
                // included in the requested certificates.
                self.aa_cert_in_cam = true;
            }
        }

        // Get the AT certificate.
        let (signer_cert, at_digest) = match signer_id {
            SignerIdentifier::Digest(hash) => {
                if aid == AID::CA {
                    // Requested certificate is sent only if the signer is digest.
                    let maybe_cert = msg
                        .requested_certificate()
                        .map_err(SecurityServiceError::InvalidContent)?;

                    if let Some(cert) = maybe_cert {
                        self.verify_certificate_request(cert, timestamp)
                            .map_err(SecurityServiceError::CertificateRequest)?;
                    }
                }

                let at_digest = HashedId8::from(&hash);
                match self.cache.lookup(&at_digest, timestamp) {
                    Some(cert) => (cert, at_digest), // Cached certs are considered trusted.
                    None => {
                        // Per ETSI TS 103 097 v2.1.1, paragraph 7.1.1, we shall
                        // include the AT certificate in next CAM transmission.
                        self.at_cert_in_cam_at = Instant::ZERO;
                        // We should also request the unknown certificate.
                        self.p2p_requested_certs.push(at_digest);

                        return Err(SecurityServiceError::SignerCertificateNotFound);
                    }
                }
            }
            SignerIdentifier::Certificate(cert) => {
                let backend = self.backend.inner();
                let at_cert = AuthorizationTicketCertificate::from_etsi_cert(cert, backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                let at_digest = at_cert
                    .hashed_id8(backend)
                    .map_err(SecurityServiceError::InvalidCertificate)?;

                if self.store.is_revoked(at_digest) {
                    return Err(SecurityServiceError::RevokedCertificate);
                }

                let at_valid = at_cert
                    .check(timestamp, backend, |sh| self.store.lookup_aa(sh))
                    .map_err(|e| {
                        if let CertificateError::UnknownSigner(sh) = e {
                            // We don't have the AA certificate, so we should request it.
                            self.p2p_requested_certs.push(sh);
                        }
                        SecurityServiceError::InvalidCertificate(e)
                    })?;

                if !at_valid {
                    // AT certificate signature is invalid.
                    return Err(SecurityServiceError::SignerCertificateFalseSignature);
                }

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

        let backend = self.backend.inner();
        let hash = match signature.hash_algorithm() {
            HashAlgorithm::SHA256 => [backend.sha256(&tbs), backend.sha256(signer_data)].concat(),
            HashAlgorithm::SHA384 => [backend.sha384(&tbs), backend.sha384(signer_data)].concat(),
            HashAlgorithm::SM3 => [
                backend.sm3(&tbs).map_err(SecurityServiceError::Backend)?,
                backend
                    .sm3(signer_data)
                    .map_err(SecurityServiceError::Backend)?,
            ]
            .concat(),
        };

        // Verify AID permission.
        let signer_permissions = signer_cert
            .application_permissions()
            .map_err(SecurityServiceError::InvalidCertificate)?;

        let Some(permission) = signer_permissions.iter().find(|e| e.aid() == aid) else {
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
                permissions: permission.to_owned(),
            })
        } else {
            Err(SecurityServiceError::FalseSignature)
        }
    }
}
