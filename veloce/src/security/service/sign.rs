use crate::{
    common::PotiPosition,
    security::{
        certificate::{CertificateTrait, ExplicitCertificate},
        permission::{Permission, AID},
        secured_message::{SecuredMessage, SignerIdentifier},
    },
    time::{Duration, Instant, TAI2004},
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
        position: PotiPosition,
    ) -> SignResult {
        let at = self
            .store
            .own_chain()
            .at_cert()
            .ok_or(SecurityServiceError::NoSigningCertificate)?
            .at_container();

        // Check AT is not expired.
        if TAI2004::from_unix_instant(timestamp) > at.certificate().validity_period().end() {
            return Err(SecurityServiceError::OffValidityPeriod);
        }

        // Check AT has permission to sign aid.
        let at_permissions = at
            .certificate()
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

        let signer = match permission.aid() {
            AID::CA if self.at_cert_in_cam_at > timestamp => {
                // Add our AA certificate in the secured message, if necessary.
                if self.aa_cert_in_cam {
                    self.aa_cert_in_cam = false;
                    self.store
                        .own_chain()
                        .aa_cert()
                        .as_ref()
                        .map_or(Ok(()), |own_aa| {
                            message
                                .set_requested_certificate(own_aa.certificate().inner().to_owned())
                        })
                        .map_err(SecurityServiceError::InvalidContent)?;
                }

                // Add P2P requested certificates in the secured message.
                let p2p_hashes = self
                    .p2p_requested_certs
                    .drain(..)
                    .map(|cert_hash| cert_hash.into())
                    .collect();

                message
                    .set_p2p_requested_certificates(p2p_hashes)
                    .map_err(SecurityServiceError::InvalidContent)?;

                // Fill Secured Message with the AT certificate HashedId8.
                SignerIdentifier::Digest(at.hashed_id8().into())
            }
            AID::CA => {
                // Add P2P requested certificates in the secured message.
                let p2p_hashes = self
                    .p2p_requested_certs
                    .drain(..)
                    .map(|cert_hash| cert_hash.into())
                    .collect();

                message
                    .set_p2p_requested_certificates(p2p_hashes)
                    .map_err(SecurityServiceError::InvalidContent)?;

                // Reset timer and fill Secured Message with the AT certificate.
                self.at_cert_in_cam_at = timestamp + Duration::from_secs(1);
                SignerIdentifier::Certificate(at.certificate().inner().clone())
            }
            AID::DEN => {
                // Set the generation location for the signature.
                message
                    .set_generation_location(position.as_3d_location())
                    .map_err(SecurityServiceError::InvalidContent)?;
                // Fill Secured Message with the AT certificate.
                SignerIdentifier::Certificate(at.certificate().inner().clone())
            }
            // Fill Secured Message with AT certificate.
            _ => SignerIdentifier::Certificate(at.certificate().inner().clone()),
        };

        message
            .set_signer_identifier(signer)
            .map_err(SecurityServiceError::InvalidContent)?;

        let signer_data = at.certificate().raw_bytes();
        let tbs = message
            .to_be_signed_bytes()
            .map_err(SecurityServiceError::InvalidContent)?;

        let backend = self.backend.inner();
        let hash = [backend.sha256(&tbs), backend.sha256(signer_data)].concat();

        let signature = backend
            .generate_signature(&hash)
            .map_err(SecurityServiceError::Backend)?;

        message
            .set_signature(signature)
            .map_err(SecurityServiceError::InvalidContent)?;

        self.privacy.inner_mut().notify_signature();

        Ok(())
    }
}
