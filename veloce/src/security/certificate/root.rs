use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609Dot2::{self, Certificate as EtsiCertificate},
        ieee1609Dot2Base_types::{self},
    },
    prelude::rasn::types::Integer,
};

use crate::{
    security::{
        aid::AID, backend::Backend, signature::EcdsaSignature, HashAlgorithm, VerificationKey,
    },
    time::{Instant, TAI2004},
};

use super::{Certificate, CertificateError};

/// Root certificate type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RootCertificate(Certificate);

impl RootCertificate {
    /// Constructs from a raw ETSI Certificate.
    /// This method verifies if the certificate is valid relative to a Root certificate Asn.1 constraints.
    pub fn from_etsi_certificate(cert: EtsiCertificate) -> Result<Self, CertificateError> {
        let cert = Certificate::from_etsi_certificate(cert)?;
        Self::verify(cert.inner())?;

        Ok(Self(cert))
    }

    /// Get a reference on the inner raw certificate.
    pub fn inner(&self) -> &EtsiCertificate {
        self.0.inner()
    }

    /// Checks the root certificate validity and signature.
    pub(super) fn check(
        &self,
        backend: impl Backend,
        timestamp: Instant,
    ) -> Result<(), CertificateError> {
        // Check validity period.
        if self.0.validity_period().end >= TAI2004::from_unix_instant(timestamp) {
            return Err(CertificateError::Expired);
        }

        // Check signature.
        // Safety: Certificate::verify() and Self::verify() ensures the certificate contains a signature.
        let sig = EcdsaSignature::try_from(self.0.signature_or_panic())
            .map_err(CertificateError::Signature)?;

        // Get public key.
        let pubkey = VerificationKey::try_from(self.0.public_verification_key_or_panic())
            .map_err(CertificateError::VerificationKey)?;

        // Get content to verify.
        let tbs = self
            .0
            .to_be_signed_as_coer()
            .map_err(|_| CertificateError::Other)?;

        let hash = match sig.hash_algorithm() {
            HashAlgorithm::SHA256 => [backend.sha256(&tbs), backend.sha256(&[])].concat(),
            HashAlgorithm::SHA384 => [backend.sha384(&tbs), backend.sha384(&[])].concat(),
        };

        Ok(())
    }

    #[inline]
    /// Verify fields constraints for a Root certificate.
    fn verify(cert: &EtsiCertificate) -> Result<(), CertificateError> {
        use ieee1609Dot2::{CertificateId, CertificateType, IssuerIdentifier};
        use ieee1609Dot2Base_types::Psid;

        // The certificate shall be of type explicit as specified in IEEE Std 1609.2, clause 6.4.6.
        match cert.0.r_type {
            CertificateType::explicit => {}
            _ => return Err(CertificateError::Malformed),
        };

        // The component issuer shall be set to self.
        match cert.0.issuer {
            IssuerIdentifier::R_self(_) => {}
            _ => return Err(CertificateError::Malformed),
        }

        // certIssuePermissions shall be used to indicate issuing permissions, i.e. permissions to sign
        // subordinate certification authority certificates with certain permissions
        let Some(cert_issue_permissions) = &cert.0.to_be_signed.cert_issue_permissions else {
            return Err(CertificateError::Malformed);
        };

        // This is not a formal requirement in the ETSI specification but if the root
        // certificate does not contain permissions, then no messages could be sent.
        if cert_issue_permissions.0.is_empty() {
            net_debug!("Certificate issue permissions is empty in root certificate.");
        }

        let Some(app_permissions) = &cert.0.to_be_signed.app_permissions else {
            return Err(CertificateError::Malformed);
        };

        // appPermissions shall be used to indicate permissions to sign CRLs and CTLs.
        let has_permissions = app_permissions
            .0
            .iter()
            .filter_map(|e| {
                if e.psid == Psid(Integer::from(AID::CRL as u64))
                    || e.psid == Psid(Integer::from(AID::CTL as u64)) && e.ssp.is_some()
                {
                    Some(e)
                } else {
                    None
                }
            })
            .count()
            >= 2;

        if !has_permissions {
            return Err(CertificateError::NoPermissions);
        }

        // The toBeSigned component CertificateId shall be set to the choice name and shall contain a unique name
        // associated to the root certification authority.
        match cert.0.to_be_signed.id {
            CertificateId::name(_) => {}
            _ => return Err(CertificateError::UnexpectedId),
        }

        Ok(())
    }
}
