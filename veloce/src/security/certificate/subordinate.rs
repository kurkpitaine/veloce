use veloce_asn1::defs::etsi_103097_v211::ieee1609Dot2::{self, Certificate as EtsiCertificate};

use super::{Certificate, CertificateError};

/// Subordinate certificate type, for Enrollment Authority and
/// Authorization Authority certificates.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubordinateCertificate(Certificate);

impl SubordinateCertificate {
    /// Constructs from a raw ETSI Certificate.
    /// This method verifies if the certificate is valid relative to a Subordinate certificate Asn.1 constraints.
    pub fn from_etsi_certificate(cert: EtsiCertificate) -> Result<Self, CertificateError> {
        let cert = Certificate::from_etsi_certificate(cert)?;
        Self::verify(cert.inner())?;

        Ok(Self(cert))
    }

    /// Get a reference on the inner raw certificate.
    pub fn inner(&self) -> &EtsiCertificate {
        self.0.inner()
    }

    #[inline]
    /// Verify fields constraints for a EA/AA certificate.
    fn verify(cert: &EtsiCertificate) -> Result<(), CertificateError> {
        use ieee1609Dot2::{CertificateId, CertificateType, IssuerIdentifier};

        // The certificate shall be of type explicit as specified in IEEE Std 1609.2™, clause 6.4.6.
        match cert.0.r_type {
            CertificateType::explicit => {}
            _ => return Err(CertificateError::Malformed),
        };

        // The component issuer shall be set to sha256AndDigest or sha384AndDigest as defined in IEEE
        // Std 1609.2™ [1] clause 6.4.7.
        match cert.0.issuer {
            IssuerIdentifier::sha256AndDigest(_) | IssuerIdentifier::sha384AndDigest(_) => {}
            _ => return Err(CertificateError::Malformed),
        }

        // This component shall contain a public encryption key for ITS-Stations to encrypt
        // messages to the enrolment / authorization authority
        if cert.0.to_be_signed.encryption_key.is_none() {
            return Err(CertificateError::Malformed);
        }

        // certIssuePermissions: this component shall be used to indicate issuing permissions, i.e.
        // permissions to sign an enrolment credential / authorization ticket with certain permissions.
        let Some(cert_issue_permissions) = &cert.0.to_be_signed.cert_issue_permissions else {
            return Err(CertificateError::Malformed);
        };

        if cert_issue_permissions.0.is_empty() {
            return Err(CertificateError::Malformed);
        }

        // appPermissions: this component shall be used to indicate message signing permissions, i.e.
        // permissions to sign certificate response messages contained in an EtsiTs103097Data.
        let Some(app_permissions) = &cert.0.to_be_signed.app_permissions else {
            return Err(CertificateError::Malformed);
        };

        if app_permissions.0.is_empty() {
            return Err(CertificateError::Malformed);
        }

        // The toBeSigned component CertificateId shall be set to the choice name contain a unique name associated to
        // the certification authority, or shall be set to the choice none.
        match cert.0.to_be_signed.id {
            CertificateId::name(_) | CertificateId::none(_) => {}
            _ => return Err(CertificateError::UnexpectedId),
        }

        Ok(())
    }
}
