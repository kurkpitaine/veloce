use veloce_asn1::{
    defs::etsi_103097_v211::ieee1609_dot2::{
        self, Certificate as EtsiCertificate, IssuerIdentifier,
    },
    prelude::rasn,
};

use crate::security::backend::BackendTrait;

use super::{
    Certificate, CertificateError, CertificateResult, CertificateTrait, ExplicitCertificate,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EnrollmentCredentialCertificate {
    /// Raw COER encoded Authorization Ticket.
    raw: Vec<u8>,
    /// Inner certificate.
    inner: EtsiCertificate,
}

impl EnrollmentCredentialCertificate {
    /// Constructs an  from an [EtsiCertificate].
    /// This method verifies if the certificate is valid relative to Enrollment Credential Asn.1 constraints.
    pub fn from_etsi_cert(
        cert: EtsiCertificate,
    ) -> CertificateResult<EnrollmentCredentialCertificate> {
        Certificate::verify_ieee_constraints(&cert)?;
        Certificate::verify_etsi_constraints(&cert)?;
        Self::verify_constraints(&cert)?;

        let raw = rasn::coer::encode(&cert).map_err(|_| CertificateError::Asn1)?;

        Ok(Self { raw, inner: cert })
    }
}

impl ExplicitCertificate for EnrollmentCredentialCertificate {}

impl CertificateTrait for EnrollmentCredentialCertificate {
    type CertificateType = Self;

    fn from_bytes<B>(bytes: &[u8], _backend: &B) -> CertificateResult<Self::CertificateType>
    where
        B: BackendTrait + ?Sized,
    {
        let raw_cert =
            rasn::coer::decode::<EtsiCertificate>(bytes).map_err(|_| CertificateError::Asn1)?;

        Self::from_etsi_cert(raw_cert)
    }

    fn inner(&self) -> &EtsiCertificate {
        &self.inner
    }

    fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn verify_constraints(cert: &EtsiCertificate) -> CertificateResult<()> {
        use ieee1609_dot2::CertificateId;

        // The component issuer shall be set to sha256AndDigest or sha384AndDigest as defined in IEEE
        // Std 1609.2 clause 6.4.7.
        match cert.0.issuer {
            IssuerIdentifier::sha256AndDigest(_) | IssuerIdentifier::sha384AndDigest(_) => {}
            _ => return Err(CertificateError::Malformed),
        }

        // appPermissions: this component shall be used to indicate message signing permissions, i.e.
        // permissions to sign a certificate request message contained in an EtsiTs103097Data.
        let Some(app_permissions) = &cert.0.to_be_signed.app_permissions else {
            return Err(CertificateError::Malformed);
        };

        if app_permissions.0.is_empty() {
            return Err(CertificateError::Malformed);
        }

        // The toBeSigned component CertificateId shall be set to the choice name.
        match cert.0.to_be_signed.id {
            CertificateId::name(_) => {}
            _ => return Err(CertificateError::Malformed),
        }

        // The toBeSigned component certIssuePermissions shall be absent.
        if cert.0.to_be_signed.cert_issue_permissions.is_some() {
            return Err(CertificateError::Malformed);
        }

        Ok(())
    }
}
