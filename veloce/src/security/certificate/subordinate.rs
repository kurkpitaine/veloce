use core::marker::PhantomData;

use veloce_asn1::{
    defs::etsi_103097_v211::ieee1609Dot2::{
        self, Certificate as EtsiCertificate, IssuerIdentifier,
    },
    prelude::rasn,
};

use crate::security::backend::BackendTrait;

use super::{Certificate, CertificateError, CertificateResult, CertificateTrait, ExplicitCertificate};

/// Marker struct for a subordinate EA certificate.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EA;
/// Marker struct for a subordinate AA certificate.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AA;

/// Enrollment Authority certificate type.
pub type EnrollmentAuthorityCertificate = SubordinateCertificate<EA>;
/// Authorization Authority certificate type.
pub type AuthorizationAuthorityCertificate = SubordinateCertificate<AA>;

/// Subordinate certificate type, for Enrollment Authority and
/// Authorization Authority certificates.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubordinateCertificate<T> {
    /// Raw COER encoded Subordinate certificate.
    raw: Vec<u8>,
    /// Inner certificate.
    inner: EtsiCertificate,
    /// Phantom marker for subordinate type.
    _type: PhantomData<T>,
}

impl<T> SubordinateCertificate<T> {
    /// Constructs from a raw ETSI Certificate.
    /// This method must verify if the certificate is valid relative to a Subordinate certificate Asn.1 constraints.
    /// Certificate has to be canonicalized if necessary.
    pub fn from_etsi_cert(
        cert: EtsiCertificate,
        backend: &impl BackendTrait,
    ) -> CertificateResult<Self> {
        Certificate::verify_ieee_constraints(&cert)?;
        Certificate::verify_etsi_constraints(&cert)?;
        Self::verify_constraints(&cert)?;
        let inner = Self::canonicalize(cert, backend)?;

        let raw = rasn::coer::encode(&inner).map_err(|_| CertificateError::Asn1)?;

        Ok(Self {
            raw,
            inner,
            _type: PhantomData,
        })
    }
}

impl<T> ExplicitCertificate for SubordinateCertificate<T> {}

impl<T> CertificateTrait for SubordinateCertificate<T> {
    fn inner(&self) -> &EtsiCertificate {
        &self.inner
    }

    fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn verify_constraints(cert: &EtsiCertificate) -> CertificateResult<()> {
        use ieee1609Dot2::{CertificateId, CertificateType};

        // The certificate shall be of type explicit as specified in IEEE Std 1609.2, clause 6.4.6.
        match cert.0.r_type {
            CertificateType::explicit => {}
            _ => return Err(CertificateError::Malformed),
        };

        // The component issuer shall be set to sha256AndDigest or sha384AndDigest as defined in IEEE
        // Std 1609.2 clause 6.4.7.
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
