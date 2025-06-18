use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609_dot2::{self, Certificate as EtsiCertificate, IssuerIdentifier},
        ieee1609_dot2_base_types,
    },
    prelude::rasn::{self, types::Integer},
};

use crate::{
    security::{backend::BackendTrait, permission::AID, HashAlgorithm},
    time::{Instant, TAI2004},
};

use super::{
    Certificate, CertificateError, CertificateResult, CertificateTrait, ExplicitCertificate,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RootCertificate {
    /// Raw COER encoded Root certificate.
    raw: Vec<u8>,
    /// Inner certificate.
    inner: EtsiCertificate,
}

impl RootCertificate {
    /// Constructs a Root certificate from an [EtsiCertificate].
    /// This method verifies if the certificate is valid relative to a Root certificate Asn.1 constraints.
    /// Certificate is also canonicalized if necessary.
    pub fn from_etsi_cert<B>(
        cert: EtsiCertificate,
        backend: &B,
    ) -> CertificateResult<RootCertificate>
    where
        B: BackendTrait + ?Sized,
    {
        Certificate::verify_ieee_constraints(&cert)?;
        Certificate::verify_etsi_constraints(&cert)?;
        Self::verify_constraints(&cert)?;
        let inner = Self::canonicalize(cert, backend)?;

        let raw = rasn::coer::encode(&inner).map_err(|_| CertificateError::Asn1)?;

        Ok(Self { raw, inner })
    }
}

impl ExplicitCertificate for RootCertificate {
    fn check<F, B, C>(&self, timestamp: Instant, backend: &B, _f: F) -> CertificateResult<bool>
    where
        B: BackendTrait + ?Sized,
        C: ExplicitCertificate,
        F: FnOnce(crate::security::HashedId8) -> Option<C>,
    {
        // Check validity period.
        if self.validity_period().end() <= TAI2004::from_unix_instant(timestamp) {
            return Err(CertificateError::Expired(self.validity_period().end()));
        }

        // Get signature.
        let sig = self.signature()?;

        // Get public key.
        let pubkey = self.public_verification_key()?;

        // Get content to verify.
        // Certificate has already been canonicalized by Self::from_etsi_certificate().
        let tbs = self
            .to_be_signed_bytes()
            .map_err(|_| CertificateError::Other)?;

        let hash = match sig.hash_algorithm() {
            HashAlgorithm::SHA256 => [backend.sha256(&tbs), backend.sha256(&[])].concat(),
            HashAlgorithm::SHA384 => [backend.sha384(&tbs), backend.sha384(&[])].concat(),
            HashAlgorithm::SM3 => [
                backend.sm3(&tbs).map_err(CertificateError::Backend)?,
                backend.sm3(&[]).map_err(CertificateError::Backend)?,
            ]
            .concat(),
        };

        let res = backend
            .verify_signature(sig, pubkey, &hash)
            .map_err(CertificateError::Backend)?;

        Ok(res)
    }
}

impl CertificateTrait for RootCertificate {
    type CertificateType = Self;

    fn from_bytes<B>(bytes: &[u8], backend: &B) -> CertificateResult<Self::CertificateType>
    where
        B: BackendTrait + ?Sized,
    {
        let raw_cert =
            rasn::coer::decode::<EtsiCertificate>(bytes).map_err(|_| CertificateError::Asn1)?;

        Self::from_etsi_cert(raw_cert, backend)
    }

    fn inner(&self) -> &EtsiCertificate {
        &self.inner
    }

    fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn verify_constraints(cert: &EtsiCertificate) -> CertificateResult<()> {
        use ieee1609_dot2::{CertificateId, CertificateType};
        use ieee1609_dot2_base_types::Psid;

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
            .filter(|e| {
                e.psid == Psid(Integer::from(i64::from(AID::CRL)))
                    || e.psid == Psid(Integer::from(i64::from(AID::CTL))) && e.ssp.is_some()
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
