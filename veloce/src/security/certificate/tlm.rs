use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609_dot2::{self, Certificate as EtsiCertificate, IssuerIdentifier},
        ieee1609_dot2_base_types,
    },
    prelude::rasn::{self, types::Integer},
};

use crate::{
    security::{
        backend::BackendTrait,
        permission::AID,
        ssp::ctl::{CtlSsp, TLM_CTL},
        HashAlgorithm,
    },
    time::{Instant, TAI2004},
};

use super::{
    Certificate, CertificateError, CertificateResult, CertificateTrait, ExplicitCertificate,
};

/// Trust List Manager certificate type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TrustListManagerCertificate {
    /// Raw COER encoded TLM certificate.
    raw: Vec<u8>,
    /// Inner certificate.
    inner: EtsiCertificate,
}

impl TrustListManagerCertificate {
    pub fn from_etsi_cert<B>(cert: EtsiCertificate, backend: &B) -> CertificateResult<Self>
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

impl ExplicitCertificate for TrustListManagerCertificate {
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

impl CertificateTrait for TrustListManagerCertificate {
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
        use ieee1609_dot2_base_types::{Psid, ServiceSpecificPermissions};

        // The certificate shall be of type explicit as specified in IEEE Std 1609.2™, clause 6.4.6.
        match cert.0.r_type {
            CertificateType::explicit => {}
            _ => return Err(CertificateError::Malformed),
        };

        // The component issuer shall be set to self.
        match cert.0.issuer {
            IssuerIdentifier::R_self(_) => {}
            _ => return Err(CertificateError::Malformed),
        }

        let Some(app_permissions) = &cert.0.to_be_signed.app_permissions else {
            return Err(CertificateError::NoPermissions);
        };

        // appPermissions: this component shall contain the ITS-AID for the CTL as assigned in
        // ETSI TS 102 965.
        if app_permissions.0.len() != 1 {
            return Err(CertificateError::IllegalPermissions);
        }

        // Safety: we checked the vector is not empty.
        let permission = &app_permissions.0[0];
        if permission.psid != Psid(Integer::from(i64::from(AID::CTL))) {
            return Err(CertificateError::IllegalPermissions);
        }

        let Some(raw_ssp) = &permission.ssp else {
            return Err(CertificateError::IllegalPermissions);
        };

        let ssp = match raw_ssp {
            ServiceSpecificPermissions::opaque(opaque) => {
                CtlSsp::parse(opaque).map_err(|_| CertificateError::IllegalPermissions)?
            }
            ServiceSpecificPermissions::bitmapSsp(bitmap) => {
                CtlSsp::parse(&bitmap.0).map_err(|_| CertificateError::IllegalPermissions)?
            }
            _ => return Err(CertificateError::IllegalPermissions),
        };

        if ssp != TLM_CTL {
            return Err(CertificateError::IllegalPermissions);
        }

        // The toBeSigned component CertificateId shall be set to the choice name and contain the unique
        // name string associated to the TLM.
        match cert.0.to_be_signed.id {
            CertificateId::name(_) => {}
            _ => return Err(CertificateError::UnexpectedId),
        }

        // encryptionKey and certIssuePermissions shall be absent.
        if cert.0.to_be_signed.encryption_key.is_some()
            || cert.0.to_be_signed.cert_issue_permissions.is_some()
        {
            return Err(CertificateError::Malformed);
        };

        Ok(())
    }
}
