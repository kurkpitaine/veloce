use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609Dot2::{self, Certificate as EtsiCertificate},
        ieee1609Dot2Base_types,
    },
    prelude::rasn::types::Integer,
};

use crate::security::{
    aid::AID,
    ssp::ctl::{CtlSsp, TLM_CTL},
};

use super::{Certificate, CertificateError};

/// Trust List Manager certificate type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TrustListManagerCertificate(Certificate);

impl TrustListManagerCertificate {
    /// Constructs from a raw ETSI Certificate.
    /// This method verifies if the certificate is valid relative to a TLM certificate Asn.1 constraints.
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
    /// Verify fields constraints for a TLM certificate.
    fn verify(cert: &EtsiCertificate) -> Result<(), CertificateError> {
        use ieee1609Dot2::{CertificateId, CertificateType, IssuerIdentifier};
        use ieee1609Dot2Base_types::{Psid, ServiceSpecificPermissions};

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
        if permission.psid != Psid(Integer::from(AID::CTL as u64)) {
            return Err(CertificateError::IllegalPermissions);
        }

        let Some(raw_ssp) = &permission.ssp else {
            return Err(CertificateError::IllegalPermissions);
        };

        let ssp = match raw_ssp {
            ServiceSpecificPermissions::opaque(opaque) => {
                CtlSsp::parse(&opaque).map_err(|_| CertificateError::IllegalPermissions)?
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
