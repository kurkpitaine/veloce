use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609Dot2::{self, Certificate as EtsiCertificate, IssuerIdentifier},
        ieee1609Dot2Base_types,
    },
    prelude::rasn::{self, types::Integer},
};

use crate::security::{aid::AID, backend::Backend};

use super::{
    Certificate, CertificateError, CertificateResult, CertificateTrait, ExplicitCertificate,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AuthorizationTicketCertificate {
    /// Raw COER encoded Authorization Ticket.
    raw: Vec<u8>,
    /// Inner certificate.
    inner: EtsiCertificate,
}

impl AuthorizationTicketCertificate {
    /// Constructs a Authorization Ticket from an [EtsiCertificate].
    /// This method verifies if the certificate is valid relative to a Root certificate Asn.1 constraints.
    /// Certificate is also canonicalized if necessary.
    pub fn from_etsi_cert<B>(
        cert: EtsiCertificate,
        backend: &B,
    ) -> CertificateResult<AuthorizationTicketCertificate>
    where
        B: Backend + ?Sized,
    {
        Certificate::verify_ieee_constraints(&cert)?;
        Certificate::verify_etsi_constraints(&cert)?;
        Self::verify_constraints(&cert)?;
        let inner = Self::canonicalize(cert, backend)?;

        let raw = rasn::coer::encode(&inner).map_err(|_| CertificateError::Asn1)?;

        Ok(Self { raw, inner })
    }
}

impl ExplicitCertificate for AuthorizationTicketCertificate {}

impl CertificateTrait for AuthorizationTicketCertificate {
    fn inner(&self) -> &EtsiCertificate {
        &self.inner
    }

    fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn verify_constraints(cert: &EtsiCertificate) -> CertificateResult<()> {
        use ieee1609Dot2::{CertificateId, CertificateType};
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
