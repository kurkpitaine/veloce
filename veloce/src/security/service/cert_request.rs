use core::fmt;

use veloce_asn1::defs::etsi_103097_v211::ieee1609_dot2::Certificate as EtsiCertificate;

use crate::{
    security::certificate::{
        AuthorizationAuthorityCertificate, CertificateError, ExplicitCertificate,
    },
    security::service::SecurityService,
    time::Instant,
};

pub type CertificateRequestResult<T> = core::result::Result<T, CertificateRequestError>;

#[derive(Debug)]
pub enum CertificateRequestError {
    /// Enclosed certificate is invalid.
    InvalidCertificate(CertificateError),
    /// Enclosed certificate signature is invalid.
    FalseSignature,
    /// Other error type.
    Other,
}

impl fmt::Display for CertificateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateRequestError::InvalidCertificate(e) => {
                write!(f, "invalid certificate: {}", e)
            }
            CertificateRequestError::FalseSignature => write!(f, "invalid signature"),
            CertificateRequestError::Other => write!(f, "other"),
        }
    }
}

impl SecurityService {
    pub(super) fn verify_certificate_request(
        &mut self,
        cert: EtsiCertificate,
        timestamp: Instant,
    ) -> CertificateRequestResult<()> {
        let backend = self.backend.inner();
        let req_aa = AuthorizationAuthorityCertificate::from_etsi_cert(cert, backend)
            .map_err(CertificateRequestError::InvalidCertificate)?
            .into_with_hash_container(backend)
            .map_err(CertificateRequestError::InvalidCertificate)?;

        // Per ETSI TS 103 097 v2.1.1, paragraph 7.1.1: unless before the generation of the next CAM,
        // the ITS-S received another CAM including the component requestedCertificate containing the
        // requested certification authority certificate: in this case the request shall be discarded.
        let aa_found = self
            .store
            .own_chain()
            .aa_cert()
            .as_ref()
            .map_or(false, |own_aa| own_aa.hashed_id8() == req_aa.hashed_id8());

        if aa_found {
            // This is our AA certificate.
            self.aa_cert_in_cam = false;
        } else {
            // This is not our AA certificate.
            if self.store.lookup_aa(req_aa.hashed_id8()).is_none() {
                // Not a known AA certificate, verify it.
                let mut signer_hash = Default::default();
                let aa_valid = req_aa
                    .certificate()
                    .check(timestamp, backend, |sh| {
                        signer_hash = sh;
                        self.store.lookup_root(sh)
                    })
                    .map_err(CertificateRequestError::InvalidCertificate)?;

                if !aa_valid {
                    return Err(CertificateRequestError::FalseSignature);
                }

                // Certificate has been checked and its signer is known.
                self.store_mut()
                    .set_remote_aa(signer_hash, req_aa)
                    .map_err(|_| CertificateRequestError::Other)?;
            }
        }

        Ok(())
    }
}
