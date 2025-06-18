use crate::{
    pki::{
        message::{
            self,
            ctl::{
                CertificateTrustList, CertificateTrustListError, CertificateTrustListResult,
                RcaCertificateTrustListMessage,
            },
            VerifierError,
        },
        service::{PkiServiceError, PkiServiceResult},
        SignerIdentifier,
    },
    security::{
        backend::PkiBackendTrait,
        certificate::{CertificateWithHashContainer, RootCertificate},
        permission::AID,
    },
    time::Instant,
};

use super::PkiClientService;

impl PkiClientService {
    pub fn parse_ctl_response<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        root_certificate: &CertificateWithHashContainer<RootCertificate>,
        timestamp: Instant,
        backend: &B,
    ) -> PkiServiceResult<CertificateTrustList> {
        self.ctl_response_inner(response, root_certificate, timestamp, backend)
            .map_err(PkiServiceError::CtlResponse)
    }

    fn ctl_response_inner<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        root_certificate: &CertificateWithHashContainer<RootCertificate>,
        _timestamp: Instant, // TODO: verify the generation time in the request.
        backend: &B,
    ) -> CertificateTrustListResult<CertificateTrustList> {
        let rca_msg = RcaCertificateTrustListMessage::from_bytes_signed(response)
            .map_err(CertificateTrustListError::Outer)?;

        let valid_signature = message::verify_signed_data(
            &rca_msg,
            backend,
            |signer_id| match signer_id {
                SignerIdentifier::Certificate(v) if !v.is_empty() => {
                    // ETSI TS 102 941 V2.2.1 paragraph 6.3.4:
                    // The signer in the SignedData shall contain the certificate of the CTL issuer.
                    // As there is no constraint on the number of certificates in the SignerIdentifier,
                    // we check only the first certificate.
                    let root_cert = root_certificate.certificate().to_owned();
                    let embedded_root_cert = RootCertificate::from_etsi_cert(v[0].clone(), backend)
                        .map_err(VerifierError::InvalidCertificate)?;

                    if embedded_root_cert != root_cert {
                        return Err(VerifierError::UnexpectedSignerCertificate);
                    }

                    Ok(Some(root_cert))
                }
                _ => Err(VerifierError::UnexpectedSigner),
            },
            |aid| {
                if AID::CTL == aid {
                    Ok(())
                } else {
                    Err(AID::CTL)
                }
            },
        )
        .map_err(CertificateTrustListError::OuterVerifier)?;

        if !valid_signature {
            return Err(CertificateTrustListError::FalseOuterSignature);
        }

        let payload = rca_msg
            .payload_data()
            .map_err(CertificateTrustListError::Outer)?;

        CertificateTrustList::from_bytes_rca(payload)
    }
}
