use crate::{
    pki::{
        message::{
            self,
            crl::{
                CertificateRevocationList, CertificateRevocationListError,
                CertificateRevocationListMessage, CertificateRevocationListResult,
            },
            VerifierError,
        },
        service::{PkiServiceError, PkiServiceResult},
        SignerIdentifier,
    },
    security::{
        backend::BackendTrait,
        certificate::{CertificateWithHashContainer, RootCertificate},
        permission::AID,
    },
    time::Instant,
};

use super::PkiClientService;

impl PkiClientService {
    pub fn parse_crl_response<B: BackendTrait>(
        &self,
        response: &[u8],
        root_certificate: &CertificateWithHashContainer<RootCertificate>,
        timestamp: Instant,
        backend: &B,
    ) -> PkiServiceResult<CertificateRevocationList> {
        Self::parse_and_check_crl(response, root_certificate, timestamp, backend)
            .map_err(PkiServiceError::CrlResponse)
    }

    pub fn parse_and_check_crl<B: BackendTrait>(
        bytes: &[u8],
        root_certificate: &CertificateWithHashContainer<RootCertificate>,
        _timestamp: Instant, // TODO: verify the generation time in the request.
        backend: &B,
    ) -> CertificateRevocationListResult<CertificateRevocationList> {
        let crl_msg = CertificateRevocationListMessage::from_bytes_signed(bytes)
            .map_err(CertificateRevocationListError::Outer)?;

        let valid_signature = message::verify_signed_data(
            &crl_msg,
            backend,
            |signer_id| match signer_id {
                SignerIdentifier::Digest(h) if h == root_certificate.hashed_id8() => {
                    Ok(Some(root_certificate.certificate().to_owned()))
                }
                _ => Err(VerifierError::UnexpectedSigner),
            },
            |aid| {
                if AID::CRL == aid {
                    Ok(())
                } else {
                    Err(AID::CRL)
                }
            },
        )
        .map_err(CertificateRevocationListError::OuterVerifier)?;

        if !valid_signature {
            return Err(CertificateRevocationListError::FalseOuterSignature);
        }

        let payload = crl_msg
            .payload_data()
            .map_err(CertificateRevocationListError::Outer)?;

        CertificateRevocationList::from_bytes(payload)
    }
}
