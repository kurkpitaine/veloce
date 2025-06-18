use crate::{
    pki::{
        message::{
            self,
            ctl::{
                CertificateTrustList, CertificateTrustListError, CertificateTrustListResult,
                TlmCertificateTrustListMessage,
            },
            VerifierError,
        },
        service::{PkiServiceError, PkiServiceResult},
        SignerIdentifier,
    },
    security::{
        backend::PkiBackendTrait,
        certificate::{ExplicitCertificate, TrustListManagerCertificate},
        permission::AID,
    },
    time::Instant,
};

use super::PkiClientService;

impl PkiClientService {
    pub fn parse_ectl_response<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        timestamp: Instant,
        backend: &B,
    ) -> PkiServiceResult<(CertificateTrustList, TrustListManagerCertificate)> {
        self.ectl_response_inner(response, timestamp, backend)
            .map_err(PkiServiceError::EctlResponse)
    }

    fn ectl_response_inner<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        timestamp: Instant,
        backend: &B,
    ) -> CertificateTrustListResult<(CertificateTrustList, TrustListManagerCertificate)> {
        let tlm_msg = TlmCertificateTrustListMessage::from_bytes_signed(response)
            .map_err(CertificateTrustListError::Outer)?;

        let mut tlm_cert = None;
        let valid_signature = message::verify_signed_data(
            &tlm_msg,
            backend,
            |signer_id| match signer_id {
                SignerIdentifier::Certificate(v) if !v.is_empty() => {
                    // ETSI TS 102 941 V2.2.1 paragraph 6.3.4:
                    // The signer in the SignedData shall contain the certificate of the CTL issuer.
                    // As there is no constraint on the number of certificates in the SignerIdentifier,
                    // we check only the first certificate.
                    let cert = TrustListManagerCertificate::from_etsi_cert(v[0].clone(), backend)
                        .map_err(VerifierError::InvalidCertificate)?;

                    let valid = cert
                        .check(timestamp, backend, |_| None::<TrustListManagerCertificate>)
                        .map_err(VerifierError::InvalidCertificate)?;

                    if !valid {
                        return Err(VerifierError::FalseCertificateSignature);
                    }

                    tlm_cert = Some(cert.clone());
                    Ok(Some(cert))
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

        let payload = tlm_msg
            .payload_data()
            .map_err(CertificateTrustListError::Outer)?;

        Ok((
            CertificateTrustList::from_bytes_tlm(payload)?,
            tlm_cert.ok_or(CertificateTrustListError::NoSignerCertificate)?,
        ))
    }
}
