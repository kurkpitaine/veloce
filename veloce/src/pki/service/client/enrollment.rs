use crate::{
    pki::{
        message::{
            self,
            enrollment::{
                EnrollmentRequest, EnrollmentRequestError, EnrollmentRequestResult,
                EnrollmentResponse, EnrollmentResponseCode, EnrollmentResponseError,
                EnrollmentResponseResult,
            },
            VerifierError,
        },
        service::{client::PkiClientService, PkiServiceError, PkiServiceResult},
        Aes128Key, SignerIdentifier,
    },
    security::{
        backend::PkiBackendTrait,
        certificate::{
            CertificateWithHashContainer, EnrollmentAuthorityCertificate, EnrollmentCredentialCertificate,
            ExplicitCertificate,
        },
        permission::{Permission, AID},
        ssp::{
            scr::{ScrPermission, ScrSsp},
            SspTrait,
        },
        EcKeyType, EcdsaKey, KeyPair,
    },
    time::Instant,
};

/// Enrollment request context.
#[derive(Debug)]
pub struct EnrollmentRequestContext<B: PkiBackendTrait> {
    /// Public signature verification key of the Enrollment Credential.
    ec_pubkey: EcdsaKey,
    /// Symmetric encryption key, used to encrypt the communications with the PKI.
    symm_encryption_key: Aes128Key,
    /// Ephemeral keypair, used to encrypt [Self::symm_encryption_key] with the DH algorithm.
    ephemeral_keypair: KeyPair<B::BackendSecretKey, B::BackendPublicKey>,
}

impl PkiClientService {
    // TODO: Manage re-enrollment.
    /// Emits an enrollment request.
    pub fn emit_enrollment_request<B: PkiBackendTrait>(
        &self,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        timestamp: Instant,
        backend: &mut B,
    ) -> PkiServiceResult<(Vec<u8>, EnrollmentRequestContext<B>)> {
        // Generate the Enrollment Credential key pair.
        let ec_pubkey = backend
            .generate_enrollment_keypair(EcKeyType::NistP256r1)
            .map_err(PkiServiceError::Backend)?
            .try_into()
            .map_err(PkiServiceError::Backend)?;

        // Generate the AES 128 ephemeral encryption key.
        let symm_encryption_key = Aes128Key(
            backend
                .generate_aes128_key()
                .map_err(PkiServiceError::Backend)?,
        );

        self.enrollment_request_inner(
            &ec_pubkey,
            &symm_encryption_key,
            ea_certificate,
            timestamp,
            backend,
        )
        .map_err(PkiServiceError::EnrollmentRequest)
        .map(|(request, ephemeral_keypair)| {
            (
                request,
                EnrollmentRequestContext {
                    ec_pubkey,
                    symm_encryption_key,
                    ephemeral_keypair,
                },
            )
        })
    }

    fn enrollment_request_inner<B>(
        &self,
        pubkey: &EcdsaKey,
        symm_encryption_key: &Aes128Key,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        timestamp: Instant,
        backend: &B,
    ) -> EnrollmentRequestResult<(Vec<u8>, KeyPair<B::BackendSecretKey, B::BackendPublicKey>)>
    where
        B: PkiBackendTrait,
    {
        let hash_algorithm = pubkey.hash_algorithm();
        let canonical_pubkey: EcdsaKey = backend
            .canonical_pubkey()
            .map_err(EnrollmentRequestError::Backend)?
            .ok_or(EnrollmentRequestError::NoCanonicalKey)?
            .try_into()
            .map_err(EnrollmentRequestError::Backend)?;

        let mut request = EnrollmentRequest::new(self.canonical_id.as_bytes().to_vec());

        // Add Enrollment Credential permissions.
        let mut ssp = ScrSsp::new();
        ssp.set_permission(ScrPermission::AuthorizationReq); // Allow authorization ticket request signing.
        ssp.set_permission(ScrPermission::EnrollmentReq); // Allow enrollment request signing for re-enrollment.

        request.set_app_permissions(vec![Permission::SCR(ssp.into())]);
        request.set_verification_key(pubkey.to_owned())?;

        // Create Inner EC Request for POP wrapper and sign it with the enrollment key.
        let mut signed_for_pop =
            EnrollmentRequest::emit_inner_ec_request_for_pop(request, timestamp)?;

        message::sign_with_enrollment_key(&mut signed_for_pop, hash_algorithm, &[], backend)
            .map_err(EnrollmentRequestError::SignedForPopSigner)?;

        // Create Outer EC Request and sign it with the canonical key.
        let mut outer_ec_request =
            EnrollmentRequest::emit_outer_ec_request(signed_for_pop, timestamp)?;

        let hash_algorithm = canonical_pubkey.hash_algorithm();

        message::sign_with_canonical_key(&mut outer_ec_request, hash_algorithm, backend)
            .map_err(EnrollmentRequestError::OuterSigner)?;

        // Serialize the outer EC Request to COER bytes.
        let to_encrypt = outer_ec_request
            .as_bytes()
            .map_err(EnrollmentRequestError::Outer)?;

        let res = message::encrypt(to_encrypt, symm_encryption_key, ea_certificate, backend)
            .map_err(EnrollmentRequestError::Encryption)?;

        Ok((
            res.0
                .as_bytes()
                .map_err(EnrollmentRequestError::Encrypted)?,
            res.1,
        ))
    }

    /// Parse the enrollment response and return the enclosed enrollment credential if the response is valid.
    pub fn parse_enrollment_response<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        ctx: EnrollmentRequestContext<B>,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        timestamp: Instant,
        backend: &B,
    ) -> PkiServiceResult<EnrollmentCredentialCertificate> {
        let response = self
            .enrollment_response_inner(response, ctx, ea_certificate, timestamp, backend)
            .map_err(PkiServiceError::EnrollmentResponse)?;

        let response_code = response
            .response_code()
            .map_err(PkiServiceError::EnrollmentResponse)?;

        let EnrollmentResponseCode::Ok = response_code else {
            return Err(PkiServiceError::EnrollmentResponse(
                EnrollmentResponseError::Failure(response_code),
            ));
        };

        let enrollment_credential = response
            .enrollment_credential()
            .map_err(PkiServiceError::EnrollmentResponse)?
            .ok_or(PkiServiceError::EnrollmentResponse(
                // We should never fall here since [EnrollmentResponse] is checked before.
                EnrollmentResponseError::Malformed,
            ))?;

        enrollment_credential
            .check(timestamp, backend, |h| {
                if h == ea_certificate.hashed_id8() {
                    Some(ea_certificate.certificate().clone())
                } else {
                    None
                }
            })
            .map_err(|e| {
                PkiServiceError::EnrollmentResponse(EnrollmentResponseError::EnrollmentCredentialCertificate(
                    e,
                ))
            })?;

        // TODO: Verify the content of the Enrollment Credential.

        Ok(enrollment_credential)
    }

    fn enrollment_response_inner<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        ctx: EnrollmentRequestContext<B>,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        _timestamp: Instant, // TODO: verify the timestamp from the request.
        backend: &B,
    ) -> EnrollmentResponseResult<EnrollmentResponse> {
        let decrypted =
            message::handle_encrypted_response(response, &ctx.symm_encryption_key, backend)
                .map_err(EnrollmentResponseError::DecryptionHandler)?;

        let outer_response = EnrollmentResponse::parse_outer_ec_response(&decrypted)?;

        let valid_signature = message::verify_signed_data(
            &outer_response,
            ea_certificate.certificate(),
            backend,
            |signer_id| match signer_id {
                SignerIdentifier::Digest(h) => {
                    if ea_certificate.hashed_id8() == h {
                        Ok(Some(
                            ea_certificate
                                .certificate()
                                .public_verification_key()
                                .map_err(VerifierError::InvalidCertificate)?,
                        ))
                    } else {
                        Ok(None)
                    }
                }
                _ => return Err(VerifierError::UnexpectedSigner),
            },
            |aid| {
                if AID::SCR == aid {
                    Ok(())
                } else {
                    Err(AID::SCR)
                }
            },
        )
        .map_err(EnrollmentResponseError::OuterVerifier)?;

        if !valid_signature {
            return Err(EnrollmentResponseError::FalseOuterSignature);
        }

        let payload = outer_response
            .payload_data()
            .map_err(EnrollmentResponseError::Outer)?;

        EnrollmentResponse::from_bytes(payload)
    }
}
