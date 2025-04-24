use crate::{
    pki::{
        asn1_wrapper::Asn1Wrapper,
        message::{
            self,
            authorization::{
                AuthorizationRequest, AuthorizationRequestError, AuthorizationRequestResult,
                AuthorizationResponse, AuthorizationResponseCode, AuthorizationResponseError,
                AuthorizationResponseResult, EcSignature,
            },
            VerifierError,
        },
        service::{PkiServiceError, PkiServiceResult},
        Aes128Key, HashedData, IncludedPublicKeys, SignerIdentifier,
    },
    security::{
        backend::PkiBackendTrait,
        certificate::{
            AuthorizationAuthorityCertificate, AuthorizationTicketCertificate, CertificateTrait,
            CertificateWithHashContainer, EnrollmentAuthorityCertificate, EnrollmentCredentialCertificate,
            ExplicitCertificate,
        },
        permission::{Permission, AID},
        EcKeyType, KeyPair, ValidityPeriod,
    },
    time::Instant,
};

use super::PkiClientService;

/// Requested AT parameters of an authorization request.
#[derive(Debug)]
pub struct AuthorizationRequestParameters {
    /// Storage ID of the requested AT certificate.
    /// Used by the backend for internal key management.
    pub storage_id: usize,
    /// Requested validity period of the requested AT certificate.
    pub validity_period: ValidityPeriod,
    /// Requested permissions in the requested AT certificate.
    pub permissions: Vec<Permission>,
    /// Enable privacy when requesting the AT certificate.
    pub privacy: bool,
    /// Enable Proof of Possession when requesting the AT certificate.
    pub proof_of_possession: bool,
    /* TODO: /// Optionally request a pubic encryption key in the AT certificate.
    pub optional_encryption_key: bool, */
}

/// Encryption keys used to cipher the Authorization Request.
pub struct AuthorizationRequestEncryptionKeys {
    /// Symmetric encryption key of the outer envelope.
    outer_encryption_key: Aes128Key,
    /// Optional symmetric encryption key of the EC signature.
    privacy_encryption_key: Option<Aes128Key>,
}

/// Certificates used to build the Authorization Request.
struct Certificates<'ec, 'ea, 'aa> {
    /// Enrollment Credential Certificate.
    pub ec_certificate: &'ec CertificateWithHashContainer<EnrollmentCredentialCertificate>,
    /// Enrollment Authority Certificate.
    pub ea_certificate: &'ea CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
    /// Authorization Authority Certificate.
    pub aa_certificate: &'aa CertificateWithHashContainer<AuthorizationAuthorityCertificate>,
}

/// Authorization request context.
#[derive(Debug)]
pub struct AuthorizationRequestContext<B: PkiBackendTrait> {
    /// Public verification and encryption keys (if any) of the Authorization Ticket.
    public_keys: IncludedPublicKeys,
    /// Outer encryption key, used to encrypt the communications with the PKI.
    outer_encryption_key: Aes128Key,
    /// Ephemeral keypair, used to encrypt [Self::outer_encryption_key] with the DH algorithm.
    outer_ephemeral_keypair: KeyPair<B::BackendSecretKey, B::BackendPublicKey>,
    /// Privacy encryption key, if any.
    privacy_encryption_key: Option<Aes128Key>,
    /// Privacy Ephemeral keypair, used to encrypt [Self::privacy_encryption_key] with the DH algorithm.
    privacy_ephemeral_keypair: Option<KeyPair<B::BackendSecretKey, B::BackendPublicKey>>,
}

impl PkiClientService {
    pub fn emit_authorization_request<B: PkiBackendTrait>(
        &self,
        ec_certificate: &CertificateWithHashContainer<EnrollmentCredentialCertificate>,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        aa_certificate: &CertificateWithHashContainer<AuthorizationAuthorityCertificate>,
        params: AuthorizationRequestParameters,
        timestamp: Instant,
        backend: &mut B,
    ) -> PkiServiceResult<(Vec<u8>, AuthorizationRequestContext<B>)> {
        // Generate the Authorization Ticket key pair.
        let verification_key = backend
            .generate_authorization_ticket_keypair(EcKeyType::NistP256r1, params.storage_id)
            .map_err(PkiServiceError::Backend)?
            .try_into()
            .map_err(PkiServiceError::Backend)?;

        // Generate the AES 128 ephemeral encryption key.
        let outer_encryption_key = Aes128Key(
            backend
                .generate_aes128_key()
                .map_err(PkiServiceError::Backend)?,
        );

        let privacy_encryption_key = if params.privacy {
            Some(Aes128Key(
                backend
                    .generate_aes128_key()
                    .map_err(PkiServiceError::Backend)?,
            ))
        } else {
            None
        };

        let encryption_keys = AuthorizationRequestEncryptionKeys {
            outer_encryption_key,
            privacy_encryption_key,
        };

        let public_keys = IncludedPublicKeys {
            verification_key,
            encryption_key: None,
        };

        let certificates = Certificates {
            ec_certificate,
            ea_certificate,
            aa_certificate,
        };

        self.authorization_request_inner(
            &encryption_keys,
            &public_keys,
            certificates,
            params,
            timestamp,
            backend,
        )
        .map_err(PkiServiceError::AuthorizationRequest)
        .map(
            |(request, outer_ephemeral_keypair, privacy_ephemeral_keypair)| {
                (
                    request,
                    AuthorizationRequestContext {
                        public_keys,
                        outer_encryption_key,
                        outer_ephemeral_keypair,
                        privacy_encryption_key,
                        privacy_ephemeral_keypair,
                    },
                )
            },
        )
    }

    fn authorization_request_inner<B>(
        &self,
        encryption_keys: &AuthorizationRequestEncryptionKeys,
        included_keys: &IncludedPublicKeys,
        certificates: Certificates,
        params: AuthorizationRequestParameters,
        timestamp: Instant,
        backend: &B,
    ) -> AuthorizationRequestResult<(
        Vec<u8>,
        KeyPair<B::BackendSecretKey, B::BackendPublicKey>,
        Option<KeyPair<B::BackendSecretKey, B::BackendPublicKey>>,
    )>
    where
        B: PkiBackendTrait,
    {
        let ea_certificate = certificates.ea_certificate;
        let ec_certificate = certificates.ec_certificate;
        let aa_certificate = certificates.aa_certificate;
        let mut request = AuthorizationRequest::new();

        let (hmac_key, key_tag) = message::generate_hmac_and_tag(&included_keys, backend)
            .map_err(AuthorizationRequestError::HmacAndTagGenerator)?;

        // Fill the 'shared at request' part of the request.
        request.set_ea_id(ea_certificate.hashed_id8());
        request.set_key_tag(key_tag)?;
        request.set_app_permissions(params.permissions);
        request.set_hmac_key(hmac_key);

        // Fill the 'ec_signature' part of the request.
        let hash_algorithm = ec_certificate
            .certificate()
            .public_verification_key()
            .map_err(AuthorizationRequestError::EcCertificate)?
            .hash_algorithm();
        let shared_atr_bytes = request.shared_at_request_bytes()?;
        let shared_atr_hash = backend.sha256(&shared_atr_bytes).to_vec();

        let mut signed_epl = AuthorizationRequest::emit_ec_signature_signed_external_payload(
            HashedData::SHA256(shared_atr_hash),
            ec_certificate.hashed_id8(),
            timestamp,
        )?;

        let signer_data = ec_certificate.certificate().raw_bytes();
        message::sign_with_enrollment_key(&mut signed_epl, hash_algorithm, signer_data, backend)
            .map_err(AuthorizationRequestError::EcSignatureSigner)?;

        // Encrypt the external payload, if required.
        let (ec_signature, privacy_keys) = if let Some(key) =
            &encryption_keys.privacy_encryption_key
        {
            let ea_certificate = certificates.ea_certificate;

            // Serialize the signed external payload struct.
            let signed_epl_bytes = signed_epl
                .as_bytes()
                .map_err(AuthorizationRequestError::EcSignature)?;

            let (enc_data, keys) = message::encrypt(signed_epl_bytes, key, ea_certificate, backend)
                .map_err(AuthorizationRequestError::PrivacyEncryption)?;

            (EcSignature::Encrypted(enc_data), Some(keys))
        } else {
            (EcSignature::Plain(signed_epl), None)
        };

        request.set_ec_signature(ec_signature)?;
        request.set_public_verification_key(included_keys.verification_key.clone())?;

        if let Some(enc_key) = &included_keys.encryption_key {
            request.set_public_encryption_key(enc_key.to_owned())?;
        }

        let etsi_data = AuthorizationRequest::emit_etsi_wrapper(request);

        let to_encrypt = if params.proof_of_possession {
            let mut pop_wrapper = AuthorizationRequest::emit_pop_wrapper(etsi_data, timestamp)?;
            let hash_algorithm = included_keys.verification_key.hash_algorithm();
            message::sign_with_authorization_key(
                &mut pop_wrapper,
                hash_algorithm,
                params.storage_id,
                backend,
            )
            .map_err(AuthorizationRequestError::PopWrapperSigner)?;

            pop_wrapper
                .as_bytes()
                .map_err(AuthorizationRequestError::PopWrapper)?
        } else {
            Asn1Wrapper::encode_coer(&etsi_data).map_err(AuthorizationRequestError::EtsiWrapper)?
        };

        let encryption_key = &encryption_keys.outer_encryption_key;
        let res = message::encrypt(to_encrypt, encryption_key, aa_certificate, backend)
            .map_err(AuthorizationRequestError::Encryption)?;

        Ok((
            res.0
                .as_bytes()
                .map_err(AuthorizationRequestError::Encrypted)?,
            res.1,
            privacy_keys,
        ))
    }

    pub fn parse_authorization_response<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        ctx: AuthorizationRequestContext<B>,
        aa_certificate: &CertificateWithHashContainer<AuthorizationAuthorityCertificate>,
        timestamp: Instant,
        backend: &B,
    ) -> PkiServiceResult<AuthorizationTicketCertificate> {
        let response = self
            .authorization_response_inner(response, ctx, aa_certificate, timestamp, backend)
            .map_err(PkiServiceError::AuthorizationResponse)?;

        let response_code = response
            .response_code()
            .map_err(PkiServiceError::AuthorizationResponse)?;

        let AuthorizationResponseCode::Ok = response_code else {
            return Err(PkiServiceError::AuthorizationResponse(
                AuthorizationResponseError::Failure(response_code),
            ));
        };

        let authorization_ticket = response
            .authorization_ticket()
            .map_err(PkiServiceError::AuthorizationResponse)?
            .ok_or(PkiServiceError::AuthorizationResponse(
                // We should never fall here since [AuthorizationResponse] is checked before.
                AuthorizationResponseError::Malformed,
            ))?;

        authorization_ticket
            .check(timestamp, backend, |h| {
                if h == aa_certificate.hashed_id8() {
                    Some(aa_certificate.certificate().clone())
                } else {
                    None
                }
            })
            .map_err(|e| {
                PkiServiceError::AuthorizationResponse(
                    AuthorizationResponseError::AuthorizationTicket(e),
                )
            })?;

        // TODO: Verify the content of the Authorization Ticket.

        Ok(authorization_ticket)
    }

    fn authorization_response_inner<B: PkiBackendTrait>(
        &self,
        response: &[u8],
        ctx: AuthorizationRequestContext<B>,
        aa_certificate: &CertificateWithHashContainer<AuthorizationAuthorityCertificate>,
        _timestamp: Instant, // TODO: verify the timestamp from the request.
        backend: &B,
    ) -> AuthorizationResponseResult<AuthorizationResponse> {
        let decrypted =
            message::handle_encrypted_response(response, &ctx.outer_encryption_key, backend)
                .map_err(AuthorizationResponseError::DecryptionHandler)?;

        let outer_response = AuthorizationResponse::parse_outer_authorization_response(&decrypted)?;

        let valid_signature = message::verify_signed_data(
            &outer_response,
            aa_certificate.certificate(),
            backend,
            |signer_id| match signer_id {
                SignerIdentifier::Digest(h) => {
                    if aa_certificate.hashed_id8() == h {
                        Ok(Some(
                            aa_certificate
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
        .map_err(AuthorizationResponseError::OuterVerifier)?;

        if !valid_signature {
            return Err(AuthorizationResponseError::FalseOuterSignature);
        }

        let payload = outer_response
            .payload_data()
            .map_err(AuthorizationResponseError::Outer)?;

        AuthorizationResponse::from_bytes(payload)
    }
}
