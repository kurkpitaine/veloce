use core::fmt;

use veloce_asn1::{
    defs::{
        etsi_102941_v221::{
            etsi_ts102941_base_types::{
                CertificateFormat, CertificateSubjectAttributes, EcSignature as EtsiEcSignature,
                PublicKeys, Version,
            },
            etsi_ts102941_messages_ca::{EtsiTs102941Data, EtsiTs102941DataContent},
            etsi_ts102941_types_authorization::{
                AuthorizationResponseCode as EtsiAuthorizationResponseCode, InnerAtRequest,
                InnerAtResponse as EtsiInnerAtResponse, SharedAtRequest,
            },
            ieee1609_dot2_base_types::{
                EccP256CurvePoint, HashedId8 as EtsiHashedId8, PublicEncryptionKey,
                PublicVerificationKey, SequenceOfPsidSsp, SymmAlgorithm,
            },
        },
        etsi_103097_v211::{
            etsi_ts103097_module::{
                EtsiTs103097Certificate, EtsiTs103097Data, EtsiTs103097DataEncrypted,
            },
            ieee1609_dot2::{
                AesCcmCiphertext, EncryptedData as EtsiEncryptedData, Ieee1609Dot2Content,
                Ieee1609Dot2Data, SequenceOfRecipientInfo, SymmetricCiphertext,
            },
            ieee1609_dot2_base_types::{Opaque, Uint8},
        },
    },
    prelude::rasn::types::{FixedOctetString, Integer, OctetString},
};

use crate::{
    pki::{
        asn1_wrapper::{Asn1Wrapper, Asn1WrapperError},
        encrypted_data::{EncryptedData, EncryptedDataError},
        signed_data::{SignedData, SignedDataError, SignedDataPayloadType},
        HashedData, SignerIdentifier,
    },
    security::{
        backend::BackendError,
        certificate::{AuthorizationTicketCertificate, CertificateError, CertificateTrait},
        permission::{Permission, PermissionError, AID},
        EcdsaKey, EcdsaKeyError, EciesKey, EciesKeyError, HashedId8, ValidityPeriod,
    },
    time::{Instant, TAI2004},
};

use super::{
    EncryptedResponseHandlerError, EncryptionError, HmacAndTagError, SignerError, VerifierError,
};

/// EC Signature type.
#[derive(Debug, Clone, PartialEq)]
pub enum EcSignature {
    /// Encrypted EC Signature. Used when privacy is required.
    Encrypted(EncryptedData),
    /// Plain EC Signature, without encryption.
    Plain(EcSignatureSignedExternalPayload),
}

/// Marker struct for EC Signature Signed External Payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedExternalPayload;

/// Marker struct for the Proof Of Possession wrapper type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct POP;

/// EC Signature Signed External Payload type.
pub type EcSignatureSignedExternalPayload = SignedData<SignedExternalPayload>;
/// Proof Of Possession wrapper type.
pub type ProofOfPossessionWrapper = SignedData<POP>;

pub type AuthorizationRequestResult<T> = core::result::Result<T, AuthorizationRequestError>;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Enrollment Request errors.
pub enum AuthorizationRequestError {
    /// Asn.1 wrapper error.
    Asn1Wrapper(Asn1WrapperError),
    /// Verification key.
    VerificationKey(EcdsaKeyError),
    /// Permission error.
    Permission(PermissionError),
    /// No application permissions present in the request.
    NoApplicationPermissions,
    /// Key tag is malformed.
    KeyTag,
    /// Something went wrong while generating HMAC and tag.
    HmacAndTagGenerator(HmacAndTagError),
    /// EC certificate error.
    EcCertificate(CertificateError),
    /// Crypto backend error.
    Backend(BackendError),
    /// Encryption key error.
    EncryptionKey(EciesKeyError),
    /// Signed external payload wrapper.
    EcSignature(SignedDataError),
    /// Something went wrong while signing the Inner Signed external payload.
    EcSignatureSigner(SignerError),
    /// Etsi wrapper.
    EtsiWrapper(Asn1WrapperError),
    /// Something went wrong while encrypting the Signed external payload.
    PrivacyEncryption(EncryptionError),
    /// Encrypted wrapper.
    PrivacyEncrypted(EncryptedDataError),
    /// Something went wrong while encrypting the Outer wrapper.
    Encryption(EncryptionError),
    /// Encrypted wrapper.
    Encrypted(EncryptedDataError),
    /// Pop wrapper.
    PopWrapper(SignedDataError),
    /// Something went wrong while signing the Pop wrapper.
    PopWrapperSigner(SignerError),
    /// Something went wrong while verifying the Pop wrapper.
    PopWrapperVerifier(VerifierError),
}

impl fmt::Display for AuthorizationRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationRequestError::Asn1Wrapper(e) => write!(f, "asn1 wrapper: {}", e),
            AuthorizationRequestError::VerificationKey(e) => {
                write!(f, "verification key: {}", e)
            }
            AuthorizationRequestError::Permission(e) => write!(f, "permission: {}", e),
            AuthorizationRequestError::NoApplicationPermissions => {
                write!(f, "no application permissions")
            }
            AuthorizationRequestError::KeyTag => {
                write!(f, "key tag")
            }
            AuthorizationRequestError::HmacAndTagGenerator(e) => {
                write!(f, "HMAC and tag generator: {}", e)
            }
            AuthorizationRequestError::EcCertificate(e) => write!(f, "EC certificate: {}", e),
            AuthorizationRequestError::Backend(e) => write!(f, "backend: {}", e),
            AuthorizationRequestError::EncryptionKey(e) => write!(f, "encryption key: {}", e),
            AuthorizationRequestError::EcSignature(e) => write!(f, "external payload: {}", e),
            AuthorizationRequestError::EcSignatureSigner(e) => {
                write!(f, "external payload signer: {}", e)
            }
            AuthorizationRequestError::EtsiWrapper(e) => write!(f, "etsi wrapper: {}", e),
            AuthorizationRequestError::PrivacyEncryption(e) => {
                write!(f, "privacy encryption : {}", e)
            }
            AuthorizationRequestError::PrivacyEncrypted(e) => write!(f, "privacy encrypted: {}", e),
            AuthorizationRequestError::Encryption(e) => write!(f, "encryption: {}", e),
            AuthorizationRequestError::Encrypted(e) => write!(f, "encrypted: {}", e),
            AuthorizationRequestError::PopWrapper(e) => write!(f, "pop wrapper: {}", e),
            AuthorizationRequestError::PopWrapperSigner(e) => {
                write!(f, "pop wrapper signer: {}", e)
            }
            AuthorizationRequestError::PopWrapperVerifier(e) => {
                write!(f, "pop wrapper verifier: {}", e)
            }
        }
    }
}

/// Authorization Request.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationRequest {
    /// Inner authorization ticket request structure.
    inner: InnerAtRequest,
}

impl AuthorizationRequest {
    /// Constructs an [AuthorizationRequest] with default values.
    pub fn new() -> Self {
        let shared_at_request = SharedAtRequest::new(
            EtsiHashedId8(FixedOctetString::new([0; 8])),
            FixedOctetString::new([0; 16]),
            CertificateFormat(1),
            CertificateSubjectAttributes::new(None, None, None, None, None, None),
        );

        let verification_key = PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::fill(()));
        let public_keys = PublicKeys::new(verification_key, None);
        let hmac_key = FixedOctetString::new([0; 32]);

        let encrypted_data = EtsiEncryptedData::new(
            SequenceOfRecipientInfo(vec![]),
            SymmetricCiphertext::aes128ccm(AesCcmCiphertext::new(
                FixedOctetString::new([0; 12]),
                Opaque(OctetString::new()),
            )),
        );
        let content = Ieee1609Dot2Content::encryptedData(encrypted_data);
        let ieee_data = Ieee1609Dot2Data::new(Uint8(3), content);
        let ec_signature = EtsiEcSignature::encryptedEcSignature(EtsiTs103097DataEncrypted(
            EtsiTs103097Data(ieee_data),
        ));

        let inner = InnerAtRequest::new(public_keys, hmac_key, shared_at_request, ec_signature);

        Self { inner }
    }

    /// Constructs a [AuthorizationRequest] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AuthorizationRequestResult<Self> {
        Ok(Self {
            inner: Asn1Wrapper::decode_coer(bytes)
                .map_err(AuthorizationRequestError::Asn1Wrapper)?,
        })
    }

    /// Get the [AuthorizationRequest] as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> AuthorizationRequestResult<Vec<u8>> {
        Asn1Wrapper::encode_coer(&self.inner).map_err(AuthorizationRequestError::Asn1Wrapper)
    }

    /// Get the shared_at_request part of the [AuthorizationRequest] as bytes, encoded as Asn.1 COER.
    pub fn shared_at_request_bytes(&self) -> AuthorizationRequestResult<Vec<u8>> {
        Asn1Wrapper::encode_coer(&self.inner.shared_at_request)
            .map_err(AuthorizationRequestError::Asn1Wrapper)
    }

    /// Get the Enrollment Authority Identifier of the [AuthorizationRequest].
    pub fn ea_id(&self) -> HashedId8 {
        HashedId8::from(&self.inner.shared_at_request.ea_id)
    }

    /// Set the Enrollment Authority Identifier of the [AuthorizationRequest].
    pub fn set_ea_id(&mut self, ea_id: HashedId8) {
        self.inner.shared_at_request.ea_id = ea_id.into();
    }

    /// Get the key tag field of the [AuthorizationRequest].
    pub fn key_tag(&self) -> Vec<u8> {
        self.inner.shared_at_request.key_tag.to_vec()
    }

    /// Set the key tag field of the [AuthorizationRequest].
    pub fn set_key_tag(&mut self, key_tag: Vec<u8>) -> AuthorizationRequestResult<()> {
        self.inner.shared_at_request.key_tag =
            FixedOctetString::try_from(key_tag).map_err(|_| AuthorizationRequestError::KeyTag)?;

        Ok(())
    }

    /// Get the application permissions of the [AuthorizationRequest].
    pub fn app_permissions(&self) -> AuthorizationRequestResult<Vec<Permission>> {
        let Some(seq_psid_ssp) = &self
            .inner
            .shared_at_request
            .requested_subject_attributes
            .app_permissions
        else {
            return Err(AuthorizationRequestError::NoApplicationPermissions);
        };

        let mut res = Vec::with_capacity(seq_psid_ssp.0.len());

        for psid_ssp in &seq_psid_ssp.0 {
            res.push(
                Permission::try_from(psid_ssp).map_err(AuthorizationRequestError::Permission)?,
            );
        }

        Ok(res)
    }

    /// Sets the application permissions if the provided `permissions` is not empty.
    pub fn set_app_permissions(&mut self, permissions: Vec<Permission>) {
        if permissions.is_empty() {
            return;
        }

        let psid_ssp = permissions.into_iter().map(|p| p.into()).collect();
        self.inner
            .shared_at_request
            .requested_subject_attributes
            .app_permissions = Some(SequenceOfPsidSsp(psid_ssp));
    }

    /// Get the validity period of the [AuthorizationRequest] if any.
    pub fn validity_period(&self) -> Option<ValidityPeriod> {
        self.inner
            .shared_at_request
            .requested_subject_attributes
            .validity_period
            .as_ref()
            .map(ValidityPeriod::from)
    }

    /// Set the validity period of the [AuthorizationRequest].
    pub fn set_validity_period(&mut self, period: ValidityPeriod) {
        self.inner
            .shared_at_request
            .requested_subject_attributes
            .validity_period = Some(period.into());
    }

    /// Get the [EcSignature] of the [AuthorizationRequest].
    pub fn ec_signature(&self) -> AuthorizationRequestResult<EcSignature> {
        let res = match &self.inner.ec_signature {
            EtsiEcSignature::encryptedEcSignature(etsi_encrypted) => {
                let ec = EncryptedData::from_raw(etsi_encrypted.to_owned())
                    .map_err(AuthorizationRequestError::PrivacyEncrypted)?;

                EcSignature::Encrypted(ec)
            }
            EtsiEcSignature::ecSignature(etsi_signature) => {
                let ec = EcSignatureSignedExternalPayload::from_raw_external_payload(
                    etsi_signature.clone(),
                )
                .map_err(AuthorizationRequestError::EcSignature)?;

                EcSignature::Plain(ec)
            }
        };

        Ok(res)
    }

    /// Set the [EcSignature] of the [AuthorizationRequest].
    pub fn set_ec_signature(&mut self, signature: EcSignature) -> AuthorizationRequestResult<()> {
        self.inner.ec_signature = match signature {
            EcSignature::Encrypted(ec) => EtsiEcSignature::encryptedEcSignature(
                ec.as_raw()
                    .map_err(AuthorizationRequestError::PrivacyEncrypted)?,
            ),
            EcSignature::Plain(ec) => EtsiEcSignature::ecSignature(
                ec.as_raw_external_payload_or_panic()
                    .map_err(AuthorizationRequestError::EcSignature)?,
            ),
        };

        Ok(())
    }

    /// Get the HMAC key of the [AuthorizationRequest].
    pub fn hmac_key(&self) -> [u8; 32] {
        *self.inner.hmac_key
    }

    /// Set the HMAC key of the [AuthorizationRequest].
    pub fn set_hmac_key(&mut self, key: [u8; 32]) {
        self.inner.hmac_key = key.into();
    }

    /// Get the verification key of the [AuthorizationRequest].
    pub fn public_verification_key(&self) -> AuthorizationRequestResult<EcdsaKey> {
        EcdsaKey::try_from(&self.inner.public_keys.verification_key)
            .map_err(AuthorizationRequestError::VerificationKey)
    }

    /// Set the verification key of the [AuthorizationRequest].
    pub fn set_public_verification_key(&mut self, key: EcdsaKey) -> AuthorizationRequestResult<()> {
        self.inner.public_keys.verification_key = key
            .try_into()
            .map_err(AuthorizationRequestError::VerificationKey)?;

        Ok(())
    }

    /// Get the public encryption key of the [AuthorizationRequest], if any.
    pub fn public_encryption_key(&self) -> AuthorizationRequestResult<Option<EciesKey>> {
        let Some(key) = &self.inner.public_keys.encryption_key else {
            return Ok(None);
        };

        let key = EciesKey::try_from(&key.public_key)
            .map_err(AuthorizationRequestError::EncryptionKey)?;

        Ok(Some(key))
    }

    /// Set the public encryption key of the [AuthorizationRequest].
    pub fn set_public_encryption_key(&mut self, key: EciesKey) -> AuthorizationRequestResult<()> {
        self.inner.public_keys.encryption_key = Some(PublicEncryptionKey {
            supported_symm_alg: SymmAlgorithm::aes128Ccm,
            public_key: key
                .try_into()
                .map_err(AuthorizationRequestError::EncryptionKey)?,
        });

        Ok(())
    }

    /// Generate the EC Signature Signed External Payload part of the [AuthorizationRequest].
    /// The returned [AuthorizationRequest] is ready to be signed. It does not contain any signature.
    pub fn emit_ec_signature_signed_external_payload(
        payload: HashedData,
        signer: HashedId8,
        timestamp: Instant,
    ) -> AuthorizationRequestResult<EcSignatureSignedExternalPayload> {
        let mut ext_payload =
            EcSignatureSignedExternalPayload::new(SignedDataPayloadType::ExtDataHash(payload))
                .map_err(AuthorizationRequestError::EcSignature)?;

        ext_payload
            .set_application_id(AID::SCR)
            .map_err(AuthorizationRequestError::EcSignature)?;

        ext_payload
            .set_generation_time(TAI2004::from_unix_instant(timestamp))
            .map_err(AuthorizationRequestError::EcSignature)?;

        ext_payload
            .set_signer_identifier(SignerIdentifier::Digest(signer))
            .map_err(AuthorizationRequestError::EcSignature)?;

        Ok(ext_payload)
    }

    /// Generate the ETSI wrapper part of the [AuthorizationRequest].
    pub fn emit_etsi_wrapper(at_request: AuthorizationRequest) -> EtsiTs102941Data {
        EtsiTs102941Data::new(
            Version(Integer::from(1)),
            EtsiTs102941DataContent::authorizationRequest(at_request.inner),
        )
    }

    /// Generate the ETSI wrapper part of the [AuthorizationRequest].
    pub fn emit_pop_wrapper(
        etsi_data: EtsiTs102941Data,
        timestamp: Instant,
    ) -> AuthorizationRequestResult<ProofOfPossessionWrapper> {
        let etsi_data_encoded =
            Asn1Wrapper::encode_coer(&etsi_data).map_err(AuthorizationRequestError::EtsiWrapper)?;

        let mut pop_wrapper =
            ProofOfPossessionWrapper::new(SignedDataPayloadType::Data(etsi_data_encoded))
                .map_err(AuthorizationRequestError::PopWrapper)?;

        pop_wrapper
            .set_application_id(AID::SCR)
            .map_err(AuthorizationRequestError::PopWrapper)?;

        pop_wrapper
            .set_generation_time(TAI2004::from_unix_instant(timestamp))
            .map_err(AuthorizationRequestError::PopWrapper)?;

        pop_wrapper
            .set_signer_identifier(SignerIdentifier::SelfSigned)
            .map_err(AuthorizationRequestError::PopWrapper)?;

        Ok(pop_wrapper)
    }
}

impl Default for AuthorizationRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Marker struct for Outer Authorization Response type.
#[derive(Debug, Clone, Copy)]
pub struct OuterResp;

/// Outer Authorization Response type.
pub type OuterAuthorizationResponse = SignedData<OuterResp>;

/// [AuthorizationResponse] methods result type.
pub type AuthorizationResponseResult<T> = core::result::Result<T, AuthorizationResponseError>;

/// Authorization Response errors.
#[derive(Debug)]
pub enum AuthorizationResponseError {
    /// Asn.1 wrapper error.
    Asn1Wrapper(Asn1WrapperError),
    /// Certificate error.
    Certificate(CertificateError),
    /// Authorization Ticket error.
    AuthorizationTicket(CertificateError),
    /// Malformed, ie: a mandatory field
    /// is absent or a present field should be absent.
    Malformed,
    /// Unexpected Etsi TS 102941 data content.
    UnexpectedDataContent,
    /// Request hash is unsupported.
    UnsupportedRequestHash,
    /// Something went wrong while decrypting the Outer wrapper.
    DecryptionHandler(EncryptedResponseHandlerError),
    /// Outer wrapper.
    Outer(SignedDataError),
    /// Something went wrong while verifying the Outer wrapper.
    OuterVerifier(VerifierError),
    /// False Outer wrapper signature.
    FalseOuterSignature,
    /// Response code is not supported.
    UnsupportedResponseCode(u64),
    /// Request failed, ie: the response code is not ok.
    Failure(AuthorizationResponseCode),
}

impl fmt::Display for AuthorizationResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationResponseError::Asn1Wrapper(e) => write!(f, "asn1 wrapper error: {}", e),
            AuthorizationResponseError::Certificate(e) => {
                write!(f, "certificate: {}", e)
            }
            AuthorizationResponseError::AuthorizationTicket(e) => {
                write!(f, "authorization ticket: {}", e)
            }
            AuthorizationResponseError::Malformed => write!(f, "malformed response"),
            AuthorizationResponseError::UnexpectedDataContent => {
                write!(f, "unexpected Etsi TS 102941 data content")
            }
            AuthorizationResponseError::UnsupportedRequestHash => {
                write!(f, "unsupported request hash")
            }

            AuthorizationResponseError::DecryptionHandler(e) => {
                write!(f, "decryption handler: {}", e)
            }
            AuthorizationResponseError::Outer(e) => write!(f, "outer: {}", e),
            AuthorizationResponseError::OuterVerifier(e) => write!(f, "outer verifier: {}", e),
            AuthorizationResponseError::FalseOuterSignature => write!(f, "false outer signature"),
            AuthorizationResponseError::UnsupportedResponseCode(u) => {
                write!(f, "unsupported response code: {}", u)
            }
            AuthorizationResponseError::Failure(e) => write!(f, "failure: {}", e),
        }
    }
}

/// Authorization Response.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationResponse {
    /// Inner authorization response structure.
    inner: EtsiInnerAtResponse,
}

impl AuthorizationResponse {
    /// Constructs an [AuthorizationResponse] from bytes. The EtsiTs102941Data wrapper is expected.
    pub fn from_bytes(bytes: &[u8]) -> AuthorizationResponseResult<Self> {
        let etsi_data = Asn1Wrapper::<EtsiTs102941Data>::decode_coer(bytes)
            .map_err(AuthorizationResponseError::Asn1Wrapper)?;

        let inner = match etsi_data.content {
            EtsiTs102941DataContent::authorizationResponse(r) => r,
            _ => return Err(AuthorizationResponseError::UnexpectedDataContent),
        };

        Ok(Self { inner })
    }

    /// Get the [AuthorizationResponse] as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> AuthorizationResponseResult<Vec<u8>> {
        Asn1Wrapper::encode_coer(&self.inner).map_err(AuthorizationResponseError::Asn1Wrapper)
    }

    /// Get the request hash of the [AuthorizationResponse].
    pub fn request_hash(&self) -> Vec<u8> {
        self.inner.request_hash.to_vec()
    }

    /// Set the request hash of the [AuthorizationResponse].
    pub fn set_request_hash(&mut self, hash: Vec<u8>) -> AuthorizationResponseResult<()> {
        self.inner.request_hash = FixedOctetString::<16>::new(
            hash.try_into()
                .map_err(|_| AuthorizationResponseError::UnsupportedRequestHash)?,
        );

        Ok(())
    }

    /// Get the response code of the [AuthorizationResponse].
    pub fn response_code(&self) -> AuthorizationResponseResult<AuthorizationResponseCode> {
        self.inner.response_code.try_into()
    }

    /// Set the response code of the [AuthorizationResponse].
    pub fn set_response_code(&mut self, code: AuthorizationResponseCode) {
        self.inner.response_code = code.into();
    }

    /// Get the Authorization Ticket of the [AuthorizationResponse], as an [AuthorizationTicketCertificate].
    pub fn authorization_ticket(
        &self,
    ) -> AuthorizationResponseResult<Option<AuthorizationTicketCertificate>> {
        let Some(cert) = &self.inner.certificate else {
            return Ok(None);
        };

        Ok(Some(
            AuthorizationTicketCertificate::from_etsi_cert_without_canonicalization(cert.0.clone())
                .map_err(AuthorizationResponseError::Certificate)?,
        ))
    }

    /// Set the Authorization Ticket of the [AuthorizationResponse].
    pub fn set_authorization_ticket(&mut self, cred: AuthorizationTicketCertificate) {
        self.inner.certificate = Some(EtsiTs103097Certificate(cred.inner().to_owned()));
    }

    /// Check `data` is valid according to InnerAtResponse Asn.1 definition.
    /// This method is necessary as the rasn Asn.1 compiler does not generate
    /// the validation code for custom parameterized types.
    #[inline]
    fn verify_constraints(data: &EtsiInnerAtResponse) -> AuthorizationResponseResult<()> {
        match (data.response_code, &data.certificate) {
            (EtsiAuthorizationResponseCode::ok, Some(_)) => {}
            (EtsiAuthorizationResponseCode::ok, None) => {
                return Err(AuthorizationResponseError::Malformed)
            }
            (_, None) => {}
            _ => return Err(AuthorizationResponseError::Malformed),
        };

        Ok(())
    }

    /// Parse the outer Authorization response.
    pub fn parse_outer_authorization_response(
        bytes: &[u8],
    ) -> AuthorizationResponseResult<OuterAuthorizationResponse> {
        OuterAuthorizationResponse::from_bytes_signed(bytes)
            .map_err(AuthorizationResponseError::Outer)
    }
}

impl TryFrom<EtsiInnerAtResponse> for AuthorizationResponse {
    type Error = AuthorizationResponseError;

    fn try_from(value: EtsiInnerAtResponse) -> Result<Self, Self::Error> {
        Self::verify_constraints(&value)?;

        Ok(AuthorizationResponse { inner: value })
    }
}

/// Authorization Response code returned by the PKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationResponseCode {
    /// Success.
    Ok,
    /// Can't parse. Valid for any enclosed structure.
    ItsAaCantparse,
    /// not encrypted, not signed, not AuthorizationRequest.
    ItsAaBadcontenttype,
    /// The "recipients" of the outermost encrypted data doesn't include me.
    ItsAaImNotTheRcipient,
    /// Either Kexalg or Contentencryptionalgorithm.
    ItsAaUnknownEncryptionAlgorithm,
    /// Works for ECIES-HMAC and AES-CCM.
    ItsAaDecryptionFailed,
    /// HMAC keyTag verification fails.
    ItsAaKeysDontMatch,
    /// Some elements are missing.
    ItsAaIncompleteRequest,
    /// The ResponseEncryptionKey is bad.
    ItsAaInvalidEncryptionKey,
    /// SigningTime is outside acceptable limits.
    ItsAaOutOfSyncRequest,
    /// The EA identified by eaId is unknown to me.
    ItsAaUnknownEa,
    /// The EA certificate is revoked
    ItsAaInvalidEa,
    /// I, the AA, deny the requested permissions.
    ItsAaDeniedPermissions,
    /// The EA is unreachable (network error?).
    AaEaCantReachEa,
    /// Valid for any structure.
    EaAaCantParse,
    /// Not encrypted, not signed, not AuthorizationRequest.
    EaAaBadContentType,
    /// The "recipients" of the outermost encrypted data doesn't include me
    EaAaImNotTheRecipient,
    /// Either Kexalg or Contentencryptionalgorithm.
    EaAaUnknownEncryptionAlgorithm,
    /// Works for ECIES-HMAC and AES-CCM.
    EaAaDecryptionFailed,
    /// The AA certificate presented is invalid/revoked/whatever.
    InvalidAa,
    /// The AA certificate presented can't validate the request signature.
    InvalidAaSignature,
    /// The encrypted signature doesn't designate me as the EA.
    WrongEa,
    /// Can't retrieve the EC/ITS in my DB.
    UnknownIts,
    /// Signature verification of the request by the EC fails.
    InvalidSignature,
    /// Signature is good, but the key is bad.
    InvalidEncryptionKey,
    /// Permissions not granted.
    DeniedPermissions,
    /// Parallel limit.
    DeniedTooManyCerts,
}

impl fmt::Display for AuthorizationResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationResponseCode::Ok => write!(f, "ok"),
            AuthorizationResponseCode::ItsAaCantparse => write!(f, "[ITS -> AA] - can't parse"),
            AuthorizationResponseCode::ItsAaBadcontenttype => {
                write!(f, "[ITS -> AA] - bad content type")
            }
            AuthorizationResponseCode::ItsAaImNotTheRcipient => {
                write!(f, "[ITS -> AA] - i'm not the recipient")
            }
            AuthorizationResponseCode::ItsAaUnknownEncryptionAlgorithm => {
                write!(f, "[ITS -> AA] - unknown encryption algorithm")
            }
            AuthorizationResponseCode::ItsAaDecryptionFailed => {
                write!(f, "[ITS -> AA] - decryption failed")
            }
            AuthorizationResponseCode::ItsAaKeysDontMatch => {
                write!(f, "[ITS -> AA] - keys don't match")
            }
            AuthorizationResponseCode::ItsAaIncompleteRequest => {
                write!(f, "[ITS -> AA] - incomplete request")
            }
            AuthorizationResponseCode::ItsAaInvalidEncryptionKey => {
                write!(f, "[ITS -> AA] - invalid encryption key")
            }
            AuthorizationResponseCode::ItsAaOutOfSyncRequest => {
                write!(f, "[ITS -> AA] - out of sync request")
            }
            AuthorizationResponseCode::ItsAaUnknownEa => write!(f, "[ITS -> AA] - unknown EA"),
            AuthorizationResponseCode::ItsAaInvalidEa => write!(f, "[ITS -> AA] - invalid EA"),
            AuthorizationResponseCode::ItsAaDeniedPermissions => {
                write!(f, "[ITS -> AA] - denied permissions")
            }
            AuthorizationResponseCode::AaEaCantReachEa => {
                write!(f, "[AA -> EA] - can't reach EA")
            }
            AuthorizationResponseCode::EaAaCantParse => write!(f, "[EA -> AA] - can't parse"),
            AuthorizationResponseCode::EaAaBadContentType => {
                write!(f, "[EA -> AA] - bad content type")
            }
            AuthorizationResponseCode::EaAaImNotTheRecipient => {
                write!(f, "[EA -> AA] - i'm not the recipient")
            }
            AuthorizationResponseCode::EaAaUnknownEncryptionAlgorithm => {
                write!(f, "[EA -> AA] - unknown encryption algorithm")
            }
            AuthorizationResponseCode::EaAaDecryptionFailed => {
                write!(f, "[EA -> AA] - decryption failed")
            }
            AuthorizationResponseCode::InvalidAa => write!(f, "invalid AA"),
            AuthorizationResponseCode::InvalidAaSignature => {
                write!(f, "invalid AA signature")
            }
            AuthorizationResponseCode::WrongEa => write!(f, "wrong EA"),
            AuthorizationResponseCode::UnknownIts => write!(f, "unknown ITS"),
            AuthorizationResponseCode::InvalidSignature => write!(f, "invalid signature"),
            AuthorizationResponseCode::InvalidEncryptionKey => {
                write!(f, "invalid encryption key")
            }
            AuthorizationResponseCode::DeniedPermissions => {
                write!(f, "denied permissions")
            }
            AuthorizationResponseCode::DeniedTooManyCerts => {
                write!(f, "denied too many certs")
            }
        }
    }
}

impl TryFrom<EtsiAuthorizationResponseCode> for AuthorizationResponseCode {
    type Error = AuthorizationResponseError;

    fn try_from(value: EtsiAuthorizationResponseCode) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiAuthorizationResponseCode::ok => AuthorizationResponseCode::Ok,
            EtsiAuthorizationResponseCode::its_aa_cantparse => {
                AuthorizationResponseCode::ItsAaCantparse
            }
            EtsiAuthorizationResponseCode::its_aa_badcontenttype => {
                AuthorizationResponseCode::ItsAaBadcontenttype
            }
            EtsiAuthorizationResponseCode::its_aa_imnottherecipient => {
                AuthorizationResponseCode::ItsAaImNotTheRcipient
            }
            EtsiAuthorizationResponseCode::its_aa_unknownencryptionalgorithm => {
                AuthorizationResponseCode::ItsAaUnknownEncryptionAlgorithm
            }
            EtsiAuthorizationResponseCode::its_aa_decryptionfailed => {
                AuthorizationResponseCode::ItsAaDecryptionFailed
            }
            EtsiAuthorizationResponseCode::its_aa_keysdontmatch => {
                AuthorizationResponseCode::ItsAaKeysDontMatch
            }
            EtsiAuthorizationResponseCode::its_aa_incompleterequest => {
                AuthorizationResponseCode::ItsAaIncompleteRequest
            }
            EtsiAuthorizationResponseCode::its_aa_invalidencryptionkey => {
                AuthorizationResponseCode::ItsAaInvalidEncryptionKey
            }
            EtsiAuthorizationResponseCode::its_aa_outofsyncrequest => {
                AuthorizationResponseCode::ItsAaOutOfSyncRequest
            }
            EtsiAuthorizationResponseCode::its_aa_unknownea => {
                AuthorizationResponseCode::ItsAaUnknownEa
            }
            EtsiAuthorizationResponseCode::its_aa_invalidea => {
                AuthorizationResponseCode::ItsAaInvalidEa
            }
            EtsiAuthorizationResponseCode::its_aa_deniedpermissions => {
                AuthorizationResponseCode::ItsAaDeniedPermissions
            }
            EtsiAuthorizationResponseCode::aa_ea_cantreachea => {
                AuthorizationResponseCode::AaEaCantReachEa
            }
            EtsiAuthorizationResponseCode::ea_aa_cantparse => {
                AuthorizationResponseCode::EaAaCantParse
            }
            EtsiAuthorizationResponseCode::ea_aa_badcontenttype => {
                AuthorizationResponseCode::EaAaBadContentType
            }
            EtsiAuthorizationResponseCode::ea_aa_imnottherecipient => {
                AuthorizationResponseCode::EaAaImNotTheRecipient
            }
            EtsiAuthorizationResponseCode::ea_aa_unknownencryptionalgorithm => {
                AuthorizationResponseCode::EaAaUnknownEncryptionAlgorithm
            }
            EtsiAuthorizationResponseCode::ea_aa_decryptionfailed => {
                AuthorizationResponseCode::EaAaDecryptionFailed
            }
            EtsiAuthorizationResponseCode::invalidaa => AuthorizationResponseCode::InvalidAa,
            EtsiAuthorizationResponseCode::invalidaasignature => {
                AuthorizationResponseCode::InvalidAaSignature
            }
            EtsiAuthorizationResponseCode::wrongea => AuthorizationResponseCode::WrongEa,
            EtsiAuthorizationResponseCode::unknownits => AuthorizationResponseCode::UnknownIts,
            EtsiAuthorizationResponseCode::invalidsignature => {
                AuthorizationResponseCode::InvalidSignature
            }
            EtsiAuthorizationResponseCode::invalidencryptionkey => {
                AuthorizationResponseCode::InvalidEncryptionKey
            }
            EtsiAuthorizationResponseCode::deniedpermissions => {
                AuthorizationResponseCode::DeniedPermissions
            }
            EtsiAuthorizationResponseCode::deniedtoomanycerts => {
                AuthorizationResponseCode::DeniedTooManyCerts
            }
            other => {
                return Err(AuthorizationResponseError::UnsupportedResponseCode(
                    other as u64,
                ))
            }
        };

        Ok(res)
    }
}

impl From<AuthorizationResponseCode> for EtsiAuthorizationResponseCode {
    fn from(value: AuthorizationResponseCode) -> Self {
        match value {
            AuthorizationResponseCode::Ok => EtsiAuthorizationResponseCode::ok,
            AuthorizationResponseCode::ItsAaCantparse => {
                EtsiAuthorizationResponseCode::its_aa_cantparse
            }
            AuthorizationResponseCode::ItsAaBadcontenttype => {
                EtsiAuthorizationResponseCode::its_aa_badcontenttype
            }
            AuthorizationResponseCode::ItsAaImNotTheRcipient => {
                EtsiAuthorizationResponseCode::its_aa_imnottherecipient
            }
            AuthorizationResponseCode::ItsAaUnknownEncryptionAlgorithm => {
                EtsiAuthorizationResponseCode::its_aa_unknownencryptionalgorithm
            }
            AuthorizationResponseCode::ItsAaDecryptionFailed => {
                EtsiAuthorizationResponseCode::its_aa_decryptionfailed
            }
            AuthorizationResponseCode::ItsAaKeysDontMatch => {
                EtsiAuthorizationResponseCode::its_aa_keysdontmatch
            }
            AuthorizationResponseCode::ItsAaIncompleteRequest => {
                EtsiAuthorizationResponseCode::its_aa_incompleterequest
            }
            AuthorizationResponseCode::ItsAaInvalidEncryptionKey => {
                EtsiAuthorizationResponseCode::its_aa_invalidencryptionkey
            }
            AuthorizationResponseCode::ItsAaOutOfSyncRequest => {
                EtsiAuthorizationResponseCode::its_aa_outofsyncrequest
            }
            AuthorizationResponseCode::ItsAaUnknownEa => {
                EtsiAuthorizationResponseCode::its_aa_unknownea
            }
            AuthorizationResponseCode::ItsAaInvalidEa => {
                EtsiAuthorizationResponseCode::its_aa_invalidea
            }
            AuthorizationResponseCode::ItsAaDeniedPermissions => {
                EtsiAuthorizationResponseCode::its_aa_deniedpermissions
            }
            AuthorizationResponseCode::AaEaCantReachEa => {
                EtsiAuthorizationResponseCode::aa_ea_cantreachea
            }
            AuthorizationResponseCode::EaAaCantParse => {
                EtsiAuthorizationResponseCode::ea_aa_cantparse
            }
            AuthorizationResponseCode::EaAaBadContentType => {
                EtsiAuthorizationResponseCode::ea_aa_badcontenttype
            }
            AuthorizationResponseCode::EaAaImNotTheRecipient => {
                EtsiAuthorizationResponseCode::ea_aa_imnottherecipient
            }
            AuthorizationResponseCode::EaAaUnknownEncryptionAlgorithm => {
                EtsiAuthorizationResponseCode::ea_aa_unknownencryptionalgorithm
            }
            AuthorizationResponseCode::EaAaDecryptionFailed => {
                EtsiAuthorizationResponseCode::ea_aa_decryptionfailed
            }
            AuthorizationResponseCode::InvalidAa => EtsiAuthorizationResponseCode::invalidaa,
            AuthorizationResponseCode::InvalidAaSignature => {
                EtsiAuthorizationResponseCode::invalidaasignature
            }
            AuthorizationResponseCode::WrongEa => EtsiAuthorizationResponseCode::wrongea,
            AuthorizationResponseCode::UnknownIts => EtsiAuthorizationResponseCode::unknownits,
            AuthorizationResponseCode::InvalidSignature => {
                EtsiAuthorizationResponseCode::invalidsignature
            }
            AuthorizationResponseCode::InvalidEncryptionKey => {
                EtsiAuthorizationResponseCode::invalidencryptionkey
            }
            AuthorizationResponseCode::DeniedPermissions => {
                EtsiAuthorizationResponseCode::deniedpermissions
            }
            AuthorizationResponseCode::DeniedTooManyCerts => {
                EtsiAuthorizationResponseCode::deniedtoomanycerts
            }
        }
    }
}
