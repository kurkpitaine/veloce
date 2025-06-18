use core::fmt;

use veloce_asn1::{
    defs::{
        etsi_102941_v221::{
            etsi_ts102941_base_types::{
                CertificateFormat, CertificateSubjectAttributes, PublicKeys, Version,
            },
            etsi_ts102941_messages_ca::{EtsiTs102941Data, EtsiTs102941DataContent},
            etsi_ts102941_types_enrolment::{
                EnrolmentResponseCode as EtsiEnrollmentResponseCode,
                InnerEcRequest as EtsiInnerEcRequest,
                InnerEcRequestSignedForPop as EtsiInnerEcRequestSignedForPop,
                InnerEcResponse as EtsiInnerEcResponse,
            },
            ieee1609_dot2_base_types::{
                EccP256CurvePoint, PublicVerificationKey, SequenceOfPsidSsp,
            },
        },
        etsi_103097_v211::etsi_ts103097_module::EtsiTs103097Certificate,
    },
    prelude::rasn::types::{FixedOctetString, Integer, OctetString},
};

use crate::{
    pki::{
        asn1_wrapper::{Asn1Wrapper, Asn1WrapperError},
        encrypted_data::EncryptedDataError,
        signed_data::{SignedData, SignedDataError, SignedDataPayloadType},
        SignerIdentifier,
    },
    security::{
        backend::BackendError,
        certificate::{CertificateError, CertificateTrait, EnrollmentCredentialCertificate},
        permission::{Permission, PermissionError, AID},
        EcdsaKey, EcdsaKeyError,
    },
    time::{Instant, TAI2004},
};

use super::{EncryptedResponseHandlerError, EncryptionError, SignerError, VerifierError};

pub type EnrollmentRequestResult<T> = core::result::Result<T, EnrollmentRequestError>;

/// Marker struct for EC Request Signed for POP type.
#[derive(Debug, Clone, Copy)]
pub struct InnerReqForPop;

/// Marker struct for Outer EC Request type.
#[derive(Debug, Clone, Copy)]
pub struct OuterReq;

/// EC Request Signed for POP type.
pub type InnerEcRequestSignedForPop = SignedData<InnerReqForPop>;
/// Outer EC Request type.
pub type OuterEcRequest = SignedData<OuterReq>;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Enrollment Request errors.
pub enum EnrollmentRequestError {
    /// Asn.1 wrapper error.
    Asn1Wrapper(Asn1WrapperError),
    /// Verification key.
    VerificationKey(EcdsaKeyError),
    /// Certificate format is unexpected.
    UnexpectedCertificateFormat,
    /// Enrollment request content is malformed, ie: a mandatory field
    /// is absent or a present field should be absent.
    Malformed,
    /// No application permissions present in the request.
    NoApplicationPermissions,
    /// Permission error.
    Permission(PermissionError),
    /// Crypto backend error.
    Backend(BackendError),
    /// Inner Signed for Pop wrapper.
    SignedForPop(SignedDataError),
    /// Outer wrapper.
    Outer(SignedDataError),
    /// Something went wrong while signing the Inner Signed for Pop wrapper.
    SignedForPopSigner(SignerError),
    /// Something went wrong while verifying the Inner Signed for Pop wrapper.
    SignedForPopVerifier(VerifierError),
    /// Something went wrong while signing the Outer wrapper.
    OuterSigner(SignerError),
    /// Something went wrong while encrypting the Outer wrapper.
    Encryption(EncryptionError),
    /// Encrypted wrapper.
    Encrypted(EncryptedDataError),
    /// No canonical key available.
    NoCanonicalKey,
    /// No enrollment key available.
    NoEnrollmentKey,
}

impl fmt::Display for EnrollmentRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollmentRequestError::Asn1Wrapper(e) => write!(f, "asn1 wrapper error: {}", e),
            EnrollmentRequestError::VerificationKey(e) => {
                write!(f, "verification key: {}", e)
            }
            EnrollmentRequestError::UnexpectedCertificateFormat => {
                write!(f, "unexpected certificate format value")
            }
            EnrollmentRequestError::Malformed => {
                write!(f, "malformed request")
            }
            EnrollmentRequestError::NoApplicationPermissions => {
                write!(f, "no application permissions")
            }
            EnrollmentRequestError::Permission(e) => write!(f, "permission: {}", e),
            EnrollmentRequestError::Backend(e) => write!(f, "backend: {}", e),
            EnrollmentRequestError::SignedForPop(e) => write!(f, "signed for POP: {}", e),
            EnrollmentRequestError::Outer(e) => write!(f, "outer: {}", e),
            EnrollmentRequestError::SignedForPopSigner(e) => {
                write!(f, "signed for POP signer: {}", e)
            }
            EnrollmentRequestError::SignedForPopVerifier(e) => {
                write!(f, "signed for POP verifier: {}", e)
            }
            EnrollmentRequestError::OuterSigner(e) => write!(f, "outer signer: {}", e),
            EnrollmentRequestError::Encryption(e) => write!(f, "encryption : {}", e),
            EnrollmentRequestError::Encrypted(e) => write!(f, "encrypted: {}", e),
            EnrollmentRequestError::NoCanonicalKey => write!(f, "no canonical key available"),
            EnrollmentRequestError::NoEnrollmentKey => write!(f, "no enrollment key available"),
        }
    }
}

/// Enrollment Request.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrollmentRequest {
    /// Inner enrollment request structure.
    inner: Asn1Wrapper<EtsiInnerEcRequest>,
}

impl EnrollmentRequest {
    /// Constructs an [EnrollmentRequest] for `requester_id` with default values.
    pub fn new(requester_id: Vec<u8>) -> Self {
        let its_id = OctetString::from(requester_id);
        let certificate_format = CertificateFormat(1);
        let public_keys = PublicKeys::new(
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::fill(())),
            None,
        );
        let requested_subject_attributes =
            CertificateSubjectAttributes::new(None, None, None, None, None, None);

        let inner_ec_req = EtsiInnerEcRequest::new(
            its_id,
            certificate_format,
            public_keys,
            requested_subject_attributes,
        );

        let inner = Asn1Wrapper::from_raw_unverified(inner_ec_req);

        Self { inner }
    }

    /// Constructs a [EnrollmentRequest] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> EnrollmentRequestResult<Self> {
        Ok(Self {
            inner: Asn1Wrapper::from_bytes(bytes).map_err(EnrollmentRequestError::Asn1Wrapper)?,
        })
    }

    /// Get the [EnrollmentRequest] as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> EnrollmentRequestResult<Vec<u8>> {
        self.inner
            .as_bytes()
            .map_err(EnrollmentRequestError::Asn1Wrapper)
    }

    /// Get the verification key of the [EnrollmentRequest].
    pub fn verification_key(&self) -> EnrollmentRequestResult<EcdsaKey> {
        let inner = self.inner.inner();
        EcdsaKey::try_from(&inner.public_keys.verification_key)
            .map_err(EnrollmentRequestError::VerificationKey)
    }

    /// Set the verification key of the [EnrollmentRequest].
    pub fn set_verification_key(&mut self, key: EcdsaKey) -> EnrollmentRequestResult<()> {
        let inner = self.inner.inner_mut();
        inner.public_keys.verification_key = key
            .try_into()
            .map_err(EnrollmentRequestError::VerificationKey)?;

        Ok(())
    }

    /// Get the application permissions of the [EnrollmentRequest].
    pub fn app_permissions(&self) -> EnrollmentRequestResult<Vec<Permission>> {
        let inner = self.inner.inner();
        let Some(seq_psid_ssp) = &inner.requested_subject_attributes.app_permissions else {
            return Err(EnrollmentRequestError::NoApplicationPermissions);
        };

        let mut res = Vec::with_capacity(seq_psid_ssp.0.len());

        for psid_ssp in &seq_psid_ssp.0 {
            res.push(Permission::try_from(psid_ssp).map_err(EnrollmentRequestError::Permission)?);
        }

        Ok(res)
    }

    /// Sets the application permissions if the provided `permissions` is not empty.
    pub fn set_app_permissions(&mut self, permissions: Vec<Permission>) {
        let inner = self.inner.inner_mut();
        if permissions.is_empty() {
            return;
        }

        let psid_ssp = permissions.into_iter().map(|p| p.into()).collect();
        inner.requested_subject_attributes.app_permissions = Some(SequenceOfPsidSsp(psid_ssp));
    }

    /// Wraps the [EnrollmentRequest] into the Inner EC Request Signed for POP container.
    /// The returned [InnerEcRequestSignedForPop] is ready to be signed. It does not contain any signature.
    pub fn emit_inner_ec_request_for_pop(
        enrollment_req: EnrollmentRequest,
        timestamp: Instant,
    ) -> EnrollmentRequestResult<InnerEcRequestSignedForPop> {
        let encoded = enrollment_req.as_bytes()?;

        let mut for_pop = SignedData::new(SignedDataPayloadType::Data(encoded))
            .map_err(EnrollmentRequestError::SignedForPop)?;

        for_pop
            .set_application_id(AID::SCR)
            .map_err(EnrollmentRequestError::SignedForPop)?;

        for_pop
            .set_generation_time(TAI2004::from_unix_instant(timestamp))
            .map_err(EnrollmentRequestError::SignedForPop)?;

        for_pop
            .set_signer_identifier(SignerIdentifier::SelfSigned)
            .map_err(EnrollmentRequestError::SignedForPop)?;

        Ok(for_pop)
    }

    /// Wraps the [InnerEcRequestSignedForPop] into the Outer EC Request container.
    /// The returned [OuterEcRequest] is ready to be signed. It does not contain any signature.
    pub fn emit_outer_ec_request(
        for_pop: InnerEcRequestSignedForPop,
        signer: SignerIdentifier,
        timestamp: Instant,
    ) -> EnrollmentRequestResult<OuterEcRequest> {
        let etsi_data = EtsiTs102941Data::new(
            Version(Integer::from(1)),
            EtsiTs102941DataContent::enrolmentRequest(EtsiInnerEcRequestSignedForPop(
                for_pop
                    .as_raw_signed_or_panic()
                    .map_err(EnrollmentRequestError::SignedForPop)?,
            )),
        );

        let etsi_data_encoded = Asn1Wrapper::encode_coer(&etsi_data)
            .map_err(SignedDataError::Asn1Wrapper)
            .map_err(EnrollmentRequestError::SignedForPop)?;

        let mut outer_ec_request = SignedData::new(SignedDataPayloadType::Data(etsi_data_encoded))
            .map_err(EnrollmentRequestError::Outer)?;

        outer_ec_request
            .set_application_id(AID::SCR)
            .map_err(EnrollmentRequestError::Outer)?;

        outer_ec_request
            .set_generation_time(TAI2004::from_unix_instant(timestamp))
            .map_err(EnrollmentRequestError::Outer)?;

        outer_ec_request
            .set_signer_identifier(signer)
            .map_err(EnrollmentRequestError::Outer)?;

        Ok(outer_ec_request)
    }
}

impl TryFrom<EtsiInnerEcRequest> for EnrollmentRequest {
    type Error = EnrollmentRequestError;

    fn try_from(value: EtsiInnerEcRequest) -> Result<Self, Self::Error> {
        let inner = Asn1Wrapper::from_raw(value).map_err(EnrollmentRequestError::Asn1Wrapper)?;

        if inner.inner().certificate_format.0 != 1 {
            return Err(EnrollmentRequestError::UnexpectedCertificateFormat);
        }

        Ok(EnrollmentRequest { inner })
    }
}

/// Marker struct for Outer EC Response type.
#[derive(Debug, Clone, Copy)]
pub struct OuterResp;

/// Outer EC Response type.
pub type OuterEcResponse = SignedData<OuterResp>;

/// [EnrollmentResponse] methods result type.
pub type EnrollmentResponseResult<T> = core::result::Result<T, EnrollmentResponseError>;

/// Enrollment Response errors.
#[derive(Debug)]
pub enum EnrollmentResponseError {
    /// Asn.1 wrapper error.
    Asn1Wrapper(Asn1WrapperError),
    /// Verification key.
    VerificationKey(EcdsaKeyError),
    /// Certificate error.
    Certificate(CertificateError),
    /// Enrollment credential error.
    EnrollmentCredentialCertificate(CertificateError),
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
    Failure(EnrollmentResponseCode),
}

impl fmt::Display for EnrollmentResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollmentResponseError::Asn1Wrapper(e) => write!(f, "asn1 wrapper error: {}", e),
            EnrollmentResponseError::VerificationKey(e) => {
                write!(f, "verification key: {}", e)
            }
            EnrollmentResponseError::Certificate(e) => {
                write!(f, "certificate: {}", e)
            }
            EnrollmentResponseError::EnrollmentCredentialCertificate(e) => {
                write!(f, "enrollment credential: {}", e)
            }
            EnrollmentResponseError::UnsupportedRequestHash => {
                write!(f, "unsupported request hash")
            }
            EnrollmentResponseError::DecryptionHandler(e) => write!(f, "decryption handler: {}", e),
            EnrollmentResponseError::Malformed => write!(f, "malformed response"),
            EnrollmentResponseError::UnexpectedDataContent => {
                write!(f, "unexpected Etsi TS 102941 data content")
            }
            EnrollmentResponseError::Outer(e) => write!(f, "outer: {}", e),
            EnrollmentResponseError::OuterVerifier(e) => write!(f, "outer verifier: {}", e),
            EnrollmentResponseError::FalseOuterSignature => write!(f, "false outer signature"),
            EnrollmentResponseError::UnsupportedResponseCode(u) => {
                write!(f, "unsupported response code: {}", u)
            }
            EnrollmentResponseError::Failure(e) => write!(f, "failure: {}", e),
        }
    }
}

/// Enrollment Response.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrollmentResponse {
    /// Inner enrollment response structure.
    inner: Asn1Wrapper<EtsiInnerEcResponse>,
}

impl EnrollmentResponse {
    /// Constructs an [EnrollmentResponse] from bytes. The [EtsiTs102941Data] wrapper is expected.
    pub fn from_bytes(bytes: &[u8]) -> EnrollmentResponseResult<Self> {
        let etsi_data = Asn1Wrapper::<EtsiTs102941Data>::decode_coer(bytes)
            .map_err(EnrollmentResponseError::Asn1Wrapper)?;

        let inner_ec_response = match etsi_data.content {
            EtsiTs102941DataContent::enrolmentResponse(r) => r,
            _ => return Err(EnrollmentResponseError::UnexpectedDataContent),
        };

        let inner = Asn1Wrapper::from_raw(inner_ec_response)
            .map_err(EnrollmentResponseError::Asn1Wrapper)?;

        Ok(Self { inner })
    }

    /// Get the [EnrollmentResponse] wrapped in The [EtsiTs102941Data] as bytes, encoded as Asn.1 COER.
    pub fn as_bytes(&self) -> EnrollmentResponseResult<Vec<u8>> {
        let etsi_wrapper = EtsiTs102941Data::new(
            Version(Integer::from(1)),
            EtsiTs102941DataContent::enrolmentResponse(
                self.inner
                    .as_raw()
                    .map_err(EnrollmentResponseError::Asn1Wrapper)?,
            ),
        );

        Asn1Wrapper::encode_coer(&etsi_wrapper).map_err(EnrollmentResponseError::Asn1Wrapper)
    }

    /// Get the request hash of the [EnrollmentResponse].
    pub fn request_hash(&self) -> Vec<u8> {
        let inner = self.inner.inner();
        inner.request_hash.to_vec()
    }

    /// Set the request hash of the [EnrollmentResponse].
    pub fn set_request_hash(&mut self, hash: Vec<u8>) -> EnrollmentResponseResult<()> {
        let inner = self.inner.inner_mut();

        inner.request_hash = FixedOctetString::<16>::new(
            hash.try_into()
                .map_err(|_| EnrollmentResponseError::UnsupportedRequestHash)?,
        );

        Ok(())
    }

    /// Get the response code of the [EnrollmentResponse].
    pub fn response_code(&self) -> EnrollmentResponseResult<EnrollmentResponseCode> {
        let inner = self.inner.inner();
        inner.response_code.try_into()
    }

    /// Set the response code of the [EnrollmentResponse].
    pub fn set_response_code(&mut self, code: EnrollmentResponseCode) {
        let inner = self.inner.inner_mut();
        inner.response_code = code.into();
    }

    /// Get the certificate of the [EnrollmentResponse], as an [EnrollmentCredentialCertificate].
    pub fn enrollment_credential(
        &self,
    ) -> EnrollmentResponseResult<Option<EnrollmentCredentialCertificate>> {
        let inner = self.inner.inner();
        let Some(cert) = &inner.certificate else {
            return Ok(None);
        };

        Ok(Some(
            EnrollmentCredentialCertificate::from_etsi_cert(cert.0.clone())
                .map_err(EnrollmentResponseError::Certificate)?,
        ))
    }

    /// Set the Enrollment Credential of the [EnrollmentResponse].
    pub fn set_enrollment_credential(&mut self, cred: EnrollmentCredentialCertificate) {
        let inner = self.inner.inner_mut();
        inner.certificate = Some(EtsiTs103097Certificate(cred.inner().to_owned()));
    }

    /// Parse the outer EC response.
    pub fn parse_outer_ec_response(bytes: &[u8]) -> EnrollmentResponseResult<OuterEcResponse> {
        OuterEcResponse::from_bytes_signed(bytes).map_err(EnrollmentResponseError::Outer)
    }
}

impl TryFrom<EtsiInnerEcResponse> for EnrollmentResponse {
    type Error = EnrollmentResponseError;

    fn try_from(value: EtsiInnerEcResponse) -> Result<Self, Self::Error> {
        let inner = Asn1Wrapper::from_raw(value).map_err(EnrollmentResponseError::Asn1Wrapper)?;

        Ok(EnrollmentResponse { inner })
    }
}

/// Enrollment Response code returned by the PKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentResponseCode {
    /// Success.
    Ok,
    /// Can't parse. Valid for any enclosed structure.
    CantParse,
    /// Not encrypted, not signed, not EnrollmentRequest
    BadContentType,
    /// The "recipients" doesn't include me.
    ImNotTheRecipient,
    /// Either Kexalg or Contentencryptionalgorithm.
    UnknownEncryptionAlgorithm,
    /// Works for ECIES-HMAC and AES-CCM.
    DecryptionFailed,
    /// Can't retrieve the ITS from the itsId.
    UnknownIts,
    /// Signature verification of the request failed.
    InvalidSignature,
    /// Signature is good, but the responseEncryptionKey is bad.
    InvalidEncryptionKey,
    /// Revoked, not yet active.
    BadItsStatus,
    /// Some elements are missing.
    IncompleteRequest,
    /// Requested permissions are not granted.
    DeniedPermissions,
    /// Either the verification_key of the encryption_key is bad.
    InvalidKeys,
    /// Any other reason ?
    DeniedRequest,
}

impl fmt::Display for EnrollmentResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollmentResponseCode::Ok => write!(f, "ok"),
            EnrollmentResponseCode::CantParse => write!(f, "can't parse"),
            EnrollmentResponseCode::BadContentType => write!(f, "bad content type"),
            EnrollmentResponseCode::ImNotTheRecipient => write!(f, "i'm not the recipient"),
            EnrollmentResponseCode::UnknownEncryptionAlgorithm => {
                write!(f, "unknown encryption algorithm")
            }
            EnrollmentResponseCode::DecryptionFailed => write!(f, "decryption failed"),
            EnrollmentResponseCode::UnknownIts => write!(f, "unknown ITS"),
            EnrollmentResponseCode::InvalidSignature => write!(f, "invalid signature"),
            EnrollmentResponseCode::InvalidEncryptionKey => write!(f, "invalid encryption key"),
            EnrollmentResponseCode::BadItsStatus => write!(f, "bad ITS status"),
            EnrollmentResponseCode::IncompleteRequest => write!(f, "incomplete request"),
            EnrollmentResponseCode::DeniedPermissions => write!(f, "denied permissions"),
            EnrollmentResponseCode::InvalidKeys => write!(f, "invalid keys"),
            EnrollmentResponseCode::DeniedRequest => write!(f, "denied request"),
        }
    }
}

impl TryFrom<EtsiEnrollmentResponseCode> for EnrollmentResponseCode {
    type Error = EnrollmentResponseError;

    fn try_from(value: EtsiEnrollmentResponseCode) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiEnrollmentResponseCode::ok => EnrollmentResponseCode::Ok,
            EtsiEnrollmentResponseCode::cantparse => EnrollmentResponseCode::CantParse,
            EtsiEnrollmentResponseCode::badcontenttype => EnrollmentResponseCode::BadContentType,
            EtsiEnrollmentResponseCode::imnottherecipient => {
                EnrollmentResponseCode::ImNotTheRecipient
            }
            EtsiEnrollmentResponseCode::unknownencryptionalgorithm => {
                EnrollmentResponseCode::UnknownEncryptionAlgorithm
            }
            EtsiEnrollmentResponseCode::decryptionfailed => {
                EnrollmentResponseCode::DecryptionFailed
            }
            EtsiEnrollmentResponseCode::unknownits => EnrollmentResponseCode::UnknownIts,
            EtsiEnrollmentResponseCode::invalidsignature => {
                EnrollmentResponseCode::InvalidSignature
            }
            EtsiEnrollmentResponseCode::invalidencryptionkey => {
                EnrollmentResponseCode::InvalidEncryptionKey
            }
            EtsiEnrollmentResponseCode::baditsstatus => EnrollmentResponseCode::BadItsStatus,
            EtsiEnrollmentResponseCode::incompleterequest => {
                EnrollmentResponseCode::IncompleteRequest
            }
            EtsiEnrollmentResponseCode::deniedpermissions => {
                EnrollmentResponseCode::DeniedPermissions
            }
            EtsiEnrollmentResponseCode::invalidkeys => EnrollmentResponseCode::InvalidKeys,
            EtsiEnrollmentResponseCode::deniedrequest => EnrollmentResponseCode::DeniedRequest,
            other => {
                return Err(EnrollmentResponseError::UnsupportedResponseCode(
                    other as u64,
                ))
            }
        };

        Ok(res)
    }
}

impl From<EnrollmentResponseCode> for EtsiEnrollmentResponseCode {
    fn from(value: EnrollmentResponseCode) -> Self {
        match value {
            EnrollmentResponseCode::Ok => EtsiEnrollmentResponseCode::ok,
            EnrollmentResponseCode::CantParse => EtsiEnrollmentResponseCode::cantparse,
            EnrollmentResponseCode::BadContentType => EtsiEnrollmentResponseCode::badcontenttype,
            EnrollmentResponseCode::ImNotTheRecipient => {
                EtsiEnrollmentResponseCode::imnottherecipient
            }
            EnrollmentResponseCode::UnknownEncryptionAlgorithm => {
                EtsiEnrollmentResponseCode::unknownencryptionalgorithm
            }
            EnrollmentResponseCode::DecryptionFailed => {
                EtsiEnrollmentResponseCode::decryptionfailed
            }
            EnrollmentResponseCode::UnknownIts => EtsiEnrollmentResponseCode::unknownits,
            EnrollmentResponseCode::InvalidSignature => {
                EtsiEnrollmentResponseCode::invalidsignature
            }
            EnrollmentResponseCode::InvalidEncryptionKey => {
                EtsiEnrollmentResponseCode::invalidencryptionkey
            }
            EnrollmentResponseCode::BadItsStatus => EtsiEnrollmentResponseCode::baditsstatus,
            EnrollmentResponseCode::IncompleteRequest => {
                EtsiEnrollmentResponseCode::incompleterequest
            }
            EnrollmentResponseCode::DeniedPermissions => {
                EtsiEnrollmentResponseCode::deniedpermissions
            }
            EnrollmentResponseCode::InvalidKeys => EtsiEnrollmentResponseCode::invalidkeys,
            EnrollmentResponseCode::DeniedRequest => EtsiEnrollmentResponseCode::deniedrequest,
        }
    }
}

/* #[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// A container around an enrollment message request/response.
pub struct Enrollment {
    /// Inner EC Request Signed For POP
    inner_ec_request_signed_for_pop: Option<Asn1Wrapper<EtsiTs103097DataSigned>>,
    /// Canonical Key Signed Data.
    outer_ec_request: Option<Asn1Wrapper<EtsiTs103097DataSigned>>,
    /// Encrypted envelope.
    encrypted: Option<Asn1Wrapper<EtsiTs103097DataSignedAndEncryptedUnicast>>,
}

impl Enrollment {
    /* /// Constructs an [Enrollment] message from bytes, encoded as Asn.1 COER.
    pub fn from_bytes<B>(
        bytes: &[u8],
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        backend: &B,
    ) -> MessageResult<Self>
    where
        B: PkiBackendTrait,
    {
        let request = Asn1Wrapper::<EtsiTs103097DataSignedAndEncryptedUnicast>::from_bytes(bytes)
            .map_err(MessageError::InvalidContent)?;

        let decrypted = Self::decrypt_request(&request, ea_certificate, backend)?;

        let outer_ec_request = Asn1Wrapper::<EtsiTs103097DataSigned>::from_bytes(&decrypted)
            .map_err(MessageError::InvalidContent)?;

        let outer_data = Self::signed_data_payload_as::<EtsiTs102941Data>(&outer_ec_request)?;

        let inner_ec_request_signed_for_pop = match outer_data.content {
            EtsiTs102941DataContent::enrolmentRequest(i) => {
                Asn1Wrapper::<EtsiTs103097DataSigned>::from_raw(i.0)
                    .map_err(MessageError::InvalidContent)?
            }
            _ => return Err(MessageError::UnexpectedDataContent),
        };

        let inner_ec_request = Asn1Wrapper::<EtsiInnerEcRequest>::from_bytes(bytes)
            .map_err(MessageError::InvalidContent)?;

        let Some(req_subject_attributes) = inner_ec_request
            .inner()
            .requested_subject_attributes
            .cert_issue_permissions
        else {
            return Err(MessageError::InvalidContent);
        };

        let issue_perm = ea_certificate
            .certificate()
            .issue_permissions()
            .map_err(MessageError::InvalidCertificate)?;

        // Check that all requested permissions are in the certificate.
        req_subject_attributes.0.iter().all(|p| {
            match p.subject_permissions {
                veloce_asn1::defs::etsi_102941_v221::ieee1609_dot2::SubjectPermissions::explicit(sequence_of_psid_ssp_range) => EnrollmentResponseCode::,
                veloce_asn1::defs::etsi_102941_v221::ieee1609_dot2::SubjectPermissions::all(_) => EnrollmentResponseCode::,
                _ => EnrollmentResponseCode::,
            }
        });

        inner_ec_request.inner().public_keys.verification_key;
        inner_ec_request.inner().requested_subject_attributes;

        Self::verify_outer_signed_data(&outer_ec_request, ea_certificate, backend)?;
        Self::verify_inner_ec_request_signed_for_pop(
            &inner_ec_request_signed_for_pop,
            ea_certificate,
            backend,
        )?;

        Ok(Self {
            inner_ec_request_signed_for_pop: None,
            outer_ec_request: None,
            encrypted: None,
        })
    }
 */

    /* /// Decrypt the `request` using the local certificate and the backend.
    fn decrypt_request<B>(
        request: &Asn1Wrapper<EtsiTs103097DataSignedAndEncryptedUnicast>,
        ea_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        backend: &B,
    ) -> MessageResult<Vec<u8>>
    where
        B: PkiBackendTrait,
    {
        let recipient = Self::recipient_info(request)?;

        let pk_recipient = match &recipient {
            RecipientInfo::Cert(pkr) => pkr,
            _ => return Err(MessageError::UnexpectedRecipientInformation),
        };

        // Should be the HashedId8 of the local certificate.
        if pk_recipient.recipient_id != ea_certificate.hashed_id8() {
            return Err(MessageError::UnknownRecipientId(pk_recipient.recipient_id));
        }

        // Ephemeral public key.
        let (pk_params, hash_algorithm) = match &pk_recipient.enc_key {
            EncryptedEciesKey::NistP256r1(p) => (p, HashAlgorithm::SHA256),
            EncryptedEciesKey::BrainpoolP256r1(p) => (p, HashAlgorithm::SHA384),
        };

        let public_key = pk_recipient.enc_key.public_key();
        let peer_public_key =
            B::BackendPublicKey::try_from(public_key).map_err(MessageError::Backend)?;

        // Reconstruct the shared secret.
        let shared_secret = backend
            .derive_canonical(&peer_public_key)
            .map_err(MessageError::Backend)?;

        let cert_hash = ea_certificate.certificate().hash(hash_algorithm, backend);

        let (ke_size, km_size) = match hash_algorithm {
            HashAlgorithm::SHA256 | HashAlgorithm::SM3 => (16, 32),
            HashAlgorithm::SHA384 => (24, 48),
        };

        // Verify received tag.
        let ke_km = kdf2(
            &shared_secret,
            &cert_hash,
            ke_size + km_size,
            hash_algorithm,
            backend,
        );

        let computed_tag = backend
            .hmac(hash_algorithm, &ke_km[ke_size..], &pk_params.encrypted_key)
            .map_err(MessageError::Backend)?;

        if computed_tag != pk_params.tag {
            return Err(MessageError::InvalidTag);
        }

        // Decrypt encryption key.
        let encryption_key: Vec<u8> = pk_params
            .encrypted_key
            .iter()
            .zip(ke_km[..ke_size].iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let ciphertext = Self::ciphertext(request)?;

        backend
            .decrypt_with_key(&ciphertext, &encryption_key)
            .map_err(MessageError::Backend)
    } */

    /* fn verify_inner_ec_request_signed_for_pop<B>(
        data: &Asn1Wrapper<EtsiTs103097DataSigned>,
        local_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        backend: &B,
    ) -> MessageResult<()>
    where
        B: PkiBackendTrait + ?Sized,
    {
        let valid = Self::verify_signed_data(data, local_certificate, backend, |signer_id| {
            // TODO: complete these functions when EnrollmentRequestContext is done.
            match signer_id {
                SignerIdentifier::SelfSigned => {} // Signed with the verification private key to be certified. Verification key in the EtsiInnerEcRequest.
                _ => return Err(MessageError::UnexpectedSigner),
            }
            Ok(None)
        })?;

        if !valid {
            return Err(MessageError::FalseInnerSignature);
        }

        Ok(())
    } */

    /* fn verify_outer_signed_data<B>(
        data: &Asn1Wrapper<EtsiTs103097DataSigned>,
        local_certificate: &CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
        backend: &B,
    ) -> MessageResult<()>
    where
        B: PkiBackendTrait + ?Sized,
    {
        let valid = Self::verify_signed_data(data, local_certificate, backend, |signer_id| {
            // TODO: complete these functions when EnrollmentRequestContext is done.
            match signer_id {
                SignerIdentifier::SelfSigned => {} // Signed with canonical private key.
                SignerIdentifier::Digest(_) => {} // Signed with the enrollment credential private key. Value should be equal to the its_id in the EtsiInnerEcRequest.
            }
            Ok(None)
        })?;

        if !valid {
            return Err(MessageError::FalseOuterSignature);
        }

        Ok(())
    } */
}*/
