pub mod enrollment;

use core::fmt;

use veloce_asn1::{
    defs::etsi_103097_v211::{ieee1609_dot2, ieee1609_dot2_base_types::SymmetricEncryptionKey},
    prelude::rasn::types::FixedOctetString,
};

use crate::security::{
    backend::{BackendError, BackendResult, BackendTrait, PkiBackendTrait},
    certificate::{CertificateError, CertificateWithHashContainer, ExplicitCertificate},
    ciphertext::{Ciphertext, CiphertextError},
    permission::AID,
    signature::EcdsaSignature,
    EcdsaKey, EncryptedEciesKey, EncryptedEciesKeyError, HashAlgorithm, HashedId8, KeyPair,
};

use super::{
    asn1_wrapper::{Asn1Wrapper, Asn1WrapperResult},
    encrypted_data::{EncryptedData, EncryptedDataError},
    kdf2,
    signed_data::{SignedData, SignedDataError},
    Aes128Key, SignerIdentifier,
};

pub type MessageResult<T> = core::result::Result<T, MessageError>;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MessageError {
    /// Signature of the inner envelope is invalid.
    FalseInnerSignature,
    /// Signature of the outer envelope is invalid.
    FalseOuterSignature,
    /// Recipient id is unknown, the message is not addressed to us.
    UnknownRecipientId(HashedId8),
    /// Recipient information choice is unexpected for the message.
    UnexpectedRecipientInformation,
    /// Recipient information type is not supported for the message.
    RecipientInformation(RecipientInfoError),
    /// Ciphertext type is not supported for the message.
    Ciphertext(CiphertextError),
    /// Signed Data Message has invalid content.
    InvalidSignedDataContent(SignedDataError),
    /// Certificate is invalid.
    InvalidCertificate(CertificateError),
    /// Certificate has insufficient permissions to sign the secured message.
    InsufficientPermissions,
    /// Message encryption tag is invalid.
    InvalidTag,
    /// Invalid AID.
    InvalidAid { expected: AID, actual: AID },
    /// Timestamp (generation time) is outside certificate validity period.
    OffValidityPeriod,
    /// Signer identifier type is unexpected
    UnexpectedSigner,
    /// Data content type is unexpected.
    UnexpectedDataContent,
    /// Certificate format is unexpected.
    UnexpectedCertificateFormat,
    /// Signer identifier is unknown.
    UnknownSigner(SignerIdentifier),
    /// Backend error.
    Backend(BackendError),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::FalseInnerSignature => write!(f, "false inner signature"),
            MessageError::FalseOuterSignature => write!(f, "false outer signature"),
            MessageError::UnknownRecipientId(h) => {
                write!(f, "unknown recipient id: {}", h)
            }
            MessageError::UnexpectedRecipientInformation => {
                write!(f, "unexpected recipient information",)
            }
            MessageError::RecipientInformation(e) => {
                write!(f, "unsupported recipient information: {}", e)
            }
            MessageError::InvalidCertificate(e) => {
                write!(f, "invalid certificate: {}", e)
            }
            MessageError::InsufficientPermissions => write!(f, "insufficient permissions"),
            MessageError::Ciphertext(e) => {
                write!(f, "unsupported ciphertext: {}", e)
            }
            MessageError::InvalidSignedDataContent(e) => {
                write!(f, "invalid signed data content: {}", e)
            }
            MessageError::InvalidTag => {
                write!(f, "invalid tag")
            }
            MessageError::InvalidAid { expected, actual } => {
                write!(f, "invalid AID: expected {}, actual {}", expected, actual)
            }
            MessageError::OffValidityPeriod => write!(f, "off validity period"),
            MessageError::UnexpectedSigner => write!(f, "unexpected signer"),
            MessageError::UnexpectedDataContent => write!(f, "unexpected data content"),
            MessageError::UnexpectedCertificateFormat => write!(f, "unexpected certificate format"),
            MessageError::UnknownSigner(h) => write!(f, "unknown signer: {}", h),
            MessageError::Backend(e) => {
                write!(f, "backend error: {}", e)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Recipient information type.
pub enum RecipientInfo {
    /// The ciphertext was encrypted directly using a symmetric key.
    PSK(HashedId8),
    /// The data encryption key was encrypted using a public key encryption scheme,
    /// where the public encryption key was obtained from a certificate.
    Cert(PrivateKeyRecipientInfo),
}

impl RecipientInfo {
    /// Constructs a new [RecipientInfo::Cert] from a `recipient_id` and an `enc_key`.
    pub fn new_cert(recipient_id: HashedId8, enc_key: EncryptedEciesKey) -> Self {
        RecipientInfo::Cert(PrivateKeyRecipientInfo {
            recipient_id,
            enc_key,
        })
    }
}

/// Error for types conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecipientInfoError {
    /// Unsupported recipient information type.
    Unsupported,
    /// Private key recipient information error.
    PKRecipient(PrivateKeyRecipientInfoError),
}

impl fmt::Display for RecipientInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecipientInfoError::Unsupported => {
                write!(f, "unsupported")
            }
            RecipientInfoError::PKRecipient(e) => {
                write!(f, "pk recipient: {}", e)
            }
        }
    }
}

impl TryFrom<&ieee1609_dot2::RecipientInfo> for RecipientInfo {
    type Error = RecipientInfoError;

    fn try_from(value: &ieee1609_dot2::RecipientInfo) -> Result<Self, Self::Error> {
        let res = match value {
            ieee1609_dot2::RecipientInfo::pskRecipInfo(p) => {
                RecipientInfo::PSK(HashedId8::from(&p.0))
            }
            ieee1609_dot2::RecipientInfo::certRecipInfo(c) => RecipientInfo::Cert(
                PrivateKeyRecipientInfo::try_from(c).map_err(RecipientInfoError::PKRecipient)?,
            ),
            _ => return Err(RecipientInfoError::Unsupported),
        };

        Ok(res)
    }
}

impl TryInto<ieee1609_dot2::RecipientInfo> for RecipientInfo {
    type Error = RecipientInfoError;

    fn try_into(self) -> Result<ieee1609_dot2::RecipientInfo, Self::Error> {
        let res = match self {
            RecipientInfo::PSK(p) => ieee1609_dot2::RecipientInfo::pskRecipInfo(
                ieee1609_dot2::PreSharedKeyRecipientInfo(p.into()),
            ),
            RecipientInfo::Cert(c) => ieee1609_dot2::RecipientInfo::certRecipInfo(
                c.try_into().map_err(RecipientInfoError::PKRecipient)?,
            ),
        };

        Ok(res)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrivateKeyRecipientInfo {
    /// Recipient identifier.
    pub recipient_id: HashedId8,
    /// Encrypted ephemeral private key.
    pub enc_key: EncryptedEciesKey,
}

/// Error for types conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PrivateKeyRecipientInfoError {
    /// Key type is unsupported.
    EncryptedKey(EncryptedEciesKeyError),
}

impl fmt::Display for PrivateKeyRecipientInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivateKeyRecipientInfoError::EncryptedKey(e) => write!(f, "encrypted key: {}", e),
        }
    }
}

impl TryFrom<&ieee1609_dot2::PKRecipientInfo> for PrivateKeyRecipientInfo {
    type Error = PrivateKeyRecipientInfoError;

    fn try_from(value: &ieee1609_dot2::PKRecipientInfo) -> Result<Self, Self::Error> {
        let res = PrivateKeyRecipientInfo {
            recipient_id: HashedId8::from(&value.recipient_id),
            enc_key: EncryptedEciesKey::try_from(&value.enc_key)
                .map_err(PrivateKeyRecipientInfoError::EncryptedKey)?,
        };

        Ok(res)
    }
}

impl TryInto<ieee1609_dot2::PKRecipientInfo> for PrivateKeyRecipientInfo {
    type Error = PrivateKeyRecipientInfoError;

    fn try_into(self) -> Result<ieee1609_dot2::PKRecipientInfo, Self::Error> {
        let res = ieee1609_dot2::PKRecipientInfo {
            recipient_id: self.recipient_id.into(),
            enc_key: self
                .enc_key
                .try_into()
                .map_err(PrivateKeyRecipientInfoError::EncryptedKey)?,
        };

        Ok(res)
    }
}

/// Verifier result type.
pub type VerifierResult<T> = core::result::Result<T, VerifierError>;

#[derive(Debug)]
/// Error returned by [`verify_signed_data`].
pub enum VerifierError {
    /// Backend error.
    Backend(BackendError),
    /// Signed data error.
    SignedData(SignedDataError),
    /// Unknown signer.
    UnknownSigner(SignerIdentifier),
    /// Unexpected signer type.
    UnexpectedSigner,
    /// Invalid AID.
    InvalidAid {
        /// Expected AID.
        expected: AID,
        /// Actual AID.
        actual: AID,
    },
    /// Invalid certificate.
    InvalidCertificate(CertificateError),
    /// Insufficient permissions.
    InsufficientPermissions,
    /// Off validity period.
    OffValidityPeriod,
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifierError::Backend(e) => write!(f, "backend error: {}", e),
            VerifierError::SignedData(e) => write!(f, "signed data error: {}", e),
            VerifierError::UnknownSigner(h) => write!(f, "unknown signer: {}", h),
            VerifierError::UnexpectedSigner => write!(f, "unexpected signer type"),
            VerifierError::InvalidAid { expected, actual } => {
                write!(f, "invalid AID: expected {}, actual {}", expected, actual)
            }
            VerifierError::InvalidCertificate(e) => {
                write!(f, "invalid certificate: {}", e)
            }
            VerifierError::InsufficientPermissions => write!(f, "insufficient permissions"),
            VerifierError::OffValidityPeriod => write!(f, "off validity period"),
        }
    }
}

/// Verifies the validity of the [SignedData] `data` message.
/// Various content checks are performed and the signature is verified with the provided `backend` and `certificate`.
/// `pub_key` callback should provide the public key used to verify the signature. None is returned if it cannot be found.
/// `verify_app` callback verifies if the AID matches the application. Expected AID should be returned if not.
pub fn verify_signed_data<B, F, A, T>(
    data: &SignedData<T>,
    certificate: &impl ExplicitCertificate,
    backend: &B,
    pub_key: F,
    verify_app: A,
) -> VerifierResult<bool>
where
    B: PkiBackendTrait,
    F: FnOnce(SignerIdentifier) -> VerifierResult<Option<EcdsaKey>>,
    A: FnOnce(AID) -> Result<(), AID>,
{
    // Retrieve generation time.
    let generation_time = data.generation_time().map_err(VerifierError::SignedData)?;

    // Get signature.
    let signature = data.signature().map_err(VerifierError::SignedData)?;

    // Get signer identifier.
    let signer_id = data
        .signer_identifier()
        .map_err(VerifierError::SignedData)?;

    // Get application identifier.
    let aid = data.application_id().map_err(VerifierError::SignedData)?;

    let signer_pubkey = pub_key(signer_id)?.ok_or(VerifierError::UnknownSigner(signer_id))?;

    // Get content to verify.
    let tbs = data
        .to_be_signed_bytes()
        .map_err(VerifierError::SignedData)?;

    let hash = match signature.hash_algorithm() {
        HashAlgorithm::SHA256 => [backend.sha256(&tbs), backend.sha256(&[])].concat(),
        HashAlgorithm::SHA384 => [backend.sha384(&tbs), backend.sha384(&[])].concat(),
        HashAlgorithm::SM3 => [
            backend.sm3(&tbs).map_err(VerifierError::Backend)?,
            backend.sm3(&[]).map_err(VerifierError::Backend)?,
        ]
        .concat(),
    };

    verify_app(aid).map_err(|expected| VerifierError::InvalidAid {
        expected: expected,
        actual: aid,
    })?;

    /* // Verify AID permission.
    if aid != AID::SCR {
        return Err(MessageError::InvalidAid {
            expected: AID::SCR,
            actual: aid,
        });
    } */

    let signer_permissions = certificate
        .application_permissions()
        .map_err(VerifierError::InvalidCertificate)?;

    let Some(_) = signer_permissions.iter().find(|e| e.aid() == aid) else {
        return Err(VerifierError::InsufficientPermissions);
    };

    // Verify generation time vs cert validity period.
    if !certificate
        .validity_period()
        .contains_instant(generation_time)
    {
        return Err(VerifierError::OffValidityPeriod);
    }

    backend
        .verify_signature(signature, signer_pubkey, &hash)
        .map_err(VerifierError::Backend)
}

/// Signer result type.
pub type SignerResult<T> = core::result::Result<T, SignerError>;

#[derive(Debug)]
/// Error returned by [`sign_data_with_enrollment_key`],
/// [`sign_data_with_canonical_key`] and [`sign_data_with`].
pub enum SignerError {
    /// Signed data error.
    SignedData(SignedDataError),
    /// Backend error.
    Backend(BackendError),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::SignedData(e) => write!(f, "signed data error: {}", e),
            SignerError::Backend(e) => write!(f, "backend error: {}", e),
        }
    }
}

/// Sign `data` which contain the data to be signed, with the enrollment key.
/// Signature is inserted into the provided `data`.
pub fn sign_data_with_enrollment_key<B, T>(
    message: &mut SignedData<T>,
    algorithm: HashAlgorithm,
    backend: &B,
) -> SignerResult<()>
where
    B: PkiBackendTrait,
{
    sign_data_with(message, algorithm, backend, |hash, backend| {
        backend.generate_enrollment_signature(&hash)
    })
}

/// Sign `data` which contain the data to be signed, with the canonical key.
/// Signature is inserted into the provided `data`.
pub fn sign_data_with_canonical_key<B, T>(
    message: &mut SignedData<T>,
    algorithm: HashAlgorithm,
    backend: &B,
) -> SignerResult<()>
where
    B: PkiBackendTrait,
{
    sign_data_with(message, algorithm, backend, |hash, backend| {
        backend.generate_canonical_signature(&hash)
    })
}

/// Sign `data` which contain the data to be signed, with the provided signature `s` function.
pub fn sign_data_with<B, S, T>(
    message: &mut SignedData<T>,
    algorithm: HashAlgorithm,
    backend: &B,
    s: S,
) -> SignerResult<()>
where
    B: PkiBackendTrait,
    S: FnOnce(Vec<u8>, &B) -> BackendResult<EcdsaSignature>,
{
    let tbs = message
        .to_be_signed_bytes()
        .map_err(SignerError::SignedData)?;

    let hash = match algorithm {
        HashAlgorithm::SHA256 => [backend.sha256(&tbs), backend.sha256(&[])].concat(),
        HashAlgorithm::SHA384 => [backend.sha384(&tbs), backend.sha384(&[])].concat(),
        HashAlgorithm::SM3 => [
            backend.sm3(&tbs).map_err(SignerError::Backend)?,
            backend.sm3(&[]).map_err(SignerError::Backend)?,
        ]
        .concat(),
    };

    let signature = s(hash, backend).map_err(SignerError::Backend)?;

    message
        .set_signature(signature)
        .map_err(SignerError::SignedData)?;

    Ok(())
}

/// Encryption result type.
pub type EncryptionResult<T> = core::result::Result<T, EncryptionError>;

/// Error returned by [`encrypt_data`].
#[derive(Debug)]
pub enum EncryptionError {
    /// Certificate error.
    Certificate(CertificateError),
    /// Encrypted wrapper
    Encrypted(EncryptedDataError),
    /// Backend error.
    Backend(BackendError),
    /// No public encryption key available in the certificate.
    NoPublicEncryptionKey,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::Certificate(e) => write!(f, "certificate: {}", e),
            EncryptionError::Encrypted(e) => write!(f, "encrypted: {}", e),
            EncryptionError::Backend(e) => write!(f, "backend: {}", e),
            EncryptionError::NoPublicEncryptionKey => write!(f, "no public encryption key"),
        }
    }
}

/// Encrypt `data` bytes using the provided symmetric `symm_encryption_key`, `certificate`,  and cryptography `backend`.
/// Returns the encrypted data and the ephemeral encryption key pair.
/// The returned [EncryptedData] structure is filled and ready to be serialized.
pub fn encrypt_data<B>(
    data: Vec<u8>,
    symm_encryption_key: &Aes128Key,
    certificate: &CertificateWithHashContainer<impl ExplicitCertificate>,
    backend: &B,
) -> EncryptionResult<(
    EncryptedData,
    KeyPair<B::BackendSecretKey, B::BackendPublicKey>,
)>
where
    B: PkiBackendTrait,
{
    // Generate the nonce associated with the encryption key.
    let nonce = backend
        .generate_random::<12>()
        .map_err(EncryptionError::Backend)?;

    // Encrypt the outer EC Request.
    let encrypted_req = backend
        .encrypt_aes128_ccm(&data, &symm_encryption_key.0, &nonce)
        .map_err(EncryptionError::Backend)?;

    // Encrypt the encryption key.
    let cert_hashed_id8 = certificate.hashed_id8();
    let public_encryption_key = certificate
        .certificate()
        .public_encryption_key()
        .map_err(EncryptionError::Certificate)?
        .ok_or(EncryptionError::NoPublicEncryptionKey)?;

    let key_type = public_encryption_key.key_type();
    let hash_algorithm = public_encryption_key.hash_algorithm();

    let ephemeral_ec_encryption_keypair = backend
        .generate_ephemeral_keypair(key_type)
        .map_err(EncryptionError::Backend)?;

    let peer_public_key =
        B::BackendPublicKey::try_from(public_encryption_key).map_err(EncryptionError::Backend)?;

    // Build the shared secret.
    let shared_secret = backend
        .derive(&ephemeral_ec_encryption_keypair.secret, &peer_public_key)
        .map_err(EncryptionError::Backend)?;

    let cert_hash = certificate.certificate().hash(hash_algorithm, backend);

    let (ke_size, km_size) = match hash_algorithm {
        HashAlgorithm::SHA256 | HashAlgorithm::SM3 => (16, 32),
        HashAlgorithm::SHA384 => (24, 48),
    };

    let ke_km = kdf2(
        &shared_secret,
        &cert_hash,
        ke_size + km_size,
        hash_algorithm,
        backend,
    );

    // Encrypt the encryption key.
    let encrypted_key: Vec<u8> = symm_encryption_key
        .0
        .iter()
        .zip(ke_km[..ke_size].iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // Generate the associated tag.
    let mut tag = backend
        .hmac(hash_algorithm, &ke_km[ke_size..], &encrypted_key)
        .map_err(EncryptionError::Backend)?;

    // Truncate the tag to the correct size.
    tag.truncate(16);

    let ciphertext = Ciphertext::new_aes_128_ccm(nonce.into(), encrypted_req);

    // Get the ephemeral public key into the correct format.
    let ephemeral_public_key = ephemeral_ec_encryption_keypair
        .public
        .clone()
        .try_into()
        .map_err(EncryptionError::Backend)?;

    let enc_key = EncryptedEciesKey::new(ephemeral_public_key, encrypted_key, tag);
    let recipient = RecipientInfo::new_cert(cert_hashed_id8, enc_key);

    Ok((
        EncryptedData::new(ciphertext, vec![recipient]).map_err(EncryptionError::Encrypted)?,
        ephemeral_ec_encryption_keypair,
    ))
}

/// Decryption result type.
pub type DecryptionResult<T> = core::result::Result<T, DecryptionError>;

/// Error returned by [`decrypt_data`].
#[derive(Debug)]
pub enum DecryptionError {
    /// Certificate error.
    Certificate(CertificateError),
    /// Encrypted wrapper
    Encrypted(EncryptedDataError),
    /// Backend error.
    Backend(BackendError),
    /// Recipient id is unknown, the message is not addressed to us.
    UnknownRecipientId(HashedId8),
    /// No public encryption key available in the certificate.
    NoPublicEncryptionKey,
    /// Recipient information choice is unexpected for the message.
    UnexpectedRecipientInformation,
    /// Message encryption tag is invalid.
    InvalidTag,
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptionError::Certificate(e) => write!(f, "certificate: {}", e),
            DecryptionError::Encrypted(e) => write!(f, "encrypted: {}", e),
            DecryptionError::Backend(e) => write!(f, "backend: {}", e),
            DecryptionError::UnknownRecipientId(e) => write!(f, "unknown recipient id: {}", e),
            DecryptionError::NoPublicEncryptionKey => write!(f, "no public encryption key"),
            DecryptionError::UnexpectedRecipientInformation => {
                write!(f, "unexpected recipient information",)
            }
            DecryptionError::InvalidTag => write!(f, "invalid tag"),
        }
    }
}

pub fn decrypt_data_with_key<B>(
    enc_wrapper: &EncryptedData,
    key: &Aes128Key,
    backend: &B,
) -> DecryptionResult<Vec<u8>>
where
    B: PkiBackendTrait,
{
    let ciphertext = enc_wrapper
        .ciphertext()
        .map_err(DecryptionError::Encrypted)?;

    match ciphertext {
        Ciphertext::Aes128Ccm(aes128_inner) => {
            backend.decrypt_aes128_ccm(&aes128_inner.data, &key.0, &aes128_inner.nonce)
        }
    }
    .map_err(DecryptionError::Backend)
}

/* fn decrypt_data<B>(
    enc_wrapper: &EncryptedData,
    symm_encryption_key: &Aes128Key,
    certificate: &CertificateWithHashContainer<impl ExplicitCertificate>,
    ephemeral_ec_encryption_keypair: KeyPair<B::BackendSecretKey, B::BackendPublicKey>,
    backend: &B,
) -> DecryptionResult<Vec<u8>>
where
    B: PkiBackendTrait,
{
    /* // TODO: improve this, ie: check that the number of recipients is one earlier.
    let recipients = enc_wrapper
        .recipients()
        .map_err(DecryptionError::Encrypted)?;

    let recipient = recipients
        .get(0)
        .ok_or(DecryptionError::UnexpectedRecipientInformation)?;

    let pk_recipient = match recipient {
        RecipientInfo::Cert(pkr) => pkr,
        _ => return Err(DecryptionError::UnexpectedRecipientInformation),
    }; */

    // Should be the HashedId8 of the local certificate.
    if pk_recipient.recipient_id != certificate.hashed_id8() {
        return Err(DecryptionError::UnknownRecipientId(
            pk_recipient.recipient_id,
        ));
    }

    // Ephemeral public key.
    let (pk_params, hash_algorithm) = match &pk_recipient.enc_key {
        EncryptedEciesKey::NistP256r1(p) => (p, HashAlgorithm::SHA256),
        EncryptedEciesKey::BrainpoolP256r1(p) => (p, HashAlgorithm::SHA384),
    };

    let public_key = pk_recipient.enc_key.public_key();
    let peer_public_key =
        B::BackendPublicKey::try_from(public_key).map_err(DecryptionError::Backend)?;

    // Reconstruct the shared secret.
    let shared_secret = backend
        .derive_canonical(&peer_public_key)
        .map_err(DecryptionError::Backend)?;

    let cert_hash = certificate.certificate().hash(hash_algorithm, backend);

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
        .map_err(DecryptionError::Backend)?;

    if computed_tag != pk_params.tag {
        return Err(DecryptionError::InvalidTag);
    }

    // Decrypt encryption key.
    let encryption_key: Vec<u8> = pk_params
        .encrypted_key
        .iter()
        .zip(ke_km[..ke_size].iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let ciphertext = enc_wrapper
        .ciphertext()
        .map_err(DecryptionError::Encrypted)?;

    match ciphertext {
        Ciphertext::Aes128Ccm(aes128_inner) => {
            backend.decrypt_aes128_ccm(&aes128_inner.data, &encryption_key, &aes128_inner.nonce)
        }
    }
    .map_err(DecryptionError::Backend)
} */

/// Computes the HashedId8 of the symmetric encryption key.
pub fn symm_encryption_key_hashed_id8<B>(
    encryption_key: &Aes128Key,
    backend: &B,
) -> Asn1WrapperResult<HashedId8>
where
    B: BackendTrait,
{
    let symm_enc_key = SymmetricEncryptionKey::aes128Ccm(FixedOctetString::from(encryption_key.0));
    let encoded = Asn1Wrapper::encode_coer(&symm_enc_key)?;

    let hash = backend.sha256(&encoded);

    Ok(HashedId8::from_bytes(&hash[24..]))
}
