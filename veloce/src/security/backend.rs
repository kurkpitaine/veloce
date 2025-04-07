use core::fmt;

use super::{signature::EcdsaSignature, EcdsaKey, EciesKey};

#[cfg(feature = "pki")]
use super::{EcKeyType, HashAlgorithm, KeyPair};

#[cfg(feature = "security-openssl")]
pub mod openssl;

#[derive(Debug)]
pub enum BackendError {
    #[cfg(feature = "std")]
    /// IO error, ie: reading/writing a file failed.
    Io(std::io::Error),
    #[cfg(feature = "security-openssl")]
    /// OpenSSL internal error.
    OpenSSL(::openssl::error::ErrorStack),
    /// Key type is not supported by crypto backend.
    UnsupportedKeyType,
    /// Key format is invalid
    InvalidKeyFormat,
    /// No canonical key password is available.
    NoCanonicalKeyPassword,
    /// No canonical key path is available.
    NoCanonicalKeyPath,
    /// No enrollment key path is available.
    NoEnrollmentKeyPath,
    /// No signing certificate secret key is available.
    NoSigningCertSecretKey,
    /// No canonical secret key is available.
    NoCanonicalSecretKey,
    /// No enrollment secret key is available.
    NoEnrollmentSecretKey,
    /// Invalid key.
    InvalidKey,
    /// Hash format is invalid.
    InvalidHashFormat,
    /// Backend internal error.
    InternalError,
    /// Unsupported point compression type.
    UnsupportedCompression,
    /// Point not on curve.
    NotOnCurve,
    /// Signature and key type mismatch.
    AlgorithmMismatch,
    /// Unsupported operation.
    UnsupportedOperation,
    /// Data input is invalid, ie: too short.
    InvalidData,
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::Io(e) => write!(f, "IO error: {}", e),
            #[cfg(feature = "security-openssl")]
            BackendError::OpenSSL(e) => write!(f, "OpenSSL error: {}", e),
            BackendError::UnsupportedKeyType => write!(f, "Unsupported key type"),
            BackendError::InvalidKeyFormat => write!(f, "Invalid key format"),
            BackendError::NoCanonicalKeyPassword => write!(f, "No canonical key password supplied"),
            BackendError::NoCanonicalKeyPath => write!(f, "No canonical key path supplied"),
            BackendError::NoEnrollmentKeyPath => write!(f, "No enrollment key path supplied"),
            BackendError::NoSigningCertSecretKey => write!(f, "No signing certificate secret key"),
            BackendError::NoCanonicalSecretKey => write!(f, "No canonical secret key"),
            BackendError::NoEnrollmentSecretKey => write!(f, "No enrollment secret key"),
            BackendError::InvalidKey => write!(f, "Invalid key"),
            BackendError::InvalidHashFormat => write!(f, "Invalid hash format"),
            BackendError::InternalError => write!(f, "Internal error"),
            BackendError::UnsupportedCompression => write!(f, "Unsupported compression"),
            BackendError::NotOnCurve => write!(f, "Point not on curve"),
            BackendError::AlgorithmMismatch => write!(f, "Signature and key type mismatch"),
            BackendError::UnsupportedOperation => write!(f, "Unsupported operation"),
            BackendError::InvalidData => write!(f, "Invalid data"),
        }
    }
}

pub type BackendResult<T> = Result<T, BackendError>;

/// Cryptography operations backend.
#[derive(Debug)]
pub enum Backend {
    #[cfg(feature = "security-openssl")]
    /// OpenSSL based backend.
    Openssl(openssl::OpensslBackend),
}

impl Backend {
    #[inline]
    pub(super) fn inner(&self) -> &impl BackendTrait {
        match self {
            #[cfg(feature = "security-openssl")]
            Backend::Openssl(backend) => backend,
        }
    }

    #[cfg(feature = "pki")]
    #[inline]
    pub(super) fn inner_pki(&self) -> &impl PkiBackendTrait {
        match self {
            #[cfg(feature = "security-openssl")]
            Backend::Openssl(backend) => backend,
        }
    }

    #[allow(unused)]
    #[inline]
    pub(super) fn inner_mut(&mut self) -> &mut impl BackendTrait {
        match self {
            #[cfg(feature = "security-openssl")]
            Backend::Openssl(backend) => backend,
        }
    }
}

#[allow(unused_variables)]
pub trait BackendTrait {
    /// Verifies `data` slice `signature` with `verification_key`.
    fn verify_signature(
        &self,
        signature: EcdsaSignature,
        verification_key: EcdsaKey,
        data: &[u8],
    ) -> BackendResult<bool>;

    /// Sign the given `data` slice with the current authorization ticket private key.
    fn generate_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature>;

    /// Computes the SHA256 hash for a given `data` slice.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// Computes the SHA384 hash for a given `data` slice.
    fn sha384(&self, data: &[u8]) -> [u8; 48];

    /// Computes the SM4 hash for a given `data` slice.s
    fn sm3(&self, data: &[u8]) -> BackendResult<[u8; 32]>;

    /// Compress an ECIES key coordinates to the Y0 or Y1 format.
    fn compress_ecies_key(&self, key: EciesKey) -> BackendResult<EciesKey>;

    /// Compress an ECDSA key coordinates to the Y0 or Y1 format.
    fn compress_ecdsa_key(&self, key: EcdsaKey) -> BackendResult<EcdsaKey>;
}

#[cfg(feature = "pki")]
pub trait PkiBackendTrait: BackendTrait {
    /// Secret Key type used by the backend.
    type BackendSecretKey;
    /// Public Key type used by the backend.
    type BackendPublicKey: Clone
        + TryFrom<EciesKey, Error = BackendError>
        + TryFrom<EcdsaKey, Error = BackendError>
        + TryInto<EciesKey, Error = BackendError>
        + TryInto<EcdsaKey, Error = BackendError>;

    /// Generate an AES 128 bit key. Due to the sensitive nature of the key, it is STRONGLY
    /// RECOMMENDED to use a cryptographically secure random number generator to generate the key.
    fn generate_aes128_key(&self) -> BackendResult<[u8; 16]>;

    /// Generate random bytes of `N` size.
    fn generate_random<const N: usize>(&self) -> BackendResult<[u8; N]>;

    /// Get the public part of the current canonical key pair, if any.
    fn canonical_pubkey(&self) -> BackendResult<Option<Self::BackendPublicKey>>;

    /// Get the public part of the enrollment key pair, if any.
    fn enrollment_pubkey(&self) -> BackendResult<Option<Self::BackendPublicKey>>;

    /// Generate a new Canonical key pair for a given `key_type`, and return the public key part
    /// of it.
    ///
    /// WARNING: the canonical key pair is VERY sensitive as it is the ITS station "master" key.
    /// Underlying secret key storage is left to the backend, special care should be taken to ensure
    /// secret key stays secret.
    fn generate_canonical_keypair(
        &mut self,
        key_type: EcKeyType,
    ) -> BackendResult<Self::BackendPublicKey>;

    /// Generate a new enrollment key pair for a given `key_type`, and return the public key part
    /// of it.
    ///
    /// WARNING: the enrollment key pair is VERY sensitive as it used by the ITS station to sign
    /// Authorization Tickets requests to the PKI or to re-enroll.
    /// Underlying secret key storage is left to the backend, special care should be taken to ensure
    /// secret key stays secret.
    fn generate_enrollment_keypair(
        &mut self,
        key_type: EcKeyType,
    ) -> BackendResult<Self::BackendPublicKey>;

    /// Generate a new authorization ticket key pair for a given `key_type`, tag it wih the given `id`,
    /// and return the public key part of it.
    ///
    /// Underlying secret key storage is left to the backend, special care should be taken to ensure
    /// secret key stays secret.
    fn generate_authorization_ticket_keypair(
        &mut self,
        key_type: EcKeyType,
        id: u64,
    ) -> BackendResult<Self::BackendPublicKey>;

    /// Generate an EC key pair for a given `key_type`, and return a [KeyPair] containing the
    /// secret and the public key.
    ///
    /// WARNING: This method HAS to be used to build ephemeral keys, DO NOT
    /// USE it for sensitive material such as canonical keys as it leaks the secret key!
    fn generate_ephemeral_keypair(
        &self,
        key_type: EcKeyType,
    ) -> BackendResult<KeyPair<Self::BackendSecretKey, Self::BackendPublicKey>>;

    /// Derive canonical secret `key` with the given `peer` public key.
    fn derive_canonical(&self, peer: &Self::BackendPublicKey) -> BackendResult<Vec<u8>>;

    /// Derive secret `key` with the given `peer` public key.
    fn derive(
        &self,
        key: &Self::BackendSecretKey,
        peer: &Self::BackendPublicKey,
    ) -> BackendResult<Vec<u8>>;

    /// Sign the given `data` slice with the current enrollment credential private key.
    fn generate_enrollment_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature>;

    /// Sign the given `data` slice with the authorization private key at the provided `key_index`.
    fn generate_authorization_signature(
        &self,
        key_index: u64,
        data: &[u8],
    ) -> BackendResult<EcdsaSignature>;

    /// Sign the given `data` slice with the canonical private key.
    fn generate_canonical_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature>;

    /// Encrypt the given 'data' slice as an AES-128-CCM cipher with the provided `key` and `nonce`.
    /// The generated AES tag is appended to the encrypted data.
    fn encrypt_aes128_ccm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> BackendResult<Vec<u8>>;

    /// Decrypt the given 'data' with the provided `key` and `nonce`.
    /// The AES tag is expected to be at the end of the encrypted data.
    fn decrypt_aes128_ccm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> BackendResult<Vec<u8>>;

    /// Computes the HMAC of the given `key` and `data` slice using the provided [HashAlgorithm].
    fn hmac(
        &self,
        hash_algorithm: HashAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> BackendResult<Vec<u8>>;
}
