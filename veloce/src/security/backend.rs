use core::fmt;

use crate::security::{EcdsaKeyType, KeyPair, PublicKey};

use super::{signature::EcdsaSignature, EcdsaKey, EciesKey};

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
    /// No signing certificate secret key is available.
    NoSigningCertSecretKey,
    /// Invalid key.
    InvalidKey,
    /// Backend internal error.
    InternalError,
    /// Unsupported point compression type.
    UnsupportedCompression,
    /// Point not on curve.
    NotOnCurve,
    /// Signature and key type mismatch.
    AlgorithmMismatch,
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::Io(e) => write!(f, "IO error: {}", e),
            #[cfg(feature = "security-openssl")]
            BackendError::OpenSSL(e) => write!(f, "OpenSSL error: {}", e),
            BackendError::UnsupportedKeyType => write!(f, "Unsupported key type"),
            BackendError::InvalidKeyFormat => write!(f, "Invalid key format"),
            BackendError::NoSigningCertSecretKey => write!(f, "No signing certificate secret key"),
            BackendError::InvalidKey => write!(f, "Invalid key"),
            BackendError::InternalError => write!(f, "Internal error"),
            BackendError::UnsupportedCompression => write!(f, "Unsupported compression"),
            BackendError::NotOnCurve => write!(f, "Point not on curve"),
            BackendError::AlgorithmMismatch => write!(f, "Signature and key type mismatch"),
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
    pub(super) fn inner(&self) -> &dyn BackendTrait {
        match self {
            #[cfg(feature = "security-openssl")]
            Backend::Openssl(backend) => backend,
        }
    }

    #[allow(unused)]
    #[inline]
    pub(super) fn inner_mut(&mut self) -> &mut dyn BackendTrait {
        match self {
            #[cfg(feature = "security-openssl")]
            Backend::Openssl(backend) => backend,
        }
    }
}

#[allow(unused_variables)]
pub trait BackendTrait {
    /// Generate a key pair for a given `key_type`, and return a [KeyPair] containing the
    /// secret and the public key.
    ///
    /// WARNING: This method HAS to be used to build ephemeral keys, DO NOT
    /// USE it for sensitive material such as canonical keys as it leaks the [SecretKey]!
    fn generate_keypair(&self, key_type: EcdsaKeyType) -> BackendResult<KeyPair>;

    /// Generate a new Canonical key pair for a given `key_type`, and return the [PublicKey] part
    /// of it.
    ///
    /// WARNING: the canonical key pair is VERY sensitive as it is the ITS station "master" key.
    /// Underlying secret key storage is left to the backend, special care should be taken to ensure
    /// secret key stays secret.
    fn generate_canonical_keypair(&self, key_type: EcdsaKeyType) -> BackendResult<PublicKey>;

    /// Verifies `data` slice `signature` with `verification_key`.
    fn verify_signature(
        &self,
        signature: EcdsaSignature,
        verification_key: EcdsaKey,
        data: &[u8],
    ) -> BackendResult<bool>;

    /// Sign the given `data` slice.
    fn generate_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature>;

    /// Computes the SHA256 hash for a given `data` slice.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// Computes the SHA384 hash for a given `data` slice.
    fn sha384(&self, data: &[u8]) -> [u8; 48];

    /// Compress an ECIES key coordinates to the Y0 or Y1 format.
    fn compress_ecies_key(&self, key: EciesKey) -> BackendResult<EciesKey>;

    /// Compress an ECDSA key coordinates to the Y0 or Y1 format.
    fn compress_ecdsa_key(&self, key: EcdsaKey) -> BackendResult<EcdsaKey>;
}
