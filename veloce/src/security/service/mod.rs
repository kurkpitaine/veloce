use crate::time::Instant;

use super::{
    backend::Backend, certificate_cache::CertificateCache, secured_message::SecuredMessageError,
    trust_store::Store as TrustStore,
};

pub(crate) mod decap;
pub(crate) mod encap;
pub(crate) mod sign;
pub(crate) mod verify;

#[derive(Debug)]
pub enum SecurityServiceError {
    /// Security envelope has invalid content.
    InvalidContent(SecuredMessageError),

    /// Signature is invalid.
    FalseSignature,
    /// Certificate is invalid.
    InvalidCertificate,
    /// Certificate is revoked.
    RevokedCertificate,
    /// Certificate chain is inconsistent.
    InconsistentChain,
    /// Timestamp (generation time) is invalid.
    InvalidTimestamp,
    /// Message is a duplicate.
    DuplicateMessage,
    /// Message contains invalid mobility data.
    InvalidMobilityData,
    /// Message has no signature.
    UnsignedMessage,
    /// Signer certificate not found, ie: certificate is not present
    /// in local cache.
    SignerCertificateNotFound,
    /// Message is not encrypted.
    UnencryptedMessage,
    /// Message decryption has failed.
    DecryptionError,
}

pub struct SecurityService {
    /// Instant at which to include the certificate in a CAM message signature.
    next_cert_in_cam_at: Instant,
    /// AT Certificates cache.
    cache: CertificateCache,
    /// Trust store for chain of trust.
    store: TrustStore,
    /// Cryptography backend.
    backend: dyn Backend,
}

impl SecurityService {}
