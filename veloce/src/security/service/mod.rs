use crate::time::Instant;

use super::{
    backend::Backend, certificate::CertificateError, certificate_cache::CertificateCache,
    secured_message::SecuredMessageError, trust_chain::TrustChain,
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
    InvalidCertificate(CertificateError),
    /// Certificate is revoked.
    RevokedCertificate,
    /// Certificate has insufficient permissions to sign the secured message.
    InsufficientPermissions,
    /// Certificate chain is inconsistent.
    InconsistentChain,
    /// Timestamp (generation time) is invalid.
    InvalidTimestamp,
    /// Timestamp (generation time) is outside signer certificate validity period.
    OffValidityPeriod,
    /// Message is a duplicate.
    DuplicateMessage,
    /// Message contains invalid mobility data.
    InvalidMobilityData,
    /// Message has no signature.
    UnsignedMessage,
    /// Signer certificate not found, ie: AT certificate is not present
    /// in local cache.
    SignerCertificateNotFound,
    /// Message is not encrypted.
    UnencryptedMessage,
    /// Message decryption has failed.
    DecryptionError,
    /// Backend error.
    Backend,
}

pub struct SecurityService<'a> {
    /// Instant at which to include the certificate in a CAM message signature.
    next_cert_in_cam_at: Instant,
    /// AT Certificates cache.
    cache: CertificateCache,
    /// Trust store for chain of trust.
    store: TrustStore,
    /// Cryptography backend.
    backend: &'a dyn Backend,
}

impl<'a> SecurityService<'a> {
    /// Constructs a [SecurityService].
    pub fn new(own_chain: TrustChain, backend: &'a impl Backend) -> Self {
        Self {
            next_cert_in_cam_at: Instant::ZERO,
            cache: CertificateCache::new(),
            store: TrustStore::new(own_chain),
            backend,
        }
    }
}
