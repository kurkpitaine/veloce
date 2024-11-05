use core::fmt::{self, Formatter};

use cert_request::CertificateRequestError;

use crate::{time::Instant, types::Pseudonym, wire::EthernetAddress};

use super::{
    backend::BackendError,
    certificate::{CertificateError, ExplicitCertificate},
    certificate_cache::CertificateCache,
    permission::Permission,
    secured_message::SecuredMessageError,
    trust_chain::TrustChain,
    trust_store::Store as TrustStore,
    HashedId8, SecurityBackend,
};

mod cert_request;
pub(crate) mod decap;
pub(crate) mod encap;
pub(crate) mod sign;
pub(crate) mod verify;

#[derive(Debug)]
pub enum SecurityServiceError {
    /// No AT certificate to sign messages.
    NoSigningCertificate,
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
    /// Signer certificate signature is invalid.
    SignerCertificateFalseSignature,
    /// Message is not encrypted.
    UnencryptedMessage,
    /// Message decryption has failed.
    DecryptionError,
    /// Backend error.
    Backend(BackendError),
    /// Certificate Request error.
    /// Used when a secured message contains a certificate request.
    CertificateRequest(CertificateRequestError),
}

impl fmt::Display for SecurityServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SecurityServiceError::NoSigningCertificate => {
                write!(f, "no signing certificate")
            }
            SecurityServiceError::InvalidContent(e) => {
                write!(f, "invalid content: {}", e)
            }
            SecurityServiceError::FalseSignature => write!(f, "false signature"),
            SecurityServiceError::InvalidCertificate(e) => {
                write!(f, "invalid certificate: {}", e)
            }
            SecurityServiceError::RevokedCertificate => write!(f, "revoked certificate"),
            SecurityServiceError::InsufficientPermissions => {
                write!(f, "insufficient permissions")
            }
            SecurityServiceError::InconsistentChain => write!(f, "inconsistent chain"),
            SecurityServiceError::InvalidTimestamp => write!(f, "invalid timestamp"),
            SecurityServiceError::OffValidityPeriod => write!(f, "off validity period"),
            SecurityServiceError::DuplicateMessage => write!(f, "duplicate message"),
            SecurityServiceError::InvalidMobilityData => write!(f, "invalid mobility data"),
            SecurityServiceError::UnsignedMessage => write!(f, "unsigned message"),
            SecurityServiceError::SignerCertificateNotFound => {
                write!(f, "signer certificate not found")
            }
            SecurityServiceError::SignerCertificateFalseSignature => {
                write!(f, "signer certificate false signature")
            }
            SecurityServiceError::UnencryptedMessage => write!(f, "unencrypted message"),
            SecurityServiceError::DecryptionError => write!(f, "decryption error"),
            SecurityServiceError::Backend(e) => write!(f, "backend error: {}", e),
            SecurityServiceError::CertificateRequest(cr) => {
                write!(f, "certificate request error: {}", cr)
            }
        }
    }
}

pub struct SecurityService {
    /// Instant at which to include the full AT certificate in a CAM message signature.
    at_cert_in_cam_at: Instant,
    /// Flag indicating whether the AA certificate should be included in the next CAM message.
    /// [SecurityService::at_cert_in_cam_at] takes precedence over this flag and will delay AA
    /// inclusion to the next transmitted CAM message without the full AT certificate.
    aa_cert_in_cam: bool,
    /// Requested certificates, ie: HashedId8 of certificates we don't have in our cache,
    /// which should be included in the next CAM message.
    p2p_requested_certs: Vec<HashedId8>,
    /// AT Certificates cache.
    cache: CertificateCache,
    /// Trust store for chain of trust.
    store: TrustStore,
    /// Cryptography backend.
    backend: SecurityBackend,
}

impl fmt::Debug for SecurityService {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityService")
            .field("at_cert_in_cam_at", &self.at_cert_in_cam_at)
            .field("aa_cert_in_cam", &self.aa_cert_in_cam)
            .field("cache", &self.cache)
            .field("store", &self.store)
            .finish()
    }
}

impl SecurityService {
    /// Constructs a [SecurityService].
    pub fn new(own_chain: TrustChain, backend: SecurityBackend) -> Self {
        Self {
            at_cert_in_cam_at: Instant::ZERO,
            aa_cert_in_cam: false,
            p2p_requested_certs: Vec::new(),
            cache: CertificateCache::new(),
            store: TrustStore::new(own_chain),
            backend,
        }
    }

    /// Get a mutable reference to the [TrustStore].
    pub fn store_mut(&mut self) -> &mut TrustStore {
        &mut self.store
    }

    /// Get the application permissions contained in the AT certificate used to sign the messages.
    pub fn application_permissions(&self) -> Result<Vec<Permission>, SecurityServiceError> {
        self.store
            .own_chain()
            .at_cert()
            .as_ref()
            .ok_or(SecurityServiceError::NoSigningCertificate)
            .and_then(|at| {
                at.certificate()
                    .application_permissions()
                    .map_err(SecurityServiceError::InvalidCertificate)
            })
    }

    /// Get the pseudonym of the local station.
    /// Pseudonym is derived from the AT certificate.
    pub fn pseudonym(&self) -> Result<Pseudonym, SecurityServiceError> {
        self.store
            .own_chain()
            .at_cert()
            .as_ref()
            .map(|at| Pseudonym(at.hashed_id8().as_u64() as u32))
            .ok_or(SecurityServiceError::NoSigningCertificate)
    }

    /// Get the hardware address of the local station.
    /// Hardware address is derived from the AT certificate.
    pub fn hardware_address(&self) -> Result<EthernetAddress, SecurityServiceError> {
        self.store
            .own_chain()
            .at_cert()
            .as_ref()
            .map(|at| {
                let mut addr_bytes = at.hashed_id8().as_bytes();
                // Clear multicast and locally administered bits.
                addr_bytes[0] &= !0x03;

                EthernetAddress::from_bytes(&addr_bytes[..6])
            })
            .ok_or(SecurityServiceError::NoSigningCertificate)
    }
}
