#[cfg(not(feature = "std"))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use core::fmt::{self, Formatter};

use cert_request::CertificateRequestError;

use crate::{
    common::PotiFix,
    security::{
        certificate::CertificateTrait,
        privacy::{PrivacyController, PrivacyStrategy},
    },
    time::Instant,
    types::Pseudonym,
    wire::EthernetAddress,
};

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

/// Events emitted by the security module when calling [SecurityService::poll].
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollEvent {
    /// Security module has changed signing certificate because of privacy strategy.
    /// Contains the elected AT certificate index and [HashedId8].
    PrivacyATCertificateRotation(usize, HashedId8),
    /// Security module has changed signing certificate because of AT certificate expiration.
    /// Contains the elected AT certificate index and [HashedId8].
    ATCertificateExpiration(usize, HashedId8),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    /// Privacy controller for certificate rotation.
    privacy: PrivacyController,
    /// Last AT certificate election result.
    last_at_election_successful: bool,
}

impl fmt::Debug for SecurityService {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityService")
            .field("at_cert_in_cam_at", &self.at_cert_in_cam_at)
            .field("aa_cert_in_cam", &self.aa_cert_in_cam)
            .field("cache", &self.cache)
            .field("store", &self.store)
            .field("privacy", &self.privacy)
            .finish()
    }
}

impl SecurityService {
    /// Constructs a [SecurityService].
    pub fn new(own_chain: TrustChain, backend: SecurityBackend, privacy: PrivacyStrategy) -> Self {
        Self {
            at_cert_in_cam_at: Instant::ZERO,
            aa_cert_in_cam: false,
            p2p_requested_certs: Vec::new(),
            cache: CertificateCache::new(),
            store: TrustStore::new(own_chain),
            backend,
            privacy: PrivacyController::new(privacy),
            last_at_election_successful: false,
        }
    }

    /// Get a reference to the [TrustStore].
    pub fn store(&self) -> &TrustStore {
        &self.store
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
            .ok_or(SecurityServiceError::NoSigningCertificate)
            .and_then(|at| {
                at.at_container()
                    .certificate()
                    .application_permissions()
                    .map_err(SecurityServiceError::InvalidCertificate)
            })
    }

    /// Get the [HashedId8] of the current AT certificate.
    pub fn at_hashed_id8(&self) -> Result<HashedId8, SecurityServiceError> {
        self.store
            .own_chain()
            .at_cert()
            .map(|at| at.at_container().hashed_id8())
            .ok_or(SecurityServiceError::NoSigningCertificate)
    }

    /// Get the pseudonym of the local station.
    /// Pseudonym is derived from the AT certificate.
    pub fn pseudonym(&self) -> Result<Pseudonym, SecurityServiceError> {
        self.store
            .own_chain()
            .at_cert()
            .map(|at| Pseudonym(at.at_container().hashed_id8().as_u64() as u32))
            .ok_or(SecurityServiceError::NoSigningCertificate)
    }

    /// Get the hardware address of the local station.
    /// Hardware address is derived from the AT certificate.
    pub fn hardware_address(&self) -> Result<EthernetAddress, SecurityServiceError> {
        self.store
            .own_chain()
            .at_cert()
            .map(|at| {
                let mut addr_bytes = at.at_container().hashed_id8().as_bytes();
                // Clear multicast and locally administered bits.
                addr_bytes[0] &= !0x03;

                EthernetAddress::from_bytes(&addr_bytes[..6])
            })
            .ok_or(SecurityServiceError::NoSigningCertificate)
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    pub fn poll_at(&self) -> Option<Instant> {
        self.privacy.inner().run_at()
    }

    /// Poll the Security Service for internal processing.
    /// In details, it checks if the current AT is still valid in time and
    /// runs the privacy strategy internal state machine. It also changes
    /// the signature private key + AT certificate if needed.
    pub fn poll(&mut self, timestamp: Instant) -> Option<PollEvent> {
        let at_expired = self.store.own_chain().at_cert().is_some_and(|c| {
            c.at_container()
                .certificate()
                .validity_period()
                .end()
                .as_unix_instant()
                <= timestamp
        });

        if self.privacy.inner_mut().run(timestamp) {
            self.elect_at_cert(timestamp)
                .map(|(i, h)| PollEvent::PrivacyATCertificateRotation(i, h))
        } else if at_expired && self.last_at_election_successful {
            // We test if the AT certificate election was successful, to avoid looping if we have no
            // candidate AT certificate left.
            self.elect_at_cert(timestamp).map(|(i, h)| {
                // Reset the privacy strategy state machine to indicate an AT certificate
                // change has been triggered.
                self.privacy.inner_mut().reset(timestamp);
                PollEvent::ATCertificateExpiration(i, h)
            })
        } else {
            None
        }
    }

    /// Notify the Security Service about a newly acquired GNSS position.
    pub fn notify_position(&mut self, position: PotiFix, timestamp: Instant) {
        self.privacy
            .inner_mut()
            .notify_position(position, timestamp);
    }

    /// Elects next AT certificate used to sign messages.
    /// Returns an option containing the AT certificate index along its [HashedId8] if the AT certificate has been changed.
    pub fn elect_at_cert(&mut self, timestamp: Instant) -> Option<(usize, HashedId8)> {
        let res = match self.find_candidate_at_cert(timestamp) {
            Some((index, h)) => self
                .backend
                .inner_mut()
                .set_at_key_index(index)
                .inspect_err(|e| net_error!("Unable to set AT secret key in the backend: {}", e))
                .is_ok_and(|_| {
                    self.store
                        .own_chain_mut()
                        .set_at_cert_index(index)
                        .inspect_err(|e| {
                            net_error!("Unable to set AT certificate in the trust chain: {}", e)
                        })
                        .is_ok()
                })
                .then_some((index, h)),
            None => {
                net_warn!("No candidate AT certificate available");
                None
            }
        };

        self.last_at_election_successful = res.is_some();
        res
    }

    /// Get the AT certificates elections statistics.
    pub fn at_certs_stats(&self) -> BTreeMap<usize, usize> {
        self.store
            .own_chain()
            .at_certs()
            .iter()
            .map(|(i, at)| (*i, at.elected()))
            .collect()
    }

    /// Get the next AT certificate used to sign messages, if any.
    fn find_candidate_at_cert(&self, timestamp: Instant) -> Option<(usize, HashedId8)> {
        let available_keys = self.backend.inner().available_at_keys().inspect_err(|e|
            net_error!("Unable to find a candidate AT certificate: failure listing available AT key indexes: {}", e)
        ).ok()?;

        // We filter certificates with no matching key, expired certificates
        // and return the one with the lowest number of elections.
        self.store
            .own_chain()
            .at_certs()
            .iter()
            .filter(|c| available_keys.iter().any(|e| e.0 == *c.0))
            .filter(|c| {
                c.1.at_container()
                    .certificate()
                    .validity_period()
                    .end()
                    .as_unix_instant()
                    > timestamp
            })
            .min_by_key(|c| c.1.elected())
            .map(|c| (*c.0, c.1.at_container().hashed_id8()))
    }
}
