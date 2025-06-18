use core::fmt;
use std::{collections::BTreeMap, rc::Rc};

use log::{error, info, warn};
use veloce::{
    network::core::SecurityConfig as RouterSecurityConfig,
    security::{
        ATContainer, DirectoryStorage, EcdsaKey, SecurityBackend, SecurityStorageMetadata,
        TrustChain,
        backend::{BackendError, BackendTrait, PkiBackendTrait},
        certificate::{
            AuthorizationAuthorityCertificate, AuthorizationTicketCertificate, CertificateError,
            CertificateWithHashContainer, EnrollmentAuthorityCertificate,
            EnrollmentCredentialCertificate, ExplicitCertificate, RootCertificate,
        },
        storage::{StorageError, StorageTrait},
    },
    time::Instant,
};

use crate::{config::Config, utils};

pub type SecurityResult<T> = core::result::Result<T, SecurityError>;

#[derive(Debug)]
pub enum SecurityError {
    /// Failed to list available AT key indexes.
    AvailableAtKeyIndexes(BackendError),
    /// Failed to load certificate.
    CertificateLoad(StorageError),
    /// Certificate format error.
    Certificate(CertificateError),
    /// Failed to check certificate.
    CertificateCheck(CertificateError),
    /// Cannot compute certificate hash.
    CertificateHash(CertificateError),
    /// Certificate false signature.
    FalseSignature,
    /// Crypto or storage backend error.
    CryptoStorage(utils::UtilError),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::AvailableAtKeyIndexes(e) => {
                write!(f, "error while listing available AT key indexes: {e}")
            }
            SecurityError::CertificateLoad(e) => write!(f, "cannot load certificate: {e}"),
            SecurityError::Certificate(e) => write!(f, "failed to parse certificate: {e}"),
            SecurityError::CertificateCheck(e) => write!(f, "failed to check certificate: {e}"),
            SecurityError::CertificateHash(e) => write!(f, "cannot compute certificate hash: {e}"),
            SecurityError::FalseSignature => write!(f, "false signature"),
            SecurityError::CryptoStorage(e) => write!(f, "failed to setup storage and crypto: {e}"),
        }
    }
}

/// Setup the security service if enabled in the configuration.
/// This method instantiates the [SecurityBackend] and the [TrustChain] from the [DirectoryStorage].
/// Returns the [RouterSecurityConfig] if security is enabled, None otherwise.
pub fn setup_security(
    config: &Config,
) -> SecurityResult<Option<(RouterSecurityConfig, Rc<DirectoryStorage>, SecurityStorageMetadata)>> {
    let res = if config.security.enable {
        info!("Setting up crypto and secure storage");
        let (backend, storage) = utils::setup_openssl_and_directory_storage(config)
            .map_err(SecurityError::CryptoStorage)?;

        info!("Loading certificates and setting up the trust chain");
        let (trust_chain, meta) = setup_trust_chain(storage.as_ref(), &backend)?;

        let security_config = RouterSecurityConfig {
            security_backend: SecurityBackend::Openssl(backend),
            own_trust_chain: trust_chain,
            privacy_strategy: config.security.privacy_strategy,
        };

        Some((security_config, storage, meta))
    } else {
        None
    };

    Ok(res)
}

/// Setup the trust chain from the storage.
/// This function will load the root certificate, the AA certificate if any, the EA certificate if any, the EC certificate if any
/// and the AT certificates if any.
/// For all certificates types above, signature verification is performed.
/// For AT and EC certificates, matching of the embedded public verification key with the public verification key returned
/// by the crypto backend is performed.
pub(crate) fn setup_trust_chain<B: PkiBackendTrait, S: StorageTrait>(
    storage: &S,
    backend: &B,
) -> SecurityResult<(TrustChain, SecurityStorageMetadata)> {
    let timestamp = Instant::now();

    let mut at_metadata = storage.load_metadata().unwrap_or_default();

    let root_cert = load_root_cert(storage, timestamp, backend).inspect_err(|e| {
        error!("Failed to load root certificate: {}", e);
    })?;

    let maybe_ea_cert = load_ea_cert(storage, root_cert.clone(), timestamp, backend)
        .inspect_err(|e| {
            warn!("Failed to load EA certificate: {}", e);
        })
        .ok();

    let maybe_aa_cert = load_aa_cert(storage, root_cert.clone(), timestamp, backend)
        .inspect_err(|e| {
            warn!("Failed to load AA certificate: {}", e);
        })
        .ok();

    let at_certs = maybe_aa_cert.as_ref().map_or_else(|| {
        warn!("Cannot load AT certificates: no AA certificate");
        BTreeMap::new()
    }, |aa_cert| {
        backend.available_at_keys()
            .map_or_else(|e| {
                error!("error while listing available AT key indexes: {e}");
                BTreeMap::new()
            }, |indexes| {
                indexes.iter()
                .filter_map(|(i, pk)| {
                    load_at_cert(*i, storage, aa_cert.clone(), timestamp, backend)
                        .map_or_else(|e| {
                            warn!("Failed to load AT certificate with index {}: {}", i, e);
                            None
                        }, |c| match c.certificate().public_verification_key() {
                            Ok(cert_pk) if cert_pk == *pk => Some(c),
                            Ok(cert_pk) => {
                                error!("Unexpected public verification key in AT certificate with index {}. Expected {:?} - Got {:?}", i, pk, cert_pk);
                                None
                            },
                            Err(e) => {
                                error!("Cannot fetch public verification key of AT certificate with index {}: {}", i, e);
                                None
                            },
                        })
                        .map(|c| {
                            let elected = at_metadata.elections_stats(*i).unwrap_or_else(||{
                                at_metadata.set_elections_stats(*i, 0);
                                0
                            });
                            let container = ATContainer::new(c, elected);
                            (*i, container)
                        })
                 })
                .collect()
            })
        });

    let maybe_ec_cert = maybe_ea_cert.as_ref().map_or_else(|| {
        warn!("Cannot load EC certificate: no EA certificate");
        None
    }, |ea_cert| {
        backend.enrollment_pubkey().map_or_else(|e| {
            error!("error while fetching EC certificate public key: {}", e);
            None
        }, |maybe_bpk| {
            maybe_bpk.map_or_else(|| {
                warn!("Cannot load EC certificate: no enrollment key available");
                None
            }, |bpk| {
                let pk: EcdsaKey = bpk.try_into().inspect_err(|e| {
                    error!("error while converting EC certificate public key from backend: {}", e);
                }).ok()?;

                load_ec_cert(storage, ea_cert.clone(), timestamp, backend).map_or_else(|e| {
                    warn!("Failed to load EC certificate: {}", e);
                    None
                },
             |ec_cert| match ec_cert.certificate().public_verification_key() {
                    Ok(cert_pk) if cert_pk == pk => Some(ec_cert),
                    Ok(cert_pk) => {
                        error!("Unexpected public verification key in EC certificate. Expected {:?} - Got {:?}", pk, cert_pk);
                        None
                    },
                    Err(e) => {
                        error!("Cannot fetch public verification key of EC certificate: {}", e);
                        None
                    },
                })
            })
        })
    });

    // Store the AT certificate election statistics.
    storage
        .store_metadata(at_metadata.clone())
        .inspect_err(|e| {
            error!("Cannot store AT certificates metadata: {}", e);
        })
        .ok();

    let mut trust_chain = TrustChain::new(root_cert);
    if let Some(aa_cert) = maybe_aa_cert {
        trust_chain.set_aa_cert(aa_cert);
    }

    if let Some(ea_cert) = maybe_ea_cert {
        trust_chain.set_ea_cert(ea_cert);
    }

    if let Some(ec_cert) = maybe_ec_cert {
        trust_chain.set_ec_cert(ec_cert);
    }

    trust_chain.set_at_certs(at_certs);

    Ok((trust_chain, at_metadata))
}

/// Load the root certificate from the storage.
fn load_root_cert<B: BackendTrait + ?Sized, S: StorageTrait>(
    storage: &S,
    timestamp: Instant,
    backend: &B,
) -> SecurityResult<CertificateWithHashContainer<RootCertificate>> {
    let root_cert_bytes = storage
        .load_root_certificate()
        .map_err(SecurityError::CertificateLoad)?;

    load_and_check_cert::<B, _, RootCertificate>(root_cert_bytes, timestamp, None, backend)
}

/// Load the AA certificate from the storage.
fn load_aa_cert<B: BackendTrait + ?Sized, S: StorageTrait>(
    storage: &S,
    root_cert: CertificateWithHashContainer<RootCertificate>,
    timestamp: Instant,
    backend: &B,
) -> SecurityResult<CertificateWithHashContainer<AuthorizationAuthorityCertificate>> {
    let aa_cert_bytes = storage
        .load_aa_certificate()
        .map_err(SecurityError::CertificateLoad)?;

    load_and_check_cert::<B, _, _>(aa_cert_bytes, timestamp, Some(root_cert), backend)
}

/// Load the EA certificate from the storage.
fn load_ea_cert<B: BackendTrait + ?Sized, S: StorageTrait>(
    storage: &S,
    root_cert: CertificateWithHashContainer<RootCertificate>,
    timestamp: Instant,
    backend: &B,
) -> SecurityResult<CertificateWithHashContainer<EnrollmentAuthorityCertificate>> {
    let ea_cert_bytes = storage
        .load_ea_certificate()
        .map_err(SecurityError::CertificateLoad)?;

    load_and_check_cert::<B, _, _>(ea_cert_bytes, timestamp, Some(root_cert), backend)
}

/// Load the EC certificate from the storage.
fn load_ec_cert<B: BackendTrait + ?Sized, S: StorageTrait>(
    storage: &S,
    ea_cert: CertificateWithHashContainer<EnrollmentAuthorityCertificate>,
    timestamp: Instant,
    backend: &B,
) -> SecurityResult<CertificateWithHashContainer<EnrollmentCredentialCertificate>> {
    let ec_cert_bytes = storage
        .load_ec_certificate()
        .map_err(SecurityError::CertificateLoad)?;

    load_and_check_cert::<B, _, _>(ec_cert_bytes, timestamp, Some(ea_cert), backend)
}

/// Load the AT certificate from the storage.
fn load_at_cert<B: BackendTrait + ?Sized, S: StorageTrait>(
    index: usize,
    storage: &S,
    aa_cert: CertificateWithHashContainer<AuthorizationAuthorityCertificate>,
    timestamp: Instant,
    backend: &B,
) -> SecurityResult<CertificateWithHashContainer<AuthorizationTicketCertificate>> {
    let ec_cert_bytes = storage
        .load_at_certificate(index)
        .map_err(SecurityError::CertificateLoad)?;

    load_and_check_cert::<B, _, _>(ec_cert_bytes, timestamp, Some(aa_cert), backend)
}

fn load_and_check_cert<
    B: BackendTrait + ?Sized,
    C: ExplicitCertificate<CertificateType = C>,
    SIGNER: ExplicitCertificate + Clone,
>(
    cert_bytes: Vec<u8>,
    timestamp: Instant,
    signer: Option<CertificateWithHashContainer<SIGNER>>,
    backend: &B,
) -> SecurityResult<CertificateWithHashContainer<C>> {
    let cert = C::from_bytes(&cert_bytes, backend).map_err(SecurityError::Certificate)?;

    let valid = cert
        .check(timestamp, backend, |h| {
            signer.and_then(|signer| {
                if signer.hashed_id8() == h {
                    Some(signer.into_certificate())
                } else {
                    None
                }
            })
        })
        .map_err(SecurityError::CertificateCheck)?;

    if !valid {
        return Err(SecurityError::FalseSignature);
    }

    cert.into_with_hash_container(backend)
        .map_err(SecurityError::CertificateHash)
}
