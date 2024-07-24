//! Certificate cache stores received AT and PCA certificates
//! in a map using the certificate HashedId8 (or digest) as the key.

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use crate::config::SEC_CERT_CACHE_ENTRY_LIFETIME;
use crate::time::Instant;

use super::certificate::AuthorizationTicketCertificate;
use super::HashedId8;

/// A cached certificate.
///
/// A certificate mapping translates from a HashedId8 digest to a complete certificate,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CachedCertificate {
    /// Complete certificate.
    certificate: AuthorizationTicketCertificate,
    /// Expiration time.
    expires_at: Instant,
}

#[derive(Debug)]
pub struct CertificateCache {
    storage: BTreeMap<HashedId8, CachedCertificate>,
}

impl CertificateCache {
    /// Create a Certificate Cache.
    pub const fn new() -> Self {
        Self {
            storage: BTreeMap::new(),
        }
    }

    pub fn fill(
        &mut self,
        digest: HashedId8,
        certificate: AuthorizationTicketCertificate,
        timestamp: Instant,
    ) {
        let expires_at = timestamp + SEC_CERT_CACHE_ENTRY_LIFETIME;

        let cached_cert = CachedCertificate {
            certificate,
            expires_at,
        };

        // Evict expired mappings.
        self.storage.retain(|k, v| {
            let keep = v.expires_at > timestamp;

            if !keep {
                net_trace!("evict HashedId [{}]", k);
            }

            keep
        });

        match self.storage.insert(digest, cached_cert) {
            Some(old) => {
                net_trace!(
                    "updated HashedId [{}] expiration {} => {}",
                    digest,
                    old.expires_at,
                    expires_at
                );
            }
            None => net_trace!("filled HashedId [{}] (was empty)", digest),
        }
    }

    /// Search the certificate cache for a certificate identified
    /// with `digest`. Returns an option containing the certificate, if any.
    pub(crate) fn lookup(
        &self,
        digest: &HashedId8,
        timestamp: Instant,
    ) -> Option<AuthorizationTicketCertificate> {
        self.storage.get(digest).and_then(|e| {
            if e.expires_at > timestamp {
                Some(e.certificate.to_owned())
            } else {
                None
            }
        })
    }

    /// Removes all the entries of the Certificate Cache.
    #[allow(unused)]
    pub fn clear(&mut self) {
        self.storage.clear();
    }
}
