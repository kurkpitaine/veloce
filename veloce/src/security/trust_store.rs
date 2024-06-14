//! The trust store contains the local chain of trust certificates as well as "remote" trust chains,
//! ie: other PKIs the local station trusts.

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use super::{certificate::AuthorizationAuthorityCertificate, trust_chain::TrustChain, HashedId8};

pub struct Store {
    /* /// TLM certificate, retrieved from ECTL.
    tlm: TrustListManagerCertificate, */
    /// Station own certificate chain, containing our enrolled PKI certs.
    own_chain: TrustChain,
    /// Other trusted certificate chains, containing other trusted PKI certs.
    /// Map key is the Root Certificate [HashedId8].
    remote_chains: BTreeMap<HashedId8, TrustChain>,
}

impl Store {
    /// Check the certificate identified with `hash` is known as revoked
    /// across any known trust chain.
    pub fn is_revoked(&self, _hash: HashedId8) -> bool {
        false
    }

    /// Lookup into the own and the remote chains for an [AuthorizationAuthorityCertificate]
    /// identified with `hash`.
    pub fn lookup_aa(&self, _hash: HashedId8) -> Option<AuthorizationAuthorityCertificate> {
        None
    }
}
