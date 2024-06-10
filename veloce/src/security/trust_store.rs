//! The trust store contains the local chain of trust certificates as well as "remote" trust chains,
//! ie: other PKIs the local station trusts.

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use super::{trust_chain::TrustChain, HashedId8};

pub struct Store {
    /* /// TLM certificate, retrieved from ECTL.
    tlm: TrustListManagerCertificate, */
    /// Station own certificate chain, containing our enrolled PKI certs.
    own_chain: TrustChain,
    /// Other trusted certificate chains, containing other trusted PKI certs.
    /// Map key is the Root Certificate [HashedId8].
    remote_chains: BTreeMap<HashedId8, TrustChain>,
}

impl Store {}
