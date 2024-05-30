//! The trust store contains the local chain of trust certificates as well as "remote" trust chains,
//! ie: other PKIs the local station trusts.
//! `std` environments provides the ability to load certs directly from the filesystem.
//! On `#[no_std]` targets, certificates should be set with the certs setter methods.

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use super::{
    certificate::{HashedId8, TrustListManagerCertificate},
    trust_chain::TrustChain,
};

#[derive(Debug, PartialEq, Eq)]
pub enum CertificateType {
    /// Root certificate type.
    Root,
    /// EA certificate type.
    EnrollmentAuthority,
    /// AA certificate type.
    AuthorizationAuthority,
    /// AT certificate type.
    AuthorizationTicket,
    /// EC certificate type.
    EnrollmentCredential,
    /// TLM certificate type.
    TrustedListManager,
}

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
}
