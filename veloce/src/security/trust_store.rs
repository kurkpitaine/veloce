//! The trust store contains the local chain of trust certificates as well as "remote" trust chains,
//! ie: other PKIs the local station trusts.

#[cfg(not(feature = "std"))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use super::{
    certificate::{
        AuthorizationAuthorityCertificate, CertificateWithHashContainer, RootCertificate,
    },
    trust_chain::TrustChain,
    HashedId8,
};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Error returned by [`Store::set_remote_aa`].
pub struct InexistentChainError;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Store {
    /// Station own certificate chain, containing our enrolled PKI certs.
    own_chain: TrustChain,
    /// Other trusted certificate chains, containing other trusted PKI certs.
    /// Map key is the Root Certificate [HashedId8].
    remote_chains: BTreeMap<HashedId8, TrustChain>,
}

impl Store {
    /// Constructs a [Store] with the local trust chain `own_chain`.
    pub fn new(own_chain: TrustChain) -> Self {
        Self {
            own_chain,
            remote_chains: BTreeMap::new(),
        }
    }

    /// Get a reference to the own certificate chain.
    pub fn own_chain(&self) -> &TrustChain {
        &self.own_chain
    }

    /// Get a mutable reference to the own certificate chain.
    pub fn own_chain_mut(&mut self) -> &mut TrustChain {
        &mut self.own_chain
    }

    /// Query whether the certificate identifier `hash` is in the revoked
    /// certificates list of any trust chain.
    pub fn is_revoked(&self, hash: HashedId8) -> bool {
        if self.own_chain.is_revoked(hash) {
            return true;
        }

        self.remote_chains
            .iter()
            .any(|(_, chain)| chain.is_revoked(hash))
    }

    /// Lookup into the own and the remote chains for a [RootCertificate]
    /// identified with `hash`.
    pub fn lookup_root(&self, hash: HashedId8) -> Option<RootCertificate> {
        if self.own_chain.root_cert().hashed_id8() == hash {
            return Some(self.own_chain.root_cert().certificate().clone());
        }

        self.remote_chains
            .get(&hash)
            .map(|e| e.root_cert().certificate().clone())
    }

    /// Lookup into the own and the remote chains for an [AuthorizationAuthorityCertificate]
    /// identified with `hash`.
    pub fn lookup_aa(&self, hash: HashedId8) -> Option<AuthorizationAuthorityCertificate> {
        match self.own_chain.aa_cert() {
            Some(own_aa) if own_aa.hashed_id8() == hash => {
                return Some(own_aa.certificate().clone())
            }
            _ => {}
        }

        self.remote_chains
            .iter()
            .find_map(|(_, chain)| match chain.aa_cert() {
                Some(aa) if aa.hashed_id8() == hash => Some(aa.certificate().clone()),
                _ => None,
            });

        None
    }

    /// Set the [AuthorizationAuthorityCertificate] for the remote chain identified with `hash`.
    pub fn set_remote_aa(
        &mut self,
        hash: HashedId8,
        cert: CertificateWithHashContainer<AuthorizationAuthorityCertificate>,
    ) -> Result<(), InexistentChainError> {
        self.remote_chains
            .get_mut(&hash)
            .ok_or(InexistentChainError)?
            .set_aa_cert(cert);

        Ok(())
    }
}
