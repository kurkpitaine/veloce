//! A trust chain contains a PKI signing certificates, ie: RCA, EA and AA certificates.
//! Also, it contains the Certificate Revocation List.
#[cfg(not(feature = "std"))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use core::{fmt, hash::Hash};

use super::{
    certificate::{
        AuthorizationAuthorityCertificate, AuthorizationTicketCertificate,
        CertificateWithHashContainer, EnrollmentAuthorityCertificate,
        EnrollmentCredentialCertificate, RootCertificate,
    },
    HashedId8,
};

type Container<C> = CertificateWithHashContainer<C>;

/// Container for the AT certificate.
#[derive(Debug)]
pub struct ATContainer {
    /// The AT certificate.
    at_cert: Container<AuthorizationTicketCertificate>,
    /// Number of times the AT has been elected to sign messages.
    elected: usize,
}

impl ATContainer {
    /// Create a new [ATContainer] from an [AuthorizationTicketCertificate] and a number of times
    /// it has been elected to sign messages.
    pub fn new(at_cert: Container<AuthorizationTicketCertificate>, elected: usize) -> Self {
        Self { at_cert, elected }
    }

    /// Return a reference on the [AuthorizationTicketCertificate].
    pub fn at_container(&self) -> &Container<AuthorizationTicketCertificate> {
        &self.at_cert
    }

    /// Return the number of times this AT has been elected to sign messages.
    pub fn elected(&self) -> usize {
        self.elected
    }

    /// Notify this AT has been elected to sign messages.
    pub fn notify_elected(&mut self) {
        self.elected += 1;
    }
}

/// Error returned when trying to set an index that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoCertificateAtIndexError(usize);

impl fmt::Display for NoCertificateAtIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No certificate at index {}", self.0)
    }
}

/// A certificate trust chain.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TrustChain {
    /// Root certificate of the trust chain.
    root_cert: Container<RootCertificate>,
    /// Enrollment Authority certificate of the trust chain.
    ea_cert: Option<Container<EnrollmentAuthorityCertificate>>,
    /// Enrollment Credential certificate of the trust chain.
    ec_cert: Option<Container<EnrollmentCredentialCertificate>>,
    /// Authorization Authority certificate of the trust chain.
    aa_cert: Option<Container<AuthorizationAuthorityCertificate>>,
    /// Authorization Ticket certificates of the trust chain.
    at_certs: BTreeMap<usize, ATContainer>,
    /// Revoked certificates.
    revoked_certs: Vec<HashedId8>,
    /// Current Authorization Ticket certificate index.
    current_at_id: Option<usize>,
}

impl TrustChain {
    /// Create a [TrustChain] with `root_cert` as root of trust.
    pub fn new(root_cert: Container<RootCertificate>) -> Self {
        Self {
            root_cert,
            ea_cert: None,
            ec_cert: None,
            aa_cert: None,
            at_certs: BTreeMap::new(),
            revoked_certs: Vec::new(),
            current_at_id: None,
        }
    }

    /// Get a reference on the Root certificate.
    pub fn root_cert(&self) -> &Container<RootCertificate> {
        &self.root_cert
    }

    /// Get a reference on the Enrollment Authority certificate, if any.
    pub fn ea_cert(&self) -> Option<&Container<EnrollmentAuthorityCertificate>> {
        self.ea_cert.as_ref()
    }

    /// Get a reference on the Enrollment Credential certificate, if any.
    pub fn ec_cert(&self) -> Option<&Container<EnrollmentCredentialCertificate>> {
        self.ec_cert.as_ref()
    }

    /// Get a reference on the Authorization Authority certificate, if any.
    pub fn aa_cert(&self) -> Option<&Container<AuthorizationAuthorityCertificate>> {
        self.aa_cert.as_ref()
    }

    /// Get a reference on the Authorization Ticket certificate, if any.
    pub fn at_cert(&self) -> Option<&ATContainer> {
        let index = self.current_at_id?;
        self.at_certs.get(&index)
    }

    /// Get a reference on all the Authorization Ticket certificates.
    pub fn at_certs(&self) -> &BTreeMap<usize, ATContainer> {
        &self.at_certs
    }

    /// Set the Enrollment Authority Certificate.
    pub fn set_ea_cert(&mut self, ea_cert: Container<EnrollmentAuthorityCertificate>) {
        self.ea_cert = Some(ea_cert);
    }

    /// Set the Enrollment Credential Certificate.
    pub fn set_ec_cert(&mut self, ec_cert: Container<EnrollmentCredentialCertificate>) {
        self.ec_cert = Some(ec_cert);
    }

    /// Set the Authorization Authority Certificate.
    pub fn set_aa_cert(&mut self, aa_cert: Container<AuthorizationAuthorityCertificate>) {
        self.aa_cert = Some(aa_cert);
    }

    /// Set the Authorization Ticket Certificates.
    /// This method will clear any previously added Authorization Ticket certificates.
    pub fn set_at_certs(&mut self, at_certs: BTreeMap<usize, ATContainer>) {
        self.at_certs = at_certs;
    }

    /// Add an Authorization Ticket certificate `at_cert` at `index`.
    pub fn add_at_cert(&mut self, index: usize, at_cert: ATContainer) {
        self.at_certs.insert(index, at_cert);
    }

    /// Set the current Authorization Ticket certificate index.
    /// Increments the election counter of the AT certificate.
    pub fn set_at_cert_index(&mut self, index: usize) -> Result<(), NoCertificateAtIndexError> {
        let Some(entry) = self.at_certs.get_mut(&index) else {
            return Err(NoCertificateAtIndexError(index));
        };

        self.current_at_id = Some(index);
        entry.notify_elected();
        Ok(())
    }

    /// Add a certificate [HashedId8] to the revoked certificates list.
    pub fn add_revoked_cert(&mut self, digest: HashedId8) {
        self.revoked_certs.push(digest);
    }

    /// Clears the revoked certificates list.
    pub fn clear_revoked_certs(&mut self) {
        self.revoked_certs.clear();
    }

    /// Query whether the certificate identifier `hash` is in the revoked
    /// certificates list.
    pub fn is_revoked(&self, hash: HashedId8) -> bool {
        self.revoked_certs.contains(&hash)
    }
}
