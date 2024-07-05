//! A trust chain contains a PKI signing certificates, ie: RCA, EA and AA certificates.
//! Also, it contains the Certificate Revocation List.

use super::{
    certificate::{
        AuthorizationAuthorityCertificate, AuthorizationTicketCertificate, CertificateWithHashContainer, EnrollmentAuthorityCertificate, RootCertificate
    },
    HashedId8,
};

type Container<C> = CertificateWithHashContainer<C>;

/// A certificate trust chain.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TrustChain {
    /// Root certificate of the trust chain.
    root_cert: Container<RootCertificate>,
    /// Enrollment Authority certificate of the trust chain.
    ea_cert: Option<Container<EnrollmentAuthorityCertificate>>,
    /// Authorization Authority certificate of the trust chain.
    aa_cert: Option<Container<AuthorizationAuthorityCertificate>>,
    /// Authorization Ticket certificate of the trust chain.
    at_cert: Option<Container<AuthorizationTicketCertificate>>,
    /// Revoked certificates.
    revoked_certs: Vec<HashedId8>,
}

impl TrustChain {
    /// Create a [TrustChain] with `root_cert` as root of trust.
    pub fn new(root_cert: Container<RootCertificate>) -> Self {
        Self {
            root_cert,
            ea_cert: None,
            aa_cert: None,
            at_cert: None,
            revoked_certs: Vec::new(),
        }
    }

    /// Get a reference on the Root certificate.
    pub fn root_cert(&self) -> &Container<RootCertificate> {
        &self.root_cert
    }

    /// Get a reference on the Enrollment Authority certificate, if any.
    pub fn ea_cert(&self) -> &Option<Container<EnrollmentAuthorityCertificate>> {
        &self.ea_cert
    }

    /// Get a reference on the Authorization Authority certificate, if any.
    pub fn aa_cert(&self) -> &Option<Container<AuthorizationAuthorityCertificate>> {
        &self.aa_cert
    }

    /// Get a reference on the Authorization Ticket certificate, if any.
    pub fn at_cert(&self) -> &Option<Container<AuthorizationTicketCertificate>> {
        &self.at_cert
    }

    /// Set the Enrollment Authority Certificate.
    pub fn set_ea_cert(&mut self, ea_cert: Container<EnrollmentAuthorityCertificate>) {
        self.ea_cert = Some(ea_cert);
    }

    /// Set the Authorization Authority Certificate.
    pub fn set_aa_cert(&mut self, aa_cert: Container<AuthorizationAuthorityCertificate>) {
        self.aa_cert = Some(aa_cert);
    }

    /// Set the Authorization Ticket Certificate.
    pub fn set_at_cert(&mut self, at_cert: Container<AuthorizationTicketCertificate>) {
        self.at_cert = Some(at_cert);
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
