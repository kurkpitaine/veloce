//! A trust chain contains a PKI signing certificates, ie: RCA, EA and AA certificates.
//! Also, it contains the Certificate Revocation List.

use super::certificate::{
    AuthorizationAuthorityCertificate, EnrollmentAuthorityCertificate, HashedId8, RootCertificate,
};

/// A certificate trust chain.
pub struct TrustChain {
    /// Root certificate of the trust chain.
    root_cert: RootCertificate,
    /// Enrollment Authority certificate of the trust chain.
    ea_cert: Option<EnrollmentAuthorityCertificate>,
    /// Authorization Authority certificate of the trust chain.
    aa_cert: Option<AuthorizationAuthorityCertificate>,
    /// Revocated certificates.
    revocated_certs: Vec<HashedId8>,
}

impl TrustChain {
    /// Create a [TrustChain].
    pub fn new(root_cert: RootCertificate) -> Self {
        Self {
            root_cert,
            ea_cert: None,
            aa_cert: None,
            revocated_certs: Vec::new(),
        }
    }

    /// Returns the Root certificate.
    pub fn root_cert(&self) -> RootCertificate {
        self.root_cert.clone()
    }

    /// Returns the Enrollment Authority certificate, if any.
    pub fn ea_cert(&self) -> Option<EnrollmentAuthorityCertificate> {
        self.ea_cert.clone()
    }

    /// Returns the Authorization Authority certificate, if any.
    pub fn aa_cert(&self) -> Option<AuthorizationAuthorityCertificate> {
        self.aa_cert.clone()
    }

    /// Set the Enrollment Authority Certificate.
    pub fn set_ea_cert(&mut self, ea_cert: EnrollmentAuthorityCertificate) {
        self.ea_cert = Some(ea_cert);
    }

    /// Set the Authorization Authority Certificate.
    pub fn set_aa_cert(&mut self, aa_cert: AuthorizationAuthorityCertificate) {
        self.aa_cert = Some(aa_cert);
    }

    /// Add a certificate [HashedId8] to the revocated certificates list.
    pub fn add_revocated_cert(&mut self, digest: HashedId8) {
        self.revocated_certs.push(digest);
    }
}
