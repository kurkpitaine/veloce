use core::fmt;

use veloce_asn1::{
    defs::etsi_102941_v221::{
        etsi_ts102941_messages_ca::{EtsiTs102941Data, EtsiTs102941DataContent},
        etsi_ts102941_trust_lists::{CrlEntry, ToBeSignedCrl},
        ieee1609_dot2_base_types::{Time32, Uint32},
    },
    prelude::rasn::types::Integer,
};

use crate::{
    pki::{
        asn1_wrapper::{Asn1Wrapper, Asn1WrapperError},
        message::VerifierError,
        signed_data::{SignedData, SignedDataError},
    },
    security::HashedId8,
    time::TAI2004,
};

/// Marker struct for CRL Request type.
#[derive(Debug, Clone, Copy)]
pub struct CRL;

/// Certificate Trust List message type.
pub type CertificateRevocationListMessage = SignedData<CRL>;

pub type CertificateRevocationListResult<T> =
    core::result::Result<T, CertificateRevocationListError>;

/// Certificate Trust List error.
#[derive(Debug)]
pub enum CertificateRevocationListError {
    /// Asn.1 wrapper error.
    Asn1Wrapper(Asn1WrapperError),
    /// CRL version is not supported.
    UnsupportedVersion,
    /// Unexpected Etsi TS 102941 data content.
    UnexpectedDataContent,
    /// Outer wrapper.
    Outer(SignedDataError),
    /// Something went wrong while verifying the Outer wrapper.
    OuterVerifier(VerifierError),
    /// False Outer wrapper signature.
    FalseOuterSignature,
    /// No signer certificate to check the CTL signature against.
    NoSignerCertificate,
}

impl fmt::Display for CertificateRevocationListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateRevocationListError::Asn1Wrapper(e) => {
                write!(f, "asn1 wrapper error: {}", e)
            }
            CertificateRevocationListError::UnsupportedVersion => write!(f, "unsupported version"),
            CertificateRevocationListError::UnexpectedDataContent => {
                write!(f, "unexpected Etsi TS 102941 data content")
            }
            CertificateRevocationListError::Outer(e) => write!(f, "outer: {}", e),
            CertificateRevocationListError::OuterVerifier(e) => write!(f, "outer verifier: {}", e),
            CertificateRevocationListError::FalseOuterSignature => {
                write!(f, "false outer signature")
            }
            CertificateRevocationListError::NoSignerCertificate => {
                write!(f, "no signer certificate")
            }
        }
    }
}

/// Certificate Revocation List type.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateRevocationList {
    /// Inner certificate revocation list structure.
    inner: Asn1Wrapper<ToBeSignedCrl>,
}

impl CertificateRevocationList {
    /// Constructs an [CertificateRevocationList] from bytes.
    /// The EtsiTs102941Data wrapper is expected.
    pub fn from_bytes(bytes: &[u8]) -> CertificateRevocationListResult<Self> {
        let etsi_data = Asn1Wrapper::<EtsiTs102941Data>::decode_coer(bytes)
            .map_err(CertificateRevocationListError::Asn1Wrapper)?;

        let tbs_crl = match etsi_data.content {
            EtsiTs102941DataContent::certificateRevocationList(crl) => crl,
            _ => return Err(CertificateRevocationListError::UnexpectedDataContent),
        };

        if tbs_crl.version.0 != Integer::from(1) {
            return Err(CertificateRevocationListError::UnsupportedVersion);
        }

        let inner =
            Asn1Wrapper::from_raw(tbs_crl).map_err(CertificateRevocationListError::Asn1Wrapper)?;

        Ok(Self { inner })
    }

    /// Return the [TAI2004] time at which this CRL update has been generated.
    pub fn this_update(&self) -> TAI2004 {
        let inner = self.inner.inner();
        TAI2004::from_secs(inner.this_update.0 .0)
    }

    /// Set the CRL `this_update` moment.
    pub fn set_this_update(&mut self, this_update: TAI2004) {
        let inner = self.inner.inner_mut();
        inner.this_update = Time32(Uint32(this_update.secs() as u32));
    }

    /// Return the CRL next update moment as [TAI2004] time.
    pub fn next_update(&self) -> TAI2004 {
        let inner = self.inner.inner();
        TAI2004::from_secs(inner.next_update.0 .0)
    }

    /// Set the CRL `next_update` moment.
    pub fn set_next_update(&mut self, next_update: TAI2004) {
        let inner = self.inner.inner_mut();

        let value = next_update.secs() as u32;
        inner.next_update = Time32(Uint32(value));
    }

    /// Get the CRL entries as a vector of [HashedId8].
    pub fn entries(&self) -> Vec<HashedId8> {
        let inner = self.inner.inner();
        inner
            .entries
            .iter()
            .map(|e| HashedId8::from(&e.0))
            .collect()
    }

    /// Set the CRL entries.
    pub fn set_entries(&mut self, entries: Vec<HashedId8>) {
        let inner = self.inner.inner_mut();
        inner.entries = entries.into_iter().map(|e| CrlEntry(e.into())).collect();
    }
}
