use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};
use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609Dot2::{self, Certificate as EtsiCertificate, VerificationKeyIndicator},
        ieee1609Dot2Base_types::{
            self, EccP256CurvePoint, EccP384CurvePoint, PublicVerificationKey, Signature,
        },
    },
    prelude::rasn,
};

use crate::time::{Duration, TAI2004};

mod root;
mod subordinate;
mod tlm;

use super::{signature::EcdsaSignatureError, VerificationKeyError};

pub use {root::RootCertificate, tlm::TrustListManagerCertificate};

/// Enrollment Authority certificate.
pub type EnrollmentAuthorityCertificate = subordinate::SubordinateCertificate;
/// Authorization Authority certificate.
pub type AuthorizationAuthorityCertificate = subordinate::SubordinateCertificate;

/// HashedId8, also known as certificate digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HashedId8(u64);

impl HashedId8 {
    /// Constructs from a bytes slice.
    ///
    /// # Panics
    /// This method panics when `bytes.len() < 8`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(NetworkEndian::read_u64(bytes))
    }

    /// Constructs from an u64.
    pub const fn from_u64(val: u64) -> Self {
        Self(val)
    }

    /// Returns HashedId8 as an u64.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for HashedId8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0x}", self.0)
    }
}

/// Certificate validity period.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ValidityPeriod {
    pub start: TAI2004,
    pub end: TAI2004,
}

#[derive(Debug)]
/// Certificate errors.
pub enum CertificateError {
    /// Malformed, ie: a mandatory field
    /// is absent or a present field should be absent.
    Malformed,
    /// Certificate does not have permissions.
    NoPermissions,
    /// Certificate does not contain allowed permissions.
    IllegalPermissions,
    /// Certificate Id type is unexpected.
    UnexpectedId,
    /// Certificate temporal validity is expired.
    Expired,
    /// Signature error.
    Signature(EcdsaSignatureError),
    /// Verification key error.
    VerificationKey(VerificationKeyError),
    /// A custom error that does not fall under any other Certificate error kind.
    Other,
}

/// Wrapper around an Etsi certificate.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Certificate(EtsiCertificate);

impl Certificate {
    /// Constructs from a raw ETSI Certificate.
    /// This method verifies if the certificate is valid relative to Asn.1 constraints.
    pub fn from_etsi_certificate(cert: EtsiCertificate) -> Result<Self, CertificateError> {
        Self::verify_etsi_certificate(&cert)?;

        Ok(Self(cert))
    }

    /// Get a reference on the inner raw certificate.
    pub fn inner(&self) -> &EtsiCertificate {
        &self.0
    }

    /// Returns the temporal validity period of the certificate.
    pub fn validity_period(&self) -> ValidityPeriod {
        use ieee1609Dot2Base_types::Duration as IeeeDuration;

        let tbs = &self.0 .0.to_be_signed;

        // Time in certificate is TAI seconds.
        let start = TAI2004::from_secs(tbs.validity_period.start.0 .0);

        let validity_duration = match &tbs.validity_period.duration {
            IeeeDuration::microseconds(us) => Duration::from_micros(us.0.into()),
            IeeeDuration::milliseconds(ms) => Duration::from_millis(ms.0.into()),
            IeeeDuration::seconds(s) => Duration::from_secs(s.0.into()),
            IeeeDuration::minutes(m) => Duration::from_secs(u64::from(m.0) * 60),
            IeeeDuration::hours(h) => Duration::from_secs(u64::from(h.0) * 3600),
            IeeeDuration::sixtyHours(sh) => Duration::from_secs(u64::from(sh.0) * 216_000),
            IeeeDuration::years(y) => Duration::from_secs(u64::from(y.0) * 31_556_952), // One gregorian year is 31556952 seconds.
        };

        ValidityPeriod {
            start,
            end: start + validity_duration,
        }
    }

    /// Get a reference on the inner certificate signature.
    ///
    /// # Panics
    ///
    /// This method panics if the inner certificate is not signed.
    /// One must ensure the certificate is valid using [Self::verify_certificate]
    /// and is of type [ieee1609Dot2::CertificateType::explicit].
    pub fn signature_or_panic(&self) -> &Signature {
        match &self.0 .0.signature {
            Some(signature) => signature,
            _ => panic!("Certificate does not contain signature."),
        }
    }

    /// Get a reference on the inner public verification key.
    ///
    /// # Panics
    ///
    /// This method panics if the inner certificate Verification Key Indicator
    /// is not a verification key.
    /// One must ensure the certificate is valid using [Self::verify_certificate]
    /// and is of type [ieee1609Dot2::CertificateType::explicit].
    pub fn public_verification_key_or_panic(&self) -> &PublicVerificationKey {
        match &self.0 .0.to_be_signed.verify_key_indicator {
            VerificationKeyIndicator::verificationKey(key) => key,
            _ => panic!("Verification Key Indicator is not a verification key."),
        }
    }

    /// Get the inner certificate `to_be_signed` content encoded as Asn.1 COER.
    pub fn to_be_signed_as_coer(&self) -> Result<Vec<u8>, ()> {
        Ok(rasn::coer::encode(&self.0 .0.to_be_signed).map_err(|_| ())?)
    }

    #[inline]
    /// Verifies the Asn.1 constraints on an EtsiTs103097Certificate.
    pub fn verify_etsi_certificate(cert: &EtsiCertificate) -> Result<(), CertificateError> {
        use ieee1609Dot2::CertificateId;

        Self::verify_certificate(cert)?;

        let tbs = &cert.0.to_be_signed;
        match tbs.id {
            CertificateId::linkageData(_) | CertificateId::binaryId(_) => {
                return Err(CertificateError::Malformed)
            }
            _ => {}
        }

        if tbs.cert_request_permissions.is_some() || tbs.can_request_rollover.is_some() {
            return Err(CertificateError::Malformed);
        }

        Ok(())
    }

    #[inline]
    /// Verifies the Asn.1 constraints on an IEEE 1609.2 Certificate.
    fn verify_certificate(cert: &EtsiCertificate) -> Result<(), CertificateError> {
        use ieee1609Dot2::CertificateType;

        match cert.0.r_type {
            CertificateType::explicit => {
                /*
                ExplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
                    type(explicit),
                    toBeSigned(WITH COMPONENTS {...,
                        verifyKeyIndicator(WITH COMPONENTS {verificationKey})
                    }),
                    signature PRESENT
                })
                */
                let key = match &cert.0.to_be_signed.verify_key_indicator {
                    VerificationKeyIndicator::verificationKey(vk) => vk,
                    _ => return Err(CertificateError::Malformed),
                };

                // Per IEEE 1609.2, chapter 6.4.36: an EccP256CurvePoint within a PublicVerificationKey
                // structure is invalid if it indicates the choice x-only.
                // We apply the same requirement for EccP384CurvePoints.
                match key {
                    PublicVerificationKey::ecdsaNistP256(p) => match p {
                        EccP256CurvePoint::x_only(_) => return Err(CertificateError::Malformed),
                        _ => {}
                    },
                    PublicVerificationKey::ecdsaBrainpoolP256r1(p) => match p {
                        EccP256CurvePoint::x_only(_) => return Err(CertificateError::Malformed),
                        _ => {}
                    },
                    PublicVerificationKey::ecdsaBrainpoolP384r1(p) => match p {
                        EccP384CurvePoint::x_only(_) => return Err(CertificateError::Malformed),
                        _ => {}
                    },
                    PublicVerificationKey::ecdsaNistP384(p) => match p {
                        EccP384CurvePoint::x_only(_) => return Err(CertificateError::Malformed),
                        _ => {}
                    },
                    _ => {}
                }

                if cert.0.signature.is_none() {
                    return Err(CertificateError::Malformed);
                }
            }
            CertificateType::implicit => {
                /*
                ImplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
                    type(implicit),
                    toBeSigned(WITH COMPONENTS {...,
                    verifyKeyIndicator(WITH COMPONENTS {reconstructionValue})
                    }),
                    signature ABSENT
                })
                */
                match cert.0.to_be_signed.verify_key_indicator {
                    VerificationKeyIndicator::reconstructionValue(_) => {}
                    _ => return Err(CertificateError::Malformed),
                }

                if cert.0.signature.is_some() {
                    return Err(CertificateError::Malformed);
                }
            }
            _ => return Err(CertificateError::Malformed),
        }

        Ok(())
    }
}
