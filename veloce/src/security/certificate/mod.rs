use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609Dot2::{self, Certificate as EtsiCertificate, VerificationKeyIndicator},
        ieee1609Dot2Base_types::{
            self, EccP256CurvePoint, EccP384CurvePoint, PublicVerificationKey,
        },
    },
    prelude::rasn::{self, types::FixedOctetString},
};

use crate::{
    security::EciesKey,
    time::{Duration, Instant, TAI2004},
};

use super::{
    backend::Backend,
    permission::{Permission, PermissionError},
    signature::{EcdsaSignature, EcdsaSignatureError, EcdsaSignatureInner},
    EccPoint, EcdsaKey, EcdsaKeyError, EciesKeyError, HashAlgorithm, HashedId8, Issuer,
};

mod at;
mod root;
mod subordinate;
mod tlm;

pub use at::AuthorizationTicketCertificate;
pub use root::RootCertificate;
pub use subordinate::AuthorizationAuthorityCertificate;
pub use subordinate::EnrollmentAuthorityCertificate;
pub use tlm::TrustListManagerCertificate;

/// Certificate validity period.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ValidityPeriod {
    pub start: TAI2004,
    pub end: TAI2004,
}

impl ValidityPeriod {
    /// Check if `self` contains `other` [ValidityPeriod].
    pub fn contains(&self, other: &ValidityPeriod) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

pub type CertificateResult<T> = core::result::Result<T, CertificateError>;

/// Certificate errors.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CertificateError {
    /// Asn.1 COER encoding error.
    Asn1,
    /// Malformed, ie: a mandatory field
    /// is absent or a present field should be absent.
    Malformed,
    /// Certificate does not have permissions.
    NoPermissions,
    /// Permission error.
    Permission(PermissionError),
    /// Certificate does not contain allowed permissions.
    IllegalPermissions,
    /// Certificate signer is unknown, and therefore the certificate
    /// cannot be checked.
    UnknownSigner(HashedId8),
    /// Certificate has an inconsistent validity period with the signer.
    InconsistentValidityPeriod,
    /// Certificate has an inconsistent permissions with the signer.
    InconsistentPermissions,
    /// Certificate Id type is unexpected.
    UnexpectedId,
    /// Certificate temporal validity is expired.
    Expired,
    /// Certificate signature issuer type is unexpected.
    UnexpectedIssuer,
    /// Certificate signature issuer type is unsupported.
    UnsupportedIssuer,
    /// Signature error.
    Signature(EcdsaSignatureError),
    /// Verification key error.
    VerificationKey(EcdsaKeyError),
    /// Encryption key error.
    EncryptionKey(EciesKeyError),
    /// Backend error.
    Backend,
    /// A custom error that does not fall under any other Certificate error kind.
    Other,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Certificate {
    /// Root certificate type.
    Root(RootCertificate),
    /// EA certificate type.
    EnrollmentAuthority(EnrollmentAuthorityCertificate),
    /// AA certificate type.
    AuthorizationAuthority(AuthorizationAuthorityCertificate),
    /* /// AT certificate type.
    AuthorizationTicket(CertWrapper<>),
    /// EC certificate type.
    EnrollmentCredential(CertWrapper<>),
    /// TLM certificate type.s
    TrustedListManager(CertWrapper<>), */
}

impl Certificate {
    /// Get a reference on the inner [RootCertificate].
    ///
    /// # Panics
    /// This method panics of the inner certificate is not of Root type.
    pub fn root_or_panic(&self) -> &RootCertificate {
        match &self {
            Certificate::Root(c) => c,
            _ => panic!("Certificate is not of Root type."),
        }
    }

    /// Get a reference on the inner [EnrollmentAuthorityCertificate].
    ///
    /// # Panics
    /// This method panics of the inner certificate is not of EA type.
    pub fn ea_or_panic(&self) -> &EnrollmentAuthorityCertificate {
        match &self {
            Certificate::EnrollmentAuthority(c) => c,
            _ => panic!("Certificate is not of EA type."),
        }
    }

    /// Get a reference on the inner [AuthorizationAuthorityCertificate].
    ///
    /// # Panics
    /// This method panics of the inner certificate is not of AA type.
    pub fn aa_or_panic(&self) -> &AuthorizationAuthorityCertificate {
        match &self {
            Certificate::AuthorizationAuthority(c) => c,
            _ => panic!("Certificate is not of AA type."),
        }
    }

    /// Verifies the Asn.1 constraints on an EtsiTs103097Certificate.
    #[inline]
    pub fn verify_etsi_constraints(cert: &EtsiCertificate) -> CertificateResult<()> {
        use ieee1609Dot2::CertificateId;

        let tbs = &cert.0.to_be_signed;

        // The component id of type CertificateId constrained to choice type name or none.
        match tbs.id {
            CertificateId::name(_) | CertificateId::none(_) => {}
            _ => return Err(CertificateError::Malformed),
        }

        // The component cracaId set to 000000'H.
        if tbs.craca_id.0 != FixedOctetString::<3>::from([0; 3]) {
            return Err(CertificateError::Malformed);
        }

        // The component crlSeries set to 0'D.
        if tbs.crl_series.0 .0 != 0 {
            return Err(CertificateError::Malformed);
        }

        // At least one of the components appPermissions and certIssuePermissions shall be present.
        if tbs.app_permissions.is_none() && tbs.cert_issue_permissions.is_none() {
            return Err(CertificateError::Malformed);
        }

        // The component certRequestPermissions absent. The component canRequestRollover absent.
        if tbs.cert_request_permissions.is_some() || tbs.can_request_rollover.is_some() {
            return Err(CertificateError::Malformed);
        }

        // The component signature of EtsiTs103097Certificate shall be of type Signature.
        if cert.0.signature.is_none() {
            return Err(CertificateError::Malformed);
        }

        Ok(())
    }

    /// Verifies the Asn.1 constraints on an IEEE 1609.2 Certificate.
    #[inline]
    pub fn verify_ieee_constraints(cert: &EtsiCertificate) -> CertificateResult<()> {
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

pub trait CertificateTrait {
    /// Get a reference on the inner certificate.
    fn inner(&self) -> &EtsiCertificate;

    /// Get a reference on the raw certificate bytes, encoded as Asn.1 COER.
    fn raw_bytes(&self) -> &[u8];

    /// Get the inner certificate `to_be_signed` content bytes, encoded as Asn.1 COER.
    fn to_be_signed_bytes(&self) -> CertificateResult<Vec<u8>> {
        Ok(rasn::coer::encode(&self.inner().0.to_be_signed).map_err(|_| CertificateError::Asn1)?)
    }

    /// Returns the [Issuer] identifier of the certificate.
    fn issuer_identifier(&self) -> CertificateResult<Issuer> {
        Issuer::try_from(&self.inner().0.issuer).map_err(|_| CertificateError::UnsupportedIssuer)
    }

    /// Returns the temporal validity period of the certificate.
    fn validity_period(&self) -> ValidityPeriod {
        use ieee1609Dot2Base_types::Duration as IeeeDuration;
        let tbs = &self.inner().0.to_be_signed;

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

    /// Canonicalize `certificate`, as defined in IEEE 1609.2 paragraph 6.4.3
    /// - Encoding considerations.
    fn canonicalize<B>(
        mut certificate: EtsiCertificate,
        backend: &B,
    ) -> CertificateResult<EtsiCertificate>
    where
        B: Backend + ?Sized,
    {
        // All keys should be in compressed form.
        let tbs = &mut certificate.0.to_be_signed;
        if let Some(enc_key) = &mut tbs.encryption_key {
            let key =
                EciesKey::try_from(&enc_key.public_key).map_err(CertificateError::EncryptionKey)?;
            enc_key.public_key = backend
                .compress_ecies_key(key)
                .map_err(|_| CertificateError::Backend)?
                .try_into()
                .map_err(CertificateError::EncryptionKey)?;
        }

        match &tbs.verify_key_indicator {
            VerificationKeyIndicator::verificationKey(p) => {
                let key = EcdsaKey::try_from(p).map_err(CertificateError::VerificationKey)?;
                tbs.verify_key_indicator = VerificationKeyIndicator::verificationKey(
                    backend
                        .compress_ecdsa_key(key)
                        .map_err(|_| CertificateError::Backend)?
                        .try_into()
                        .map_err(CertificateError::VerificationKey)?,
                );
            }
            // Dunno what to do, IEEE 1609.2 and TS 103 097 does not describe anything...
            VerificationKeyIndicator::reconstructionValue(_p) => {}
            _ => {}
        };

        let canonicalize_sig = |sig: EcdsaSignatureInner| {
            let s = sig.s;
            let r = match sig.r {
                EccPoint::XCoordinateOnly(p) => EccPoint::XCoordinateOnly(p),
                EccPoint::CompressedY0(p) => EccPoint::XCoordinateOnly(p),
                EccPoint::CompressedY1(p) => EccPoint::XCoordinateOnly(p),
                EccPoint::Uncompressed(p) => EccPoint::XCoordinateOnly(p.x),
            };

            EcdsaSignatureInner { r, s }
        };

        if let Some(signature) = &certificate.0.signature {
            let ecdsa_sig =
                EcdsaSignature::try_from(signature).map_err(CertificateError::Signature)?;
            let sig = match ecdsa_sig {
                EcdsaSignature::NistP256r1(s) => EcdsaSignature::NistP256r1(canonicalize_sig(s)),
                EcdsaSignature::NistP384r1(s) => EcdsaSignature::NistP384r1(canonicalize_sig(s)),
                EcdsaSignature::BrainpoolP256r1(s) => {
                    EcdsaSignature::BrainpoolP256r1(canonicalize_sig(s))
                }
                EcdsaSignature::BrainpoolP384r1(s) => {
                    EcdsaSignature::BrainpoolP384r1(canonicalize_sig(s))
                }
            };

            certificate.0.signature = Some(sig.try_into().map_err(CertificateError::Signature)?);
        }

        Ok(certificate)
    }

    /// Verifies the Asn.1 constraints on the enclosed certificate.
    fn verify_constraints(cert: &EtsiCertificate) -> CertificateResult<()>;
}

pub trait ExplicitCertificate: CertificateTrait {
    /// Get the application permissions of the certificate.
    fn application_permissions(&self) -> CertificateResult<Vec<Permission>> {
        let inner = self.inner();
        let mut permissions = Vec::new();

        if let Some(seq) = &inner.0.to_be_signed.app_permissions {
            for ps in &seq.0 {
                let p = Permission::try_from(ps).map_err(CertificateError::Permission)?;
                permissions.push(p);
            }
        }

        Ok(permissions)
    }

    /// Get the issue permissions of the certificate.
    fn issue_permissions(&self) -> CertificateResult<Vec<Permission>> {
        use ieee1609Dot2::SubjectPermissions;

        let inner = self.inner();
        let mut permissions = Vec::new();

        if let Some(seq) = &inner.0.to_be_signed.cert_issue_permissions {
            for group in &seq.0 {
                match &group.subject_permissions {
                    SubjectPermissions::explicit(s) => {
                        for psr in &s.0 {
                            let p =
                                Permission::try_from(psr).map_err(CertificateError::Permission)?;
                            permissions.push(p);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(permissions)
    }

    /// Checks the certificate validity and signature.
    fn check<F, B, C>(&self, timestamp: Instant, backend: &B, f: F) -> CertificateResult<bool>
    where
        B: Backend + ?Sized,
        C: ExplicitCertificate,
        F: FnOnce(HashedId8) -> Option<C>,
    {
        let validity_period = self.validity_period();

        // Check validity period.
        if validity_period.end <= TAI2004::from_unix_instant(timestamp) {
            return Err(CertificateError::Expired);
        }

        // Get signature.
        let sig = self.signature()?;

        // Get issuer identifier.
        let signer = self.issuer_identifier()?;

        let signer_id = match signer {
            Issuer::SelfSigned(_) => return Err(CertificateError::UnexpectedIssuer),
            Issuer::SHA256Digest(h) | Issuer::SHA384Digest(h) => h,
        };

        // Get matching signer certificate.
        let signer_cert = f(signer_id).ok_or(CertificateError::UnknownSigner(signer_id))?;

        // Check time consistency between self and signer.
        let signer_validity = signer_cert.validity_period();
        if !signer_validity.contains(&validity_period) {
            return Err(CertificateError::InconsistentValidityPeriod);
        }

        // Check issuing permissions consistency between self and signer.
        let signer_permissions = signer_cert.issue_permissions()?;
        let permissions = self.issue_permissions()?;
        if !permissions.iter().all(|p| {
            signer_permissions
                .iter()
                .find(|e| e.aid() == p.aid())
                .is_some()
        }) {
            return Err(CertificateError::InconsistentPermissions);
        }

        // Get public verification key.
        let signer_pubkey = signer_cert.public_verification_key()?;
        let signer_data = signer_cert.raw_bytes();

        // Get content to verify.
        // Certificate has already been canonicalized by Self::from_etsi_certificate().
        let tbs = self
            .to_be_signed_bytes()
            .map_err(|_| CertificateError::Other)?;

        let hash = match sig.hash_algorithm() {
            HashAlgorithm::SHA256 => [backend.sha256(&tbs), backend.sha256(signer_data)].concat(),
            HashAlgorithm::SHA384 => [backend.sha384(&tbs), backend.sha384(signer_data)].concat(),
        };

        let res = backend
            .verify_signature(sig, signer_pubkey, &hash)
            .map_err(|_| CertificateError::Backend)?;

        Ok(res)
    }

    /// Computes the Hashed-id8 of the certificate.
    fn hashed_id8<B>(&self, backend: &B) -> CertificateResult<HashedId8>
    where
        B: Backend + ?Sized,
    {
        let k = self.public_verification_key()?;

        // Hashing algorithm is determined by verification key.
        let hash = match k {
            EcdsaKey::NistP256r1(_) | EcdsaKey::BrainpoolP256r1(_) => {
                let h = backend.sha256(self.raw_bytes());
                HashedId8::from_bytes(&h[24..])
            }
            EcdsaKey::NistP384r1(_) | EcdsaKey::BrainpoolP384r1(_) => {
                let h = backend.sha384(self.raw_bytes());
                HashedId8::from_bytes(&h[40..])
            }
        };

        Ok(hash)
    }

    /// Get a reference on the inner public verification key.
    fn public_verification_key(&self) -> CertificateResult<EcdsaKey> {
        let k = match &self.inner().0.to_be_signed.verify_key_indicator {
            VerificationKeyIndicator::verificationKey(key) => key,
            _ => return Err(CertificateError::Malformed),
        };

        EcdsaKey::try_from(k).map_err(CertificateError::VerificationKey)
    }

    /// Get a reference on the inner certificate signature.
    fn signature(&self) -> CertificateResult<EcdsaSignature> {
        let s = match &self.inner().0.signature {
            Some(signature) => signature,
            _ => return Err(CertificateError::Malformed),
        };

        EcdsaSignature::try_from(s).map_err(CertificateError::Signature)
    }
}
