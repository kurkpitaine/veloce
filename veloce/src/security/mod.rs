use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};
use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609Dot2::IssuerIdentifier,
        ieee1609Dot2Base_types::{
            self, BasePublicEncryptionKey, EccP256CurvePoint, EccP256CurvePointUncompressedP256,
            EccP384CurvePoint, EccP384CurvePointUncompressedP384,
            HashAlgorithm as EtsiHashAlgorithm, PublicVerificationKey,
        },
    },
    prelude::rasn::types::FixedOctetString,
};

pub mod backend;
pub mod certificate;
mod certificate_cache;
pub mod permission;
pub mod secured_message;
pub mod service;
pub mod signature;
pub mod ssp;
pub mod trust_chain;
pub mod trust_store;

#[cfg(test)]
mod tests;

pub use backend::{
    openssl::{OpensslBackend, OpensslBackendConfig},
    Backend as SecurityBackend,
};

pub use certificate::Certificate;
pub use service::SecurityService;
pub use trust_chain::TrustChain;

/// Hash algorithm for a certificate digest or a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HashAlgorithm {
    /// SHA256 Hash algorithm.
    SHA256,
    /// SHA384 Hash algorithm.
    SHA384,
}

/// Hash algorithm type is unsupported.
pub struct HashAlgorithmUnsupportedError;

impl TryFrom<&EtsiHashAlgorithm> for HashAlgorithm {
    type Error = HashAlgorithmUnsupportedError;

    fn try_from(value: &EtsiHashAlgorithm) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiHashAlgorithm::sha256 => HashAlgorithm::SHA256,
            EtsiHashAlgorithm::sha384 => HashAlgorithm::SHA384,
            _ => return Err(HashAlgorithmUnsupportedError),
        };

        Ok(res)
    }
}

impl Into<EtsiHashAlgorithm> for HashAlgorithm {
    fn into(self) -> EtsiHashAlgorithm {
        match self {
            HashAlgorithm::SHA256 => EtsiHashAlgorithm::sha256,
            HashAlgorithm::SHA384 => EtsiHashAlgorithm::sha384,
        }
    }
}

/// Unsupported type of issuer.
pub struct IssuerUnsupportedError;

/// Certificate issuer identifier.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Issuer {
    /// Certificate is self signed.
    SelfSigned(HashAlgorithm),
    /// Certificate is signed with another certificate identified with
    /// an SHA256 digest truncated as an [HashedId8].
    SHA256Digest(HashedId8),
    /// Certificate is signed with another certificate identified with
    /// an SHA384 digest truncated as an [HashedId8].
    SHA384Digest(HashedId8),
}

impl TryFrom<&IssuerIdentifier> for Issuer {
    type Error = IssuerUnsupportedError;

    fn try_from(value: &IssuerIdentifier) -> Result<Self, Self::Error> {
        let res = match value {
            IssuerIdentifier::sha256AndDigest(h) => {
                Issuer::SHA256Digest(HashedId8::from_bytes(h.0.as_slice()))
            }
            IssuerIdentifier::sha384AndDigest(h) => {
                Issuer::SHA384Digest(HashedId8::from_bytes(h.0.as_slice()))
            }
            IssuerIdentifier::R_self(h) => {
                Issuer::SelfSigned(HashAlgorithm::try_from(h).map_err(|_| IssuerUnsupportedError)?)
            }
            _ => return Err(IssuerUnsupportedError),
        };

        Ok(res)
    }
}

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

    /// Returns HashedId8 as a byte array.
    pub fn as_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        NetworkEndian::write_u64(&mut bytes, self.0);
        bytes
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

impl From<&ieee1609Dot2Base_types::HashedId8> for HashedId8 {
    fn from(value: &ieee1609Dot2Base_types::HashedId8) -> Self {
        Self::from_bytes(value.0.as_slice())
    }
}

impl Into<ieee1609Dot2Base_types::HashedId8> for HashedId8 {
    fn into(self) -> ieee1609Dot2Base_types::HashedId8 {
        let hash = self.as_bytes();
        ieee1609Dot2Base_types::HashedId8(FixedOctetString::<8>::new(hash))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Elliptic curve digital signature algorithm key type.
pub enum EcdsaKeyType {
    /// NistP 256 R1 key type, aka secp256r1.
    NistP256r1,
    /// NistP 384 R1 key type, aka secp384r1.
    NistP384r1,
    /// Brainpool 256 R1 key type.
    BrainpoolP256r1,
    /// Brainpool 384 R1 key type.
    BrainpoolP384r1,
}

/// Representation of an ECC point.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EccPoint {
    /// Point contains X coordinate only.
    XCoordinateOnly(Vec<u8>),
    /// Point coordinates are compressed with Y0 method.
    CompressedY0(Vec<u8>),
    /// Point coordinates are compressed with Y1 method.
    CompressedY1(Vec<u8>),
    /// Point coordinates are uncompressed.
    Uncompressed(UncompressedEccPoint),
}

/// Error for types conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EccPointUnsupportedCoordinatesErr;

impl fmt::Display for EccPointUnsupportedCoordinatesErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unsupported coordinates")
    }
}

impl TryFrom<&EccP256CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_from(value: &EccP256CurvePoint) -> Result<Self, Self::Error> {
        let res = match value {
            EccP256CurvePoint::x_only(p) => Self::XCoordinateOnly(p.to_vec()),
            EccP256CurvePoint::compressed_y_0(p) => Self::CompressedY0(p.to_vec()),
            EccP256CurvePoint::compressed_y_1(p) => Self::CompressedY1(p.to_vec()),
            EccP256CurvePoint::uncompressedP256(p) => Self::Uncompressed(UncompressedEccPoint {
                x: p.x.to_vec(),
                y: p.y.to_vec(),
            }),
            _ => return Err(EccPointUnsupportedCoordinatesErr),
        };

        Ok(res)
    }
}

impl TryFrom<&EccP384CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_from(value: &EccP384CurvePoint) -> Result<Self, Self::Error> {
        let res = match value {
            EccP384CurvePoint::x_only(p) => Self::XCoordinateOnly(p.to_vec()),
            EccP384CurvePoint::compressed_y_0(p) => Self::CompressedY0(p.to_vec()),
            EccP384CurvePoint::compressed_y_1(p) => Self::CompressedY1(p.to_vec()),
            EccP384CurvePoint::uncompressedP384(p) => Self::Uncompressed(UncompressedEccPoint {
                x: p.x.to_vec(),
                y: p.y.to_vec(),
            }),
            _ => return Err(EccPointUnsupportedCoordinatesErr),
        };

        Ok(res)
    }
}

impl TryInto<EccP256CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_into(self) -> Result<EccP256CurvePoint, Self::Error> {
        let res = match self {
            EccPoint::XCoordinateOnly(c) => EccP256CurvePoint::x_only(FixedOctetString::<32>::new(
                c.try_into()
                    .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
            )),
            EccPoint::CompressedY0(c) => {
                EccP256CurvePoint::compressed_y_0(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY1(c) => {
                EccP256CurvePoint::compressed_y_1(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::Uncompressed(c) => {
                EccP256CurvePoint::uncompressedP256(EccP256CurvePointUncompressedP256 {
                    x: FixedOctetString::<32>::new(
                        c.x.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                    y: FixedOctetString::<32>::new(
                        c.y.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                })
            }
        };

        Ok(res)
    }
}

impl TryInto<EccP384CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_into(self) -> Result<EccP384CurvePoint, Self::Error> {
        let res = match self {
            EccPoint::XCoordinateOnly(c) => EccP384CurvePoint::x_only(FixedOctetString::<48>::new(
                c.try_into()
                    .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
            )),
            EccPoint::CompressedY0(c) => {
                EccP384CurvePoint::compressed_y_0(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY1(c) => {
                EccP384CurvePoint::compressed_y_1(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::Uncompressed(c) => {
                EccP384CurvePoint::uncompressedP384(EccP384CurvePointUncompressedP384 {
                    x: FixedOctetString::<48>::new(
                        c.x.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                    y: FixedOctetString::<48>::new(
                        c.y.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                })
            }
        };

        Ok(res)
    }
}

/// Elliptic curve digital signature key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EcdsaKey {
    /// NistP 256 R1 key type.
    NistP256r1(EccPoint),
    /// NistP 384 R1 key type.
    NistP384r1(EccPoint),
    /// Brainpool 256 R1 key type.
    BrainpoolP256r1(EccPoint),
    /// Brainpool 384 R1 key type.
    BrainpoolP384r1(EccPoint),
}

/// Error for types conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EcdsaKeyError {
    /// Key type is unsupported.
    UnsupportedType,
    /// Key point coordinates type is unsupported.
    UnsupportedCoordinates(EccPointUnsupportedCoordinatesErr),
}

impl fmt::Display for EcdsaKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcdsaKeyError::UnsupportedType => write!(f, "Unsupported key type"),
            EcdsaKeyError::UnsupportedCoordinates(e) => write!(f, "{}", e),
        }
    }
}

impl TryFrom<&PublicVerificationKey> for EcdsaKey {
    type Error = EcdsaKeyError;

    fn try_from(value: &PublicVerificationKey) -> Result<Self, Self::Error> {
        let res = match value {
            PublicVerificationKey::ecdsaNistP256(k) => EcdsaKey::NistP256r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            PublicVerificationKey::ecdsaNistP384(k) => EcdsaKey::NistP384r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            PublicVerificationKey::ecdsaBrainpoolP256r1(k) => EcdsaKey::BrainpoolP256r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            PublicVerificationKey::ecdsaBrainpoolP384r1(k) => EcdsaKey::BrainpoolP384r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            _ => return Err(EcdsaKeyError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryInto<PublicVerificationKey> for EcdsaKey {
    type Error = EcdsaKeyError;

    fn try_into(self) -> Result<PublicVerificationKey, Self::Error> {
        let res = match self {
            EcdsaKey::NistP256r1(p) => PublicVerificationKey::ecdsaNistP256(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::NistP384r1(p) => PublicVerificationKey::ecdsaNistP384(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::BrainpoolP256r1(p) => PublicVerificationKey::ecdsaBrainpoolP256r1(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::BrainpoolP384r1(p) => PublicVerificationKey::ecdsaBrainpoolP384r1(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
        };

        Ok(res)
    }
}

/// Elliptic Curve Integrated Encryption Scheme key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EciesKey {
    /// NistP 256 R1 key type.
    NistP256r1(EccPoint),
    /// Brainpool 256 R1 key type.
    BrainpoolP256r1(EccPoint),
}

/// Error for types conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EciesKeyError {
    /// Key type is unsupported.
    UnsupportedType,
    /// Key point coordinates type is unsupported.
    UnsupportedCoordinates(EccPointUnsupportedCoordinatesErr),
}

impl fmt::Display for EciesKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EciesKeyError::UnsupportedType => write!(f, "Unsupported key type"),
            EciesKeyError::UnsupportedCoordinates(e) => write!(f, "{}", e),
        }
    }
}

impl TryFrom<&BasePublicEncryptionKey> for EciesKey {
    type Error = EciesKeyError;

    fn try_from(value: &BasePublicEncryptionKey) -> Result<Self, Self::Error> {
        let res = match value {
            BasePublicEncryptionKey::eciesNistP256(k) => EciesKey::NistP256r1(
                EccPoint::try_from(k).map_err(EciesKeyError::UnsupportedCoordinates)?,
            ),
            BasePublicEncryptionKey::eciesBrainpoolP256r1(k) => EciesKey::BrainpoolP256r1(
                EccPoint::try_from(k).map_err(EciesKeyError::UnsupportedCoordinates)?,
            ),
            _ => return Err(EciesKeyError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryInto<BasePublicEncryptionKey> for EciesKey {
    type Error = EciesKeyError;

    fn try_into(self) -> Result<BasePublicEncryptionKey, Self::Error> {
        let res = match self {
            EciesKey::NistP256r1(p) => BasePublicEncryptionKey::eciesNistP256(
                p.try_into()
                    .map_err(EciesKeyError::UnsupportedCoordinates)?,
            ),
            EciesKey::BrainpoolP256r1(p) => BasePublicEncryptionKey::eciesBrainpoolP256r1(
                p.try_into()
                    .map_err(EciesKeyError::UnsupportedCoordinates)?,
            ),
        };

        Ok(res)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Representation of an uncompressed ECC point.
pub struct UncompressedEccPoint {
    /// X coordinate of the point on the curve.
    pub x: Vec<u8>,
    /// Y coordinate of the point on the curve.
    pub y: Vec<u8>,
}

/// Secret key type, stored as uncompressed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecretKey(pub Vec<u8>);

/// Public key type, stored as uncompressed ECC point coordinates.
/// See [UncompressedEccPoint].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublicKey(pub UncompressedEccPoint);

pub type KeyPair = (SecretKey, PublicKey);
