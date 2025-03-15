use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};
use veloce_asn1::{
    defs::{
        etsi_102941_v221::ieee1609_dot2_base_types::{
            EccP256CurvePoint as Etsi102941EccP256CurvePoint,
            EccP256CurvePointUncompressedP256 as Etsi102941EccP256CurvePointUncompressedP256,
            EccP384CurvePoint as Etsi102941EccP384CurvePoint,
            EccP384CurvePointUncompressedP384 as Etsi102941EccP384CurvePointUncompressedP384,
            PublicVerificationKey as Etsi102941PublicVerificationKey,
        },
        etsi_103097_v211::{
            ieee1609_dot2::{EncryptedDataEncryptionKey, IssuerIdentifier},
            ieee1609_dot2_base_types::{
                self, BasePublicEncryptionKey, EccP256CurvePoint as Etsi103097EccP256CurvePoint,
                EccP256CurvePointUncompressedP256 as Etsi103097EccP256CurvePointUncompressedP256,
                EccP384CurvePoint as Etsi103097EccP384CurvePoint,
                EccP384CurvePointUncompressedP384 as Etsi103097EccP384CurvePointUncompressedP384,
                EciesP256EncryptedKey, HashAlgorithm as EtsiHashAlgorithm,
                PublicVerificationKey as Etsi103097PublicVerificationKey,
            },
        },
    },
    prelude::rasn::types::FixedOctetString,
};

pub mod backend;
pub mod certificate;
mod certificate_cache;
pub mod ciphertext;
pub mod permission;
#[cfg(feature = "pki")]
pub mod pki;
pub mod secured_message;
pub mod service;
pub mod signature;
pub mod ssp;
pub mod trust_chain;
pub mod trust_store;

#[cfg(test)]
mod tests;

#[cfg(feature = "security-openssl")]
pub use backend::openssl::{OpensslBackend, OpensslBackendConfig};

pub use backend::Backend as SecurityBackend;

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
    /// SM3 Hash algorithm.
    SM3,
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

impl TryInto<EtsiHashAlgorithm> for HashAlgorithm {
    type Error = HashAlgorithmUnsupportedError;

    fn try_into(self) -> Result<EtsiHashAlgorithm, Self::Error> {
        let res = match self {
            HashAlgorithm::SHA256 => EtsiHashAlgorithm::sha256,
            HashAlgorithm::SHA384 => EtsiHashAlgorithm::sha384,
            _ => return Err(HashAlgorithmUnsupportedError),
        };

        Ok(res)
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
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

impl From<&ieee1609_dot2_base_types::HashedId8> for HashedId8 {
    fn from(value: &ieee1609_dot2_base_types::HashedId8) -> Self {
        Self::from_bytes(value.0.as_slice())
    }
}

impl From<HashedId8> for ieee1609_dot2_base_types::HashedId8 {
    fn from(value: HashedId8) -> Self {
        let hash = value.as_bytes();
        Self(FixedOctetString::<8>::new(hash))
    }
}

impl From<HashedId8> for ieee1609_dot2_base_types::HashedId3 {
    fn from(value: HashedId8) -> Self {
        let hash = value.as_bytes();
        Self(FixedOctetString::<3>::new([hash[5], hash[6], hash[7]]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Elliptic curve key type.
pub enum EcKeyType {
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

impl TryFrom<&Etsi103097EccP256CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_from(value: &Etsi103097EccP256CurvePoint) -> Result<Self, Self::Error> {
        let res = match value {
            Etsi103097EccP256CurvePoint::x_only(p) => Self::XCoordinateOnly(p.to_vec()),
            Etsi103097EccP256CurvePoint::compressed_y_0(p) => Self::CompressedY0(p.to_vec()),
            Etsi103097EccP256CurvePoint::compressed_y_1(p) => Self::CompressedY1(p.to_vec()),
            Etsi103097EccP256CurvePoint::uncompressedP256(p) => {
                Self::Uncompressed(UncompressedEccPoint {
                    x: p.x.to_vec(),
                    y: p.y.to_vec(),
                })
            }
            _ => return Err(EccPointUnsupportedCoordinatesErr),
        };

        Ok(res)
    }
}

impl TryFrom<&Etsi102941EccP256CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_from(value: &Etsi102941EccP256CurvePoint) -> Result<Self, Self::Error> {
        let res = match value {
            Etsi102941EccP256CurvePoint::x_only(p) => Self::XCoordinateOnly(p.to_vec()),
            Etsi102941EccP256CurvePoint::compressed_y_0(p) => Self::CompressedY0(p.to_vec()),
            Etsi102941EccP256CurvePoint::compressed_y_1(p) => Self::CompressedY1(p.to_vec()),
            Etsi102941EccP256CurvePoint::uncompressedP256(p) => {
                Self::Uncompressed(UncompressedEccPoint {
                    x: p.x.to_vec(),
                    y: p.y.to_vec(),
                })
            }
            _ => return Err(EccPointUnsupportedCoordinatesErr),
        };

        Ok(res)
    }
}

impl TryFrom<&Etsi103097EccP384CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_from(value: &Etsi103097EccP384CurvePoint) -> Result<Self, Self::Error> {
        let res = match value {
            Etsi103097EccP384CurvePoint::x_only(p) => Self::XCoordinateOnly(p.to_vec()),
            Etsi103097EccP384CurvePoint::compressed_y_0(p) => Self::CompressedY0(p.to_vec()),
            Etsi103097EccP384CurvePoint::compressed_y_1(p) => Self::CompressedY1(p.to_vec()),
            Etsi103097EccP384CurvePoint::uncompressedP384(p) => {
                Self::Uncompressed(UncompressedEccPoint {
                    x: p.x.to_vec(),
                    y: p.y.to_vec(),
                })
            }
            _ => return Err(EccPointUnsupportedCoordinatesErr),
        };

        Ok(res)
    }
}

impl TryFrom<&Etsi102941EccP384CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_from(value: &Etsi102941EccP384CurvePoint) -> Result<Self, Self::Error> {
        let res = match value {
            Etsi102941EccP384CurvePoint::x_only(p) => Self::XCoordinateOnly(p.to_vec()),
            Etsi102941EccP384CurvePoint::compressed_y_0(p) => Self::CompressedY0(p.to_vec()),
            Etsi102941EccP384CurvePoint::compressed_y_1(p) => Self::CompressedY1(p.to_vec()),
            Etsi102941EccP384CurvePoint::uncompressedP384(p) => {
                Self::Uncompressed(UncompressedEccPoint {
                    x: p.x.to_vec(),
                    y: p.y.to_vec(),
                })
            }
            _ => return Err(EccPointUnsupportedCoordinatesErr),
        };

        Ok(res)
    }
}

impl TryInto<Etsi103097EccP256CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_into(self) -> Result<Etsi103097EccP256CurvePoint, Self::Error> {
        let res = match self {
            EccPoint::XCoordinateOnly(c) => {
                Etsi103097EccP256CurvePoint::x_only(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY0(c) => {
                Etsi103097EccP256CurvePoint::compressed_y_0(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY1(c) => {
                Etsi103097EccP256CurvePoint::compressed_y_1(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::Uncompressed(c) => Etsi103097EccP256CurvePoint::uncompressedP256(
                Etsi103097EccP256CurvePointUncompressedP256 {
                    x: FixedOctetString::<32>::new(
                        c.x.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                    y: FixedOctetString::<32>::new(
                        c.y.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                },
            ),
        };

        Ok(res)
    }
}

impl TryInto<Etsi102941EccP256CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_into(self) -> Result<Etsi102941EccP256CurvePoint, Self::Error> {
        let res = match self {
            EccPoint::XCoordinateOnly(c) => {
                Etsi102941EccP256CurvePoint::x_only(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY0(c) => {
                Etsi102941EccP256CurvePoint::compressed_y_0(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY1(c) => {
                Etsi102941EccP256CurvePoint::compressed_y_1(FixedOctetString::<32>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::Uncompressed(c) => Etsi102941EccP256CurvePoint::uncompressedP256(
                Etsi102941EccP256CurvePointUncompressedP256 {
                    x: FixedOctetString::<32>::new(
                        c.x.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                    y: FixedOctetString::<32>::new(
                        c.y.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                },
            ),
        };

        Ok(res)
    }
}

impl TryInto<Etsi103097EccP384CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_into(self) -> Result<Etsi103097EccP384CurvePoint, Self::Error> {
        let res = match self {
            EccPoint::XCoordinateOnly(c) => {
                Etsi103097EccP384CurvePoint::x_only(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY0(c) => {
                Etsi103097EccP384CurvePoint::compressed_y_0(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY1(c) => {
                Etsi103097EccP384CurvePoint::compressed_y_1(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::Uncompressed(c) => Etsi103097EccP384CurvePoint::uncompressedP384(
                Etsi103097EccP384CurvePointUncompressedP384 {
                    x: FixedOctetString::<48>::new(
                        c.x.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                    y: FixedOctetString::<48>::new(
                        c.y.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                },
            ),
        };

        Ok(res)
    }
}

impl TryInto<Etsi102941EccP384CurvePoint> for EccPoint {
    type Error = EccPointUnsupportedCoordinatesErr;

    fn try_into(self) -> Result<Etsi102941EccP384CurvePoint, Self::Error> {
        let res = match self {
            EccPoint::XCoordinateOnly(c) => {
                Etsi102941EccP384CurvePoint::x_only(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY0(c) => {
                Etsi102941EccP384CurvePoint::compressed_y_0(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::CompressedY1(c) => {
                Etsi102941EccP384CurvePoint::compressed_y_1(FixedOctetString::<48>::new(
                    c.try_into()
                        .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                ))
            }
            EccPoint::Uncompressed(c) => Etsi102941EccP384CurvePoint::uncompressedP384(
                Etsi102941EccP384CurvePointUncompressedP384 {
                    x: FixedOctetString::<48>::new(
                        c.x.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                    y: FixedOctetString::<48>::new(
                        c.y.try_into()
                            .map_err(|_| EccPointUnsupportedCoordinatesErr)?,
                    ),
                },
            ),
        };

        Ok(res)
    }
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
    /// Sm2 key type.
    Sm2(EccPoint),
}

impl EcdsaKey {
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            EcdsaKey::NistP256r1(_) | EcdsaKey::BrainpoolP256r1(_) => HashAlgorithm::SHA256,
            EcdsaKey::NistP384r1(_) | EcdsaKey::BrainpoolP384r1(_) => HashAlgorithm::SHA384,
            EcdsaKey::Sm2(_) => HashAlgorithm::SM3,
        }
    }
}

impl TryFrom<&Etsi103097PublicVerificationKey> for EcdsaKey {
    type Error = EcdsaKeyError;

    fn try_from(value: &Etsi103097PublicVerificationKey) -> Result<Self, Self::Error> {
        let res = match value {
            Etsi103097PublicVerificationKey::ecdsaNistP256(k) => EcdsaKey::NistP256r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            Etsi103097PublicVerificationKey::ecdsaNistP384(k) => EcdsaKey::NistP384r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            Etsi103097PublicVerificationKey::ecdsaBrainpoolP256r1(k) => EcdsaKey::BrainpoolP256r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            Etsi103097PublicVerificationKey::ecdsaBrainpoolP384r1(k) => EcdsaKey::BrainpoolP384r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            _ => return Err(EcdsaKeyError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryFrom<&Etsi102941PublicVerificationKey> for EcdsaKey {
    type Error = EcdsaKeyError;

    fn try_from(value: &Etsi102941PublicVerificationKey) -> Result<Self, Self::Error> {
        let res = match value {
            Etsi102941PublicVerificationKey::ecdsaNistP256(k) => EcdsaKey::NistP256r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            Etsi102941PublicVerificationKey::ecdsaNistP384(k) => EcdsaKey::NistP384r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            Etsi102941PublicVerificationKey::ecdsaBrainpoolP256r1(k) => EcdsaKey::BrainpoolP256r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            Etsi102941PublicVerificationKey::ecdsaBrainpoolP384r1(k) => EcdsaKey::BrainpoolP384r1(
                EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            Etsi102941PublicVerificationKey::ecsigSm2(k) => {
                EcdsaKey::Sm2(EccPoint::try_from(k).map_err(EcdsaKeyError::UnsupportedCoordinates)?)
            }
            _ => return Err(EcdsaKeyError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryInto<Etsi103097PublicVerificationKey> for EcdsaKey {
    type Error = EcdsaKeyError;

    fn try_into(self) -> Result<Etsi103097PublicVerificationKey, Self::Error> {
        let res = match self {
            EcdsaKey::NistP256r1(p) => Etsi103097PublicVerificationKey::ecdsaNistP256(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::NistP384r1(p) => Etsi103097PublicVerificationKey::ecdsaNistP384(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::BrainpoolP256r1(p) => Etsi103097PublicVerificationKey::ecdsaBrainpoolP256r1(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::BrainpoolP384r1(p) => Etsi103097PublicVerificationKey::ecdsaBrainpoolP384r1(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            _ => return Err(EcdsaKeyError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryInto<Etsi102941PublicVerificationKey> for EcdsaKey {
    type Error = EcdsaKeyError;

    fn try_into(self) -> Result<Etsi102941PublicVerificationKey, Self::Error> {
        let res = match self {
            EcdsaKey::NistP256r1(p) => Etsi102941PublicVerificationKey::ecdsaNistP256(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::NistP384r1(p) => Etsi102941PublicVerificationKey::ecdsaNistP384(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::BrainpoolP256r1(p) => Etsi102941PublicVerificationKey::ecdsaBrainpoolP256r1(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::BrainpoolP384r1(p) => Etsi102941PublicVerificationKey::ecdsaBrainpoolP384r1(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            EcdsaKey::Sm2(p) => Etsi102941PublicVerificationKey::ecsigSm2(
                p.try_into()
                    .map_err(EcdsaKeyError::UnsupportedCoordinates)?,
            ),
            //_ => return Err(EcdsaKeyError::UnsupportedType),
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

impl EciesKey {
    /// Get the hash algorithm to use for the key type.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            EciesKey::NistP256r1(_) | EciesKey::BrainpoolP256r1(_) => HashAlgorithm::SHA256,
        }
    }

    /// Get the key type.
    pub fn key_type(&self) -> EcKeyType {
        match self {
            EciesKey::NistP256r1(_) => EcKeyType::NistP256r1,
            EciesKey::BrainpoolP256r1(_) => EcKeyType::BrainpoolP256r1,
        }
    }
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

/// Encrypted Elliptic Curve Integrated Encryption Scheme key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EncryptedEciesKey {
    /// Encrypted NistP 256 R1 key type.
    NistP256r1(EncryptedEciesKeyParams),
    /// Encrypted Brainpool 256 R1 key type.
    BrainpoolP256r1(EncryptedEciesKeyParams),
}

impl EncryptedEciesKey {
    /// Constructs a new [EncryptedEciesKey] from a `public_key`, `encrypted_key` and an authentication `tag`.
    pub fn new(public_key: EciesKey, encrypted_key: Vec<u8>, tag: Vec<u8>) -> Self {
        match public_key {
            EciesKey::NistP256r1(ephemeral_public_key) => {
                EncryptedEciesKey::NistP256r1(EncryptedEciesKeyParams {
                    ephemeral_public_key,
                    encrypted_key,
                    tag,
                })
            }
            EciesKey::BrainpoolP256r1(ephemeral_public_key) => {
                EncryptedEciesKey::BrainpoolP256r1(EncryptedEciesKeyParams {
                    ephemeral_public_key,
                    encrypted_key,
                    tag,
                })
            }
        }
    }

    /// Get the public key of the encrypted key.
    pub fn public_key(&self) -> EciesKey {
        match self {
            EncryptedEciesKey::NistP256r1(p) => {
                EciesKey::NistP256r1(p.ephemeral_public_key.clone())
            }
            EncryptedEciesKey::BrainpoolP256r1(p) => {
                EciesKey::BrainpoolP256r1(p.ephemeral_public_key.clone())
            }
        }
    }

    /// Get the hash algorithm of the encrypted key.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            EncryptedEciesKey::NistP256r1(_) | EncryptedEciesKey::BrainpoolP256r1(_) => {
                HashAlgorithm::SHA256
            }
        }
    }
}

/// Error for types conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EncryptedEciesKeyError {
    /// Key type is unsupported.
    UnsupportedType,
    /// Key point coordinates type is unsupported.
    UnsupportedCoordinates(EccPointUnsupportedCoordinatesErr),
    /// Encrypted key size is incorrect.
    EncryptedKeySize,
    /// Authentication tag size is incorrect.
    AuthenticationTagSize,
}

impl fmt::Display for EncryptedEciesKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptedEciesKeyError::UnsupportedType => write!(f, "Unsupported key type"),
            EncryptedEciesKeyError::UnsupportedCoordinates(e) => write!(f, "{}", e),
            EncryptedEciesKeyError::EncryptedKeySize => write!(f, "incorrect encrypted key size"),
            EncryptedEciesKeyError::AuthenticationTagSize => {
                write!(f, "incorrect authentication tag size")
            }
        }
    }
}

impl TryFrom<&EncryptedDataEncryptionKey> for EncryptedEciesKey {
    type Error = EncryptedEciesKeyError;

    fn try_from(value: &EncryptedDataEncryptionKey) -> Result<Self, Self::Error> {
        let res = match value {
            EncryptedDataEncryptionKey::eciesNistP256(k) => {
                EncryptedEciesKey::NistP256r1(EncryptedEciesKeyParams {
                    ephemeral_public_key: EccPoint::try_from(&k.v)
                        .map_err(EncryptedEciesKeyError::UnsupportedCoordinates)?,
                    encrypted_key: k.c.to_vec(),
                    tag: k.t.to_vec(),
                })
            }
            EncryptedDataEncryptionKey::eciesBrainpoolP256r1(k) => {
                EncryptedEciesKey::BrainpoolP256r1(EncryptedEciesKeyParams {
                    ephemeral_public_key: EccPoint::try_from(&k.v)
                        .map_err(EncryptedEciesKeyError::UnsupportedCoordinates)?,
                    encrypted_key: k.c.to_vec(),
                    tag: k.t.to_vec(),
                })
            }
            _ => return Err(EncryptedEciesKeyError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryInto<EncryptedDataEncryptionKey> for EncryptedEciesKey {
    type Error = EncryptedEciesKeyError;

    fn try_into(self) -> Result<EncryptedDataEncryptionKey, Self::Error> {
        let res = match self {
            EncryptedEciesKey::NistP256r1(p) => {
                EncryptedDataEncryptionKey::eciesNistP256(EciesP256EncryptedKey {
                    v: p.ephemeral_public_key
                        .try_into()
                        .map_err(EncryptedEciesKeyError::UnsupportedCoordinates)?,
                    c: p.encrypted_key
                        .try_into()
                        .map_err(|_| EncryptedEciesKeyError::EncryptedKeySize)?,
                    t: p.tag
                        .try_into()
                        .map_err(|_| EncryptedEciesKeyError::AuthenticationTagSize)?,
                })
            }
            EncryptedEciesKey::BrainpoolP256r1(p) => {
                EncryptedDataEncryptionKey::eciesBrainpoolP256r1(EciesP256EncryptedKey {
                    v: p.ephemeral_public_key
                        .try_into()
                        .map_err(EncryptedEciesKeyError::UnsupportedCoordinates)?,
                    c: p.encrypted_key
                        .try_into()
                        .map_err(|_| EncryptedEciesKeyError::EncryptedKeySize)?,
                    t: p.tag
                        .try_into()
                        .map_err(|_| EncryptedEciesKeyError::AuthenticationTagSize)?,
                })
            }
        };

        Ok(res)
    }
}

/// Encrypted Elliptic Curve Integrated Encryption Scheme parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedEciesKeyParams {
    /// Sender ephemeral public key.
    pub ephemeral_public_key: EccPoint,
    /// Encrypted symmetric key.
    pub encrypted_key: Vec<u8>,
    /// Authentication tag.
    pub tag: Vec<u8>,
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

#[derive(Debug)]
/// Representation of an uncompressed ECC point.
pub struct KeyPair<S, P> {
    /// Secret key part of the keypair.
    pub secret: S,
    /// Public key part of the keypair.
    pub public: P,
}
