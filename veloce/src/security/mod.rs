use veloce_asn1::defs::etsi_103097_v211::ieee1609Dot2Base_types::{
    EccP256CurvePoint, EccP384CurvePoint, PublicVerificationKey as EtsiVerificationKey,
};

pub mod aid;
pub mod backend;
pub mod certificate;
mod certificate_cache;
pub mod secured_message;
pub mod service;
pub mod signature;
pub mod ssp;
pub mod trust_chain;
pub mod trust_store;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
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

/// Public Verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum VerificationKey {
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
pub enum VerificationKeyError {
    /// Key type is unsupported.
    UnsupportedType,
    /// Key point coordinates type is unsupported.
    UnsupportedCoordinates(EccPointUnsupportedCoordinatesErr),
}

impl TryFrom<&EtsiVerificationKey> for VerificationKey {
    type Error = VerificationKeyError;

    fn try_from(value: &EtsiVerificationKey) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiVerificationKey::ecdsaNistP256(k) => VerificationKey::NistP256r1(
                EccPoint::try_from(k).map_err(VerificationKeyError::UnsupportedCoordinates)?,
            ),
            EtsiVerificationKey::ecdsaNistP384(k) => VerificationKey::NistP384r1(
                EccPoint::try_from(k).map_err(VerificationKeyError::UnsupportedCoordinates)?,
            ),
            EtsiVerificationKey::ecdsaBrainpoolP256r1(k) => VerificationKey::BrainpoolP256r1(
                EccPoint::try_from(k).map_err(VerificationKeyError::UnsupportedCoordinates)?,
            ),
            EtsiVerificationKey::ecdsaBrainpoolP384r1(k) => VerificationKey::BrainpoolP384r1(
                EccPoint::try_from(k).map_err(VerificationKeyError::UnsupportedCoordinates)?,
            ),
            _ => return Err(VerificationKeyError::UnsupportedType),
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
pub struct SecretKey(pub Vec<u8>);

/// Public key type, stored as uncompressed ECC point coordinates.
/// See [UncompressedEccPoint].
pub struct PublicKey(pub UncompressedEccPoint);

pub type KeyPair = (SecretKey, PublicKey);
