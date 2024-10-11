use core::fmt;

use veloce_asn1::defs::etsi_103097_v211::ieee1609_dot2_base_types::{
    EcdsaP256Signature, EcdsaP384Signature, Signature as EtsiSignature,
};

use super::{EccPoint, EccPointUnsupportedCoordinatesErr, HashAlgorithm};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EcdsaSignatureError {
    /// Signature type is unsupported.
    UnsupportedType,
    /// Signature point coordinates type is unsupported.
    UnsupportedCoordinates(EccPointUnsupportedCoordinatesErr),
    /// Other type of error
    Other,
}

impl fmt::Display for EcdsaSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcdsaSignatureError::UnsupportedType => write!(f, "unsupported signature type"),
            EcdsaSignatureError::UnsupportedCoordinates(e) => {
                write!(f, "unsupported signature coordinates: {}", e)
            }
            EcdsaSignatureError::Other => write!(f, "other error"),
        }
    }
}

/// An ECDSA signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EcdsaSignature {
    /// NistP 256 R1 key type based signature.
    NistP256r1(EcdsaSignatureInner),
    /// NistP 384 R1 key type based signature.
    NistP384r1(EcdsaSignatureInner),
    /// Brainpool 256 R1 key type based signature.
    BrainpoolP256r1(EcdsaSignatureInner),
    /// Brainpool 384 R1 key type based signature.
    BrainpoolP384r1(EcdsaSignatureInner),
}

impl EcdsaSignature {
    /// Get the hash algorithm of the signature.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            EcdsaSignature::NistP256r1(_) | EcdsaSignature::BrainpoolP256r1(_) => {
                HashAlgorithm::SHA256
            }
            EcdsaSignature::NistP384r1(_) | EcdsaSignature::BrainpoolP384r1(_) => {
                HashAlgorithm::SHA384
            }
        }
    }
}

impl TryFrom<&EtsiSignature> for EcdsaSignature {
    type Error = EcdsaSignatureError;

    fn try_from(value: &EtsiSignature) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiSignature::ecdsaNistP256Signature(s) => {
                EcdsaSignature::NistP256r1(EcdsaSignatureInner {
                    r: EccPoint::try_from(&s.r_sig)
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s: s.s_sig.to_vec(),
                })
            }
            EtsiSignature::ecdsaNistP384Signature(s) => {
                EcdsaSignature::NistP384r1(EcdsaSignatureInner {
                    r: EccPoint::try_from(&s.r_sig)
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s: s.s_sig.to_vec(),
                })
            }
            EtsiSignature::ecdsaBrainpoolP256r1Signature(s) => {
                EcdsaSignature::BrainpoolP256r1(EcdsaSignatureInner {
                    r: EccPoint::try_from(&s.r_sig)
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s: s.s_sig.to_vec(),
                })
            }
            EtsiSignature::ecdsaBrainpoolP384r1Signature(s) => {
                EcdsaSignature::BrainpoolP384r1(EcdsaSignatureInner {
                    r: EccPoint::try_from(&s.r_sig)
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s: s.s_sig.to_vec(),
                })
            }
            _ => return Err(EcdsaSignatureError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryInto<EtsiSignature> for EcdsaSignature {
    type Error = EcdsaSignatureError;

    fn try_into(self) -> Result<EtsiSignature, Self::Error> {
        let res = match self {
            EcdsaSignature::NistP256r1(i) => {
                EtsiSignature::ecdsaNistP256Signature(EcdsaP256Signature {
                    r_sig: i
                        .r
                        .try_into()
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s_sig: i.s.try_into().map_err(|_| EcdsaSignatureError::Other)?,
                })
            }
            EcdsaSignature::NistP384r1(i) => {
                EtsiSignature::ecdsaNistP384Signature(EcdsaP384Signature {
                    r_sig: i
                        .r
                        .try_into()
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s_sig: i.s.try_into().map_err(|_| EcdsaSignatureError::Other)?,
                })
            }
            EcdsaSignature::BrainpoolP256r1(i) => {
                EtsiSignature::ecdsaBrainpoolP256r1Signature(EcdsaP256Signature {
                    r_sig: i
                        .r
                        .try_into()
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s_sig: i.s.try_into().map_err(|_| EcdsaSignatureError::Other)?,
                })
            }
            EcdsaSignature::BrainpoolP384r1(i) => {
                EtsiSignature::ecdsaBrainpoolP384r1Signature(EcdsaP384Signature {
                    r_sig: i
                        .r
                        .try_into()
                        .map_err(EcdsaSignatureError::UnsupportedCoordinates)?,
                    s_sig: i.s.try_into().map_err(|_| EcdsaSignatureError::Other)?,
                })
            }
        };

        Ok(res)
    }
}

/// Inner representation of the ECDSA signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EcdsaSignatureInner {
    /// R component of the signature, see [EccPoint].
    pub r: EccPoint,
    /// S component of the signature.
    pub s: Vec<u8>,
}
