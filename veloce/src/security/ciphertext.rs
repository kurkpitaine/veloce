use core::fmt;

use veloce_asn1::{
    defs::etsi_103097_v211::{
        ieee1609_dot2::{
            AesCcmCiphertext as EtsiAesCcmCiphertext, SymmetricCiphertext as EtsiCiphertext,
        },
        ieee1609_dot2_base_types::Opaque as EtsiOpaque,
    },
    prelude::rasn::types::{FixedOctetString, OctetString},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CiphertextError {
    /// Ciphertext type is unsupported.
    UnsupportedType,
    /// Nonce content is unsupported, ie: length is not of the expected size.
    UnsupportedNonce,
}

impl fmt::Display for CiphertextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CiphertextError::UnsupportedType => write!(f, "Unsupported ciphertext type"),
            CiphertextError::UnsupportedNonce => write!(f, "Unsupported nonce"),
        }
    }
}

/// A ciphertext.
/// Stores the encrypted data and the nonce used to encrypt it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Ciphertext {
    /// AES-128 CCM ciphertext.
    Aes128Ccm(CiphertextInner),
}

impl Ciphertext {
    /// Create an AES-128 CCM ciphertext from `nonce` and `data`.
    pub fn new_aes_128_ccm(nonce: Vec<u8>, data: Vec<u8>) -> Self {
        Self::Aes128Ccm(CiphertextInner { nonce, data })
    }
}

/// Inner representation of the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CiphertextInner {
    /// Nonce used to encrypt the data.
    pub nonce: Vec<u8>,
    /// Encrypted data + tag at the tail.
    pub data: Vec<u8>,
}

impl TryFrom<&EtsiCiphertext> for Ciphertext {
    type Error = CiphertextError;

    fn try_from(value: &EtsiCiphertext) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiCiphertext::aes128ccm(aes_ccm_ciphertext) => {
                Ciphertext::Aes128Ccm(CiphertextInner {
                    nonce: aes_ccm_ciphertext.nonce.to_vec(),
                    data: aes_ccm_ciphertext.ccm_ciphertext.0.to_vec(),
                })
            }
            _ => return Err(CiphertextError::UnsupportedType),
        };

        Ok(res)
    }
}

impl TryInto<EtsiCiphertext> for Ciphertext {
    type Error = CiphertextError;

    fn try_into(self) -> Result<EtsiCiphertext, Self::Error> {
        let res = match self {
            Ciphertext::Aes128Ccm(inner) => EtsiCiphertext::aes128ccm(EtsiAesCcmCiphertext {
                nonce: FixedOctetString::<12>::new(
                    inner
                        .nonce
                        .try_into()
                        .map_err(|_| CiphertextError::UnsupportedNonce)?,
                ),
                ccm_ciphertext: EtsiOpaque(OctetString::from(inner.data)),
            }),
        };

        Ok(res)
    }
}
