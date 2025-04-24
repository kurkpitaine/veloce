use core::fmt;

use veloce_asn1::{
    defs::etsi_103097_v211::ieee1609_dot2::{self, HashedData as EtsiHashedData},
    prelude::rasn::types::FixedOctetString,
};

use crate::security::{backend::BackendTrait, EcdsaKey, EciesKey, HashAlgorithm, HashedId8};

pub mod asn1_wrapper;
pub mod encrypted_data;
pub mod message;
pub mod service;
pub mod signed_data;

/// AES 128 bit key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Aes128Key(pub [u8; 16]);

/// Signer identifier error.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SignerIdentifierError {
    /// Unsupported signer identifier.
    UnsupportedSignerIdentifier,
}

impl fmt::Display for SignerIdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerIdentifierError::UnsupportedSignerIdentifier => {
                write!(f, "unsupported signer identifier")
            }
        }
    }
}

/// Signer identifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignerIdentifier {
    /// Signer identifier is self-signed.
    SelfSigned,
    /// Signer identifier is a certificate digest.
    Digest(HashedId8),
}

impl fmt::Display for SignerIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerIdentifier::SelfSigned => write!(f, "SelfSigned"),
            SignerIdentifier::Digest(h) => write!(f, "Digest({})", h),
        }
    }
}

impl TryFrom<&ieee1609_dot2::SignerIdentifier> for SignerIdentifier {
    type Error = SignerIdentifierError;

    fn try_from(signer_id: &ieee1609_dot2::SignerIdentifier) -> Result<Self, Self::Error> {
        let res = match signer_id {
            ieee1609_dot2::SignerIdentifier::digest(digest) => {
                SignerIdentifier::Digest(digest.into())
            }
            ieee1609_dot2::SignerIdentifier::R_self(_) => SignerIdentifier::SelfSigned,
            _ => return Err(SignerIdentifierError::UnsupportedSignerIdentifier),
        };

        Ok(res)
    }
}

impl From<SignerIdentifier> for ieee1609_dot2::SignerIdentifier {
    fn from(value: SignerIdentifier) -> Self {
        match value {
            SignerIdentifier::Digest(digest) => {
                ieee1609_dot2::SignerIdentifier::digest(digest.into())
            }
            SignerIdentifier::SelfSigned => ieee1609_dot2::SignerIdentifier::R_self(()),
        }
    }
}

/// Hashed data.
#[derive(Debug, Clone, PartialEq)]
pub enum HashedData {
    /// SHA-256 hashed data.
    SHA256(Vec<u8>),
    /// SHA-384 hashed data.
    SHA384(Vec<u8>),
    /// Reserved hashed data.
    Reserved(Vec<u8>),
}

/// Hashed data error.
pub struct UnsupportedHashedData;

impl TryFrom<&EtsiHashedData> for HashedData {
    type Error = UnsupportedHashedData;

    fn try_from(value: &EtsiHashedData) -> Result<Self, Self::Error> {
        let res = match value {
            EtsiHashedData::sha256HashedData(data) => HashedData::SHA256(data.to_vec()),
            EtsiHashedData::sha384HashedData(data) => HashedData::SHA384(data.to_vec()),
            EtsiHashedData::reserved(data) => HashedData::Reserved(data.to_vec()),
            _ => return Err(UnsupportedHashedData),
        };

        Ok(res)
    }
}

impl TryInto<EtsiHashedData> for HashedData {
    type Error = UnsupportedHashedData;

    fn try_into(self) -> Result<EtsiHashedData, Self::Error> {
        let res = match self {
            HashedData::SHA256(data) => EtsiHashedData::sha256HashedData(
                FixedOctetString::try_from(data).map_err(|_| UnsupportedHashedData)?,
            ),
            HashedData::SHA384(data) => EtsiHashedData::sha384HashedData(
                FixedOctetString::try_from(data).map_err(|_| UnsupportedHashedData)?,
            ),
            HashedData::Reserved(data) => EtsiHashedData::reserved(
                FixedOctetString::try_from(data).map_err(|_| UnsupportedHashedData)?,
            ),
        };

        Ok(res)
    }
}

/// Public keys to be included in a certificate request.
#[derive(Debug)]
pub struct IncludedPublicKeys {
    /// Public verification key.
    pub verification_key: EcdsaKey,
    /// Public encryption key.
    pub encryption_key: Option<EciesKey>,
}

/// Compute the key derivation function (KDF) as defined in ETSI TS 102 941 V2.2.1 annex F.
/// The ETSI standard omits the salt, but it is required by the PKI as the
/// [test suite](https://forge.etsi.org/rep/ITS/TS.ITS/-/blob/devel2/ccsrc/Protocols/Security/security_ecc.cc?ref_type=heads#L1143)
/// requires it.
pub fn kdf2<B>(
    key: &[u8],
    salt: &[u8],
    output_len: usize,
    hash_algorithm: HashAlgorithm,
    backend: &B,
) -> Vec<u8>
where
    B: BackendTrait + ?Sized,
{
    let num_iter = output_len.div_ceil(key.len());
    let mut res = Vec::with_capacity(key.len() * num_iter);

    match hash_algorithm {
        HashAlgorithm::SHA256 => {
            for i in 1..=num_iter {
                res.extend_from_slice(
                    &backend.sha256(&[key, &(i as u32).to_be_bytes(), salt].concat()),
                );
            }
        }
        HashAlgorithm::SHA384 => {
            for i in 1..=num_iter {
                res.extend_from_slice(
                    &backend.sha384(&[key, &(i as u32).to_be_bytes(), salt].concat()),
                );
            }
        }
        HashAlgorithm::SM3 => unimplemented!(),
    }

    res.truncate(output_len);
    res
}

#[test]
fn test_kdf2() {
    use crate::security::tests::{self};

    let base_path = tests::get_test_storage_path();
    let (_, backend) = tests::setup_storage_and_crypto(base_path);

    let key = [
        0x0d, 0xa7, 0x98, 0x18, 0x42, 0xf8, 0x26, 0x7e, 0xfe, 0x30, 0x59, 0xdb, 0x7a, 0xc6, 0x19,
        0xc9, 0x92, 0x9, 0xee, 0x98, 0xd1, 0x8c, 0x0b, 0x5, 0x52, 0x14, 0xfe, 0xe1, 0x3d, 0x21,
        0xf6, 0x71,
    ];
    let salt = [
        0x85, 0xd7, 0x24, 0xb0, 0x58, 0x30, 0xd5, 0x44, 0xc8, 0xb, 0x29, 0x4f, 0x1b, 0x5f, 0x89,
        0x1f, 0x78, 0x15, 0xb8, 0x66, 0xb4, 0xed, 0x86, 0x35, 0xe6, 0xf4, 0x22, 0x8d, 0xe0, 0x93,
        0xde, 0x4d,
    ];

    let res = kdf2(&key, &salt, 48, HashAlgorithm::SHA256, &backend);
    assert_eq!(
        res,
        [
            0x28, 0xfb, 0xd7, 0x03, 0x3b, 0xfa, 0xaf, 0x11, 0x67, 0x89, 0xa9, 0x55, 0xa6, 0x52,
            0x81, 0x49, 0xa8, 0x8b, 0x57, 0xdc, 0xb9, 0xb2, 0xc6, 0x99, 0xfc, 0x78, 0x12, 0x52,
            0x7e, 0xa3, 0xc9, 0xc5, 0x42, 0xb6, 0x3b, 0x96, 0xce, 0xe1, 0x40, 0x08, 0xb7, 0x41,
            0xdc, 0x75, 0xeb, 0x7a, 0x26, 0x10
        ]
    );
}
