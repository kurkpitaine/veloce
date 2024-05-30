use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    md_ctx::MdCtx,
    nid::Nid,
    pkey::{PKey, Private},
    sha, symm,
};
use std::{fs::File, io::Write};

use super::{Backend, BackendError, BackendResult};
use crate::security::{
    signature::EcdsaSignature, EccPoint, EcdsaKeyType, KeyPair, PublicKey, SecretKey,
    UncompressedEccPoint, VerificationKey,
};

pub struct OpensslBackendConfig {
    /// Canonical secret key path.
    pub canonical_key_path: String,
    /// Canonical key password.
    pub canonical_key_passwd: String,
}

pub struct OpensslBackend {
    /// Backend configuration.
    config: OpensslBackendConfig,
}

impl OpensslBackend {
    /// Constructs a new [OpensslBackend] with the provided `config`.
    pub fn new(config: OpensslBackendConfig) -> Self {
        Self { config }
    }

    /// Generate a secret key for a given `key_type`.
    fn generate_secret_key(key_type: EcdsaKeyType) -> Result<EcKey<Private>, ErrorStack> {
        let nid = match key_type {
            EcdsaKeyType::NistP256r1 => Nid::X9_62_PRIME256V1,
            EcdsaKeyType::NistP384r1 => Nid::SECP384R1,
            EcdsaKeyType::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            EcdsaKeyType::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
        };

        let group = EcGroup::from_curve_name(nid)?;
        EcKey::generate(&group)
    }

    /// Extracts the public key for a given `private_key`. Returns a tuple as (x,y) coordinates.
    fn extract_public_key(secret_key: &EcKey<Private>) -> Result<(BigNum, BigNum), ErrorStack> {
        let mut ctx = BigNumContext::new()?;
        let (mut x, mut y) = (BigNum::new()?, BigNum::new()?);

        secret_key
            .public_key()
            .affine_coordinates(secret_key.group(), &mut x, &mut y, &mut ctx)?;

        Ok((x, y))
    }
}

impl Backend for OpensslBackend {
    fn generate_keypair(&self, key_type: EcdsaKeyType) -> BackendResult<KeyPair> {
        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let (x, y) =
            OpensslBackend::extract_public_key(&secret_key).map_err(BackendError::OpenSSL)?;

        Ok((
            SecretKey(secret_key.private_key().to_vec()),
            PublicKey(UncompressedEccPoint {
                x: x.to_vec(),
                y: y.to_vec(),
            }),
        ))
    }

    fn generate_canonical_keypair(&self, key_type: EcdsaKeyType) -> BackendResult<PublicKey> {
        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let (x, y) =
            OpensslBackend::extract_public_key(&secret_key).map_err(BackendError::OpenSSL)?;

        let content = secret_key
            .private_key_to_pem_passphrase(
                symm::Cipher::chacha20_poly1305(),
                self.config.canonical_key_passwd.as_bytes(),
            )
            .map_err(BackendError::OpenSSL)?;

        let mut file = File::create(&self.config.canonical_key_path).map_err(BackendError::Io)?;
        file.write_all(&content).map_err(BackendError::Io)?;
        file.sync_all().map_err(BackendError::Io)?;

        Ok(PublicKey(UncompressedEccPoint {
            x: x.to_vec(),
            y: y.to_vec(),
        }))
    }

    fn verify_signature(
        &self,
        signature: EcdsaSignature,
        verification_key: VerificationKey,
        data: &[u8],
    ) -> BackendResult<bool> {
        let (nid, point, signature) = match (verification_key, signature) {
            (VerificationKey::NistP256r1(p), EcdsaSignature::NistP256r1(s)) => {
                (Nid::X9_62_PRIME256V1, p, s)
            }
            (VerificationKey::NistP384r1(p), EcdsaSignature::NistP384r1(s)) => {
                (Nid::SECP384R1, p, s)
            }
            (VerificationKey::BrainpoolP256r1(p), EcdsaSignature::BrainpoolP256r1(s)) => {
                (Nid::BRAINPOOL_P256R1, p, s)
            }
            (VerificationKey::BrainpoolP384r1(p), EcdsaSignature::BrainpoolP384r1(s)) => {
                (Nid::BRAINPOOL_P384R1, p, s)
            }
            _ => return Err(BackendError::AlgorithmMismatch),
        };

        let group = EcGroup::from_curve_name(nid).map_err(BackendError::OpenSSL)?;

        let mut ctx = BigNumContext::new().map_err(BackendError::OpenSSL)?;
        let ec_point = match point {
            EccPoint::CompressedY0(c) => {
                // According to SEC1, Y0 starts with 02.
                let buf = [vec![0x02], c].concat();
                EcPoint::from_bytes(&group, &buf, &mut ctx).map_err(BackendError::OpenSSL)?
            }
            EccPoint::CompressedY1(c) => {
                // According to SEC1, Y1 starts with 03.
                let buf = [vec![0x03], c].concat();
                EcPoint::from_bytes(&group, &buf, &mut ctx).map_err(BackendError::OpenSSL)?
            }
            EccPoint::Uncompressed(c) => {
                let x = BigNum::from_slice(&c.x).map_err(BackendError::OpenSSL)?;
                let y = BigNum::from_slice(&c.y).map_err(BackendError::OpenSSL)?;
                let mut pub_key = EcPoint::new(&group).map_err(BackendError::OpenSSL)?;
                pub_key
                    .set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
                    .map_err(BackendError::OpenSSL)?;
                pub_key
            }
            _ => unreachable!(),
        };

        if !ec_point
            .is_on_curve(&group, &mut ctx)
            .map_err(BackendError::OpenSSL)?
        {
            return Err(BackendError::NotOnCurve);
        }

        let key = EcKey::from_public_key(&group, &ec_point).map_err(BackendError::OpenSSL)?;
        key.check_key().map_err(|_| BackendError::InvalidKey)?;

        let r = match signature.r {
            EccPoint::XCoordinateOnly(c) => c,
            EccPoint::CompressedY0(c) => c,
            EccPoint::CompressedY1(c) => c,
            EccPoint::Uncompressed(c) => c.x,
        };
        let r = BigNum::from_slice(&r).map_err(BackendError::OpenSSL)?;
        let s = BigNum::from_slice(&signature.s).map_err(BackendError::OpenSSL)?;
        let signature = EcdsaSig::from_private_components(r, s).map_err(BackendError::OpenSSL)?;

        let res = signature
            .verify(data, &key)
            .map_err(BackendError::OpenSSL)?;

        Ok(res)
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha::sha256(data)
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        sha::sha384(data)
    }
}
