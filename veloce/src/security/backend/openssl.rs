use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sha,
    sign::Verifier,
    symm,
};
use std::{fs::File, io::Write};

use super::{Backend, BackendError, BackendResult};
use crate::security::{
    signature::EcdsaSignature, EccPoint, EcdsaKey, EcdsaKeyType, EciesKey, HashAlgorithm, KeyPair,
    PublicKey, SecretKey, UncompressedEccPoint,
};

#[derive(Debug, Default)]
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

    fn compress_ecc_point(&self, point: EccPoint, nid: Nid) -> BackendResult<EccPoint> {
        let group = EcGroup::from_curve_name(nid).map_err(BackendError::OpenSSL)?;
        let mut ctx = BigNumContext::new().map_err(BackendError::OpenSSL)?;

        let ec_point = match point {
            // Already compressed form.
            EccPoint::XCoordinateOnly(c) => return Err(BackendError::UnsupportedCompression),
            EccPoint::CompressedY0(_) | EccPoint::CompressedY1(_) => return Ok(point),
            EccPoint::Uncompressed(c) => {
                let x = BigNum::from_slice(&c.x).map_err(BackendError::OpenSSL)?;
                let y = BigNum::from_slice(&c.y).map_err(BackendError::OpenSSL)?;
                let mut ec_point = EcPoint::new(&group).map_err(BackendError::OpenSSL)?;
                ec_point
                    .set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
                    .map_err(BackendError::OpenSSL)?;
                ec_point
            }
        };

        if !ec_point
            .is_on_curve(&group, &mut ctx)
            .map_err(BackendError::OpenSSL)?
        {
            return Err(BackendError::NotOnCurve);
        }

        let ec_key = EcKey::from_public_key(&group, &ec_point).map_err(BackendError::OpenSSL)?;
        ec_key.check_key().map_err(|_| BackendError::InvalidKey)?;

        let bytes = ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .map_err(BackendError::OpenSSL)?;

        let res = match bytes[0] {
            0x02 => EccPoint::CompressedY0(bytes[1..].to_vec()),
            0x03 => EccPoint::CompressedY1(bytes[1..].to_vec()),
            _ => return Err(BackendError::InternalError),
        };

        Ok(res)
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
        verification_key: EcdsaKey,
        data: &[u8],
    ) -> BackendResult<bool> {
        let msg_digest = match signature.hash_algorithm() {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
        };

        let (nid, point, signature) = match (verification_key, signature) {
            (EcdsaKey::NistP256r1(p), EcdsaSignature::NistP256r1(s)) => {
                (Nid::X9_62_PRIME256V1, p, s)
            }
            (EcdsaKey::NistP384r1(p), EcdsaSignature::NistP384r1(s)) => (Nid::SECP384R1, p, s),
            (EcdsaKey::BrainpoolP256r1(p), EcdsaSignature::BrainpoolP256r1(s)) => {
                (Nid::BRAINPOOL_P256R1, p, s)
            }
            (EcdsaKey::BrainpoolP384r1(p), EcdsaSignature::BrainpoolP384r1(s)) => {
                (Nid::BRAINPOOL_P384R1, p, s)
            }
            _ => return Err(BackendError::AlgorithmMismatch),
        };

        let group = EcGroup::from_curve_name(nid).map_err(BackendError::OpenSSL)?;

        let mut ctx = BigNumContext::new().map_err(BackendError::OpenSSL)?;
        let ec_point = match point {
            EccPoint::CompressedY0(c) => {
                // According to SECG SEC1 paragraph 2.3.4, Y0 starts with 02.
                let buf = [vec![0x02], c].concat();
                EcPoint::from_bytes(&group, &buf, &mut ctx).map_err(BackendError::OpenSSL)?
            }
            EccPoint::CompressedY1(c) => {
                // According to SECG SEC1 paragraph 2.3.4, Y1 starts with 03.
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

        /* let mut bn_ctx = BigNumContext::new().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        ec_point
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .unwrap();

        println!("data: {:02x?}", data);
        println!("x: {:02x?}", x.to_vec());
        println!("y: {:02x?}", y.to_vec()); */

        let ec_key = EcKey::from_public_key(&group, &ec_point).map_err(BackendError::OpenSSL)?;
        ec_key.check_key().map_err(|_| BackendError::InvalidKey)?;

        let key = PKey::from_ec_key(ec_key).map_err(BackendError::OpenSSL)?;

        let r = match signature.r {
            EccPoint::XCoordinateOnly(c) => c,
            EccPoint::CompressedY0(c) => c,
            EccPoint::CompressedY1(c) => c,
            EccPoint::Uncompressed(c) => c.x,
        };
        let r = BigNum::from_slice(&r).map_err(BackendError::OpenSSL)?;
        let s = BigNum::from_slice(&signature.s).map_err(BackendError::OpenSSL)?;

        /* println!("r: {:02x?}", r.to_vec());
        println!("s: {:02x?}", s.to_vec()); */

        let mut verifier = Verifier::new(msg_digest, &key).map_err(BackendError::OpenSSL)?;
        verifier.update(data).map_err(BackendError::OpenSSL)?;

        let signature = EcdsaSig::from_private_components(r, s).map_err(BackendError::OpenSSL)?;
        let sig_der = signature.to_der().map_err(BackendError::OpenSSL)?;

        Ok(verifier.verify(&sig_der).map_err(BackendError::OpenSSL)?)
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha::sha256(data)
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        sha::sha384(data)
    }

    fn compress_ecies_key(&self, key: EciesKey) -> BackendResult<EciesKey> {
        let res = match key {
            EciesKey::NistP256r1(p) => {
                EciesKey::NistP256r1(self.compress_ecc_point(p, Nid::X9_62_PRIME256V1)?)
            }
            EciesKey::BrainpoolP256r1(p) => {
                EciesKey::BrainpoolP256r1(self.compress_ecc_point(p, Nid::BRAINPOOL_P256R1)?)
            }
        };

        Ok(res)
    }

    fn compress_ecdsa_key(&self, key: EcdsaKey) -> BackendResult<EcdsaKey> {
        let res = match key {
            EcdsaKey::NistP256r1(p) => {
                EcdsaKey::NistP256r1(self.compress_ecc_point(p, Nid::X9_62_PRIME256V1)?)
            }
            EcdsaKey::NistP384r1(p) => {
                EcdsaKey::NistP384r1(self.compress_ecc_point(p, Nid::SECP384R1)?)
            }
            EcdsaKey::BrainpoolP256r1(p) => {
                EcdsaKey::BrainpoolP256r1(self.compress_ecc_point(p, Nid::BRAINPOOL_P256R1)?)
            }
            EcdsaKey::BrainpoolP384r1(p) => {
                EcdsaKey::BrainpoolP384r1(self.compress_ecc_point(p, Nid::BRAINPOOL_P384R1)?)
            }
        };

        Ok(res)
    }
}
