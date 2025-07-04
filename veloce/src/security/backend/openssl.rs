use openssl::{
    bn::{BigNum, BigNumContext},
    cipher::Cipher,
    cipher_ctx::CipherCtx,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::{self, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private, Public},
    sha,
    sign::{Signer, Verifier},
    symm,
};

#[cfg(feature = "pki")]
use openssl::{derive::Deriver, rand};

use regex::bytes::Regex;
use secrecy::{ExposeSecret, SecretString};
use std::{collections::HashMap, fmt, io, path::PathBuf, rc::Rc};

use super::{BackendError, BackendResult, BackendTrait};
use crate::security::{
    signature::{EcdsaSignature, EcdsaSignatureInner},
    DirectoryStorage, EcKeyType, EccPoint, EcdsaKey, EciesKey, HashAlgorithm,
};

#[cfg(feature = "pki")]
use crate::security::KeyPair;

#[cfg(feature = "pki")]
use super::PkiBackendTrait;

#[derive(Debug)]
pub struct OpensslBackendConfig {
    /// Secret keys password.
    pub keys_password: SecretString,
    /// Canonical key filename.
    canonical_key_filename: String,
    /// Enrollment credential key filename.
    ec_key_filename: String,
    /// AT keys filename prefix.
    at_key_filename_prefix: String,
}

impl OpensslBackendConfig {
    /// Constructs a new [OpensslBackendConfig] with the provided `keys_password` and `veloce_dir`.
    pub fn new(keys_password: SecretString) -> Self {
        Self {
            keys_password,
            ..Default::default()
        }
    }
}

impl Default for OpensslBackendConfig {
    fn default() -> Self {
        Self {
            keys_password: SecretString::new("".into()),
            canonical_key_filename: "canonical.pem".into(),
            ec_key_filename: "EC.pem".into(),
            at_key_filename_prefix: "AT_".into(),
        }
    }
}

type OpensslBackendResult<T> = core::result::Result<T, OpensslBackendError>;

/// Openssl Backend error types.
#[derive(Debug)]
pub enum OpensslBackendError {
    /// IO error.
    Io(io::Error),
    /// OpenSSL error.
    OpenSSL(openssl::error::ErrorStack),
    /// Regex error.
    Regex(regex::Error),
    /// Bad permissions. Expected value is the second parameter.
    BadPermissions(PathBuf, u32),
}

impl fmt::Display for OpensslBackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OpensslBackendError::Io(e) => write!(f, "io: {}", e),
            OpensslBackendError::OpenSSL(e) => write!(f, "openssl: {}", e),
            OpensslBackendError::Regex(e) => write!(f, "regex: {}", e),
            OpensslBackendError::BadPermissions(p, m) => {
                write!(f, "bad permissions, should be {:#o} on: {}", m, p.display())
            }
        }
    }
}

#[derive(Debug)]
#[allow(unused)]
pub struct OpensslBackend {
    /// Backend configuration.
    config: OpensslBackendConfig,
    /// Private storage provider.
    storage: Rc<DirectoryStorage>,
    /// Canonical secret key. Used to encrypt PKI related communications.
    canonical_secret_key: Option<EcKey<Private>>,
    /// EC certificate secret key.
    ec_cert_secret_key: Option<EcKey<Private>>,
    /// EC certificate re-keying secret key.
    ec_cert_rekeying_secret_key: Option<EcKey<Private>>,
    /// AT certificates secret keys. Used to sign the messages over the air.
    at_certs_secret_keys: HashMap<usize, EcKey<Private>>,
    /// Index of the current AT certificate secret key used for signing.
    current_at_id: Option<usize>,
}

impl OpensslBackend {
    /// Constructs a new [OpensslBackend] with the provided `config`.
    pub fn new(
        config: OpensslBackendConfig,
        storage: Rc<DirectoryStorage>,
    ) -> OpensslBackendResult<Self> {
        // Load canonical key if any.
        let canonical_secret_key = Self::load_secret_key(
            config.canonical_key_filename.clone(),
            &config.keys_password,
            &storage,
        )?;

        let exp = config.at_key_filename_prefix.clone() + "([0-9]+).pem";
        let regex = Regex::new(exp.as_str()).map_err(OpensslBackendError::Regex)?;

        let at_key_files: Vec<(String, usize)> = storage
            .list_private_files_where(|name| {
                let Some(caps) = regex.captures(name.as_bytes()) else {
                    return (false, 0);
                };

                let Some(id_m) = caps.get(1) else {
                    return (false, 0);
                };

                let Some(id_str) = std::str::from_utf8(id_m.as_bytes()).ok() else {
                    return (false, 0);
                };

                let Some(id) = id_str.parse().ok() else {
                    return (false, 0);
                };

                (true, id)
            })
            .map_err(OpensslBackendError::Io)?;

        let mut at_certs_secret_keys = HashMap::new();
        for (name, id) in at_key_files {
            let Some(at_cert_secret_key) =
                Self::load_secret_key(name, &config.keys_password, &storage)?
            else {
                continue;
            };

            at_certs_secret_keys.insert(id, at_cert_secret_key);
        }

        // Check EC secret key permissions and load it if exist.
        let ec_cert_secret_key = Self::load_secret_key(
            config.ec_key_filename.clone(),
            &config.keys_password,
            &storage,
        )?;

        Ok(Self {
            config,
            storage,
            canonical_secret_key,
            ec_cert_secret_key,
            ec_cert_rekeying_secret_key: None,
            at_certs_secret_keys,
            current_at_id: None,
        })
    }

    /// Generate a secret key for a given `key_type`.
    #[allow(unused)]
    fn generate_secret_key(key_type: EcKeyType) -> Result<EcKey<Private>, ErrorStack> {
        let nid = match key_type {
            EcKeyType::NistP256r1 => Nid::X9_62_PRIME256V1,
            EcKeyType::NistP384r1 => Nid::SECP384R1,
            EcKeyType::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            EcKeyType::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
            EcKeyType::Sm2 => Nid::SM2,
        };

        let group = EcGroup::from_curve_name(nid)?;
        EcKey::generate(&group)
    }

    #[allow(unused)]
    /// Extracts the public key x and y coordinates for a given `private_key`. Returns a tuple as (x,y) coordinates.
    fn extract_public_key_coordinates(
        secret_key: &EcKey<Private>,
    ) -> Result<(BigNum, BigNum), ErrorStack> {
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
            EccPoint::XCoordinateOnly(_) => return Err(BackendError::UnsupportedCompression),
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

    /// Loads the secret key `name` protected with `password`.
    /// Returns `Ok(None)` if the file does not exist.
    fn load_secret_key(
        name: String,
        password: &SecretString,
        storage: &DirectoryStorage,
    ) -> OpensslBackendResult<Option<EcKey<Private>>> {
        storage.load_private_file(name).map_or_else(
            |e| match e.kind() {
                io::ErrorKind::NotFound => Ok(None),
                _ => Err(OpensslBackendError::Io(e)),
            },
            |buf| {
                EcKey::private_key_from_pem_passphrase(&buf, password.expose_secret().as_bytes())
                    .map(Some)
                    .map_err(OpensslBackendError::OpenSSL)
            },
        )
    }

    /// Stores `secret key` with `name` protected with `password`.
    #[allow(unused)]
    fn store_secret_key(
        secret_key: &EcKey<Private>,
        name: String,
        password: &SecretString,
        storage: &DirectoryStorage,
    ) -> BackendResult<()> {
        let content = secret_key
            .private_key_to_pem_passphrase(
                symm::Cipher::chacha20_poly1305(),
                password.expose_secret().as_bytes(),
            )
            .map_err(BackendError::OpenSSL)?;

        storage
            .store_private_file(name, &content)
            .map_err(BackendError::Io)
    }

    fn sign(&self, data: &[u8], ec_key: &EcKey<Private>) -> BackendResult<EcdsaSignature> {
        let (msg_digest, sig_size) = match ec_key.group().curve_name() {
            Some(Nid::BRAINPOOL_P256R1) | Some(Nid::X9_62_PRIME256V1) => {
                (MessageDigest::sha256(), 32)
            }
            Some(Nid::BRAINPOOL_P384R1) | Some(Nid::SECP384R1) => (MessageDigest::sha384(), 48),
            _ => return Err(BackendError::UnsupportedKeyType),
        };

        let key = PKey::from_ec_key(ec_key.to_owned()).map_err(BackendError::OpenSSL)?;

        let mut signer = Signer::new(msg_digest, &key).map_err(BackendError::OpenSSL)?;
        signer.update(data).map_err(BackendError::OpenSSL)?;

        let raw_signature = signer.sign_to_vec().map_err(BackendError::OpenSSL)?;
        let signature = EcdsaSig::from_der(&raw_signature).map_err(BackendError::OpenSSL)?;

        let r_padded = signature
            .r()
            .to_vec_padded(sig_size)
            .map_err(BackendError::OpenSSL)?;
        let s_padded = signature
            .s()
            .to_vec_padded(sig_size)
            .map_err(BackendError::OpenSSL)?;

        let sig_inner = EcdsaSignatureInner {
            r: EccPoint::XCoordinateOnly(r_padded),
            s: s_padded,
        };

        let res = match ec_key.group().curve_name() {
            Some(Nid::X9_62_PRIME256V1) => EcdsaSignature::NistP256r1(sig_inner),
            Some(Nid::SECP384R1) => EcdsaSignature::NistP384r1(sig_inner),
            Some(Nid::BRAINPOOL_P256R1) => EcdsaSignature::BrainpoolP256r1(sig_inner),
            Some(Nid::BRAINPOOL_P384R1) => EcdsaSignature::BrainpoolP384r1(sig_inner),
            _ => unreachable!(),
        };

        Ok(res)
    }
}

impl BackendTrait for OpensslBackend {
    fn verify_signature(
        &self,
        signature: EcdsaSignature,
        verification_key: EcdsaKey,
        data: &[u8],
    ) -> BackendResult<bool> {
        let msg_digest = match signature.hash_algorithm() {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            HashAlgorithm::SM3 => MessageDigest::sm3(),
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

        let ec_key = EcKey::from_public_key(&group, &ec_point).map_err(BackendError::OpenSSL)?;
        ec_key.check_key().map_err(|_| BackendError::InvalidKey)?;

        let key = PKey::from_ec_key(ec_key).map_err(BackendError::OpenSSL)?;

        let r = match &signature.r {
            EccPoint::XCoordinateOnly(c) => c,
            EccPoint::CompressedY0(c) => c,
            EccPoint::CompressedY1(c) => c,
            EccPoint::Uncompressed(c) => &c.x,
        };

        let r = BigNum::from_slice(r).map_err(BackendError::OpenSSL)?;
        let s = BigNum::from_slice(&signature.s).map_err(BackendError::OpenSSL)?;

        let mut verifier = Verifier::new(msg_digest, &key).map_err(BackendError::OpenSSL)?;
        verifier.update(data).map_err(BackendError::OpenSSL)?;

        let signature = EcdsaSig::from_private_components(r, s).map_err(BackendError::OpenSSL)?;
        let sig_der = signature.to_der().map_err(BackendError::OpenSSL)?;

        verifier.verify(&sig_der).map_err(BackendError::OpenSSL)
    }

    fn generate_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature> {
        let Some(id) = &self.current_at_id else {
            return Err(BackendError::NoSigningCertSecretKey);
        };

        let Some(ec_key) = self.at_certs_secret_keys.get(id) else {
            return Err(BackendError::NoSigningCertSecretKey);
        };

        self.sign(data, ec_key)
    }

    fn set_at_key_index(&mut self, index: usize) -> BackendResult<()> {
        let exists = self.at_certs_secret_keys.contains_key(&index);

        if exists {
            self.current_at_id = Some(index);
            Ok(())
        } else {
            Err(BackendError::NoKeyAtIndex)
        }
    }

    fn available_at_keys(&self) -> BackendResult<Vec<(usize, EcdsaKey)>> {
        let mut res = Vec::new();
        for (i, k) in &self.at_certs_secret_keys {
            let ec_key =
                EcKey::from_public_key(k.group(), k.public_key()).map_err(BackendError::OpenSSL)?;

            let pkey = PKey::from_ec_key(ec_key).map_err(BackendError::OpenSSL)?;
            res.push((*i, pkey.try_into()?));
        }

        Ok(res)
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha::sha256(data)
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        sha::sha384(data)
    }

    fn sm3(&self, data: &[u8]) -> BackendResult<[u8; 32]> {
        let data = hash::hash(hash::MessageDigest::sm3(), data).map_err(BackendError::OpenSSL)?;
        (*data)
            .try_into()
            .map_err(|_| BackendError::InvalidHashFormat)
    }

    fn compress_ecies_key(&self, key: EciesKey) -> BackendResult<EciesKey> {
        let res = match key {
            EciesKey::NistP256r1(p) => {
                EciesKey::NistP256r1(self.compress_ecc_point(p, Nid::X9_62_PRIME256V1)?)
            }
            EciesKey::BrainpoolP256r1(p) => {
                EciesKey::BrainpoolP256r1(self.compress_ecc_point(p, Nid::BRAINPOOL_P256R1)?)
            }
            EciesKey::Sm2(p) => EciesKey::Sm2(self.compress_ecc_point(p, Nid::SM2)?),
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
            EcdsaKey::Sm2(p) => EcdsaKey::Sm2(self.compress_ecc_point(p, Nid::SM2)?),
        };

        Ok(res)
    }
}

#[cfg(feature = "pki")]
impl PkiBackendTrait for OpensslBackend {
    type BackendSecretKey = PKey<Private>;
    type BackendPublicKey = PKey<Public>;

    fn generate_aes128_key(&self) -> BackendResult<[u8; 16]> {
        let mut buf = [0; 16];
        rand::rand_priv_bytes(&mut buf).map_err(BackendError::OpenSSL)?;

        Ok(buf)
    }

    fn generate_random<const N: usize>(&self) -> BackendResult<[u8; N]> {
        let mut buf = [0; N];
        rand::rand_bytes(&mut buf).map_err(BackendError::OpenSSL)?;

        Ok(buf)
    }

    fn canonical_pubkey(&self) -> BackendResult<Option<Self::BackendPublicKey>> {
        let Some(key) = &self.canonical_secret_key else {
            return Ok(None);
        };

        let ec_key =
            EcKey::from_public_key(key.group(), key.public_key()).map_err(BackendError::OpenSSL)?;

        PKey::from_ec_key(ec_key)
            .map_err(BackendError::OpenSSL)
            .map(Some)
    }

    fn enrollment_pubkey(&self) -> BackendResult<Option<Self::BackendPublicKey>> {
        let Some(key) = &self.ec_cert_secret_key else {
            return Ok(None);
        };

        let ec_key =
            EcKey::from_public_key(key.group(), key.public_key()).map_err(BackendError::OpenSSL)?;

        PKey::from_ec_key(ec_key)
            .map_err(BackendError::OpenSSL)
            .map(Some)
    }

    fn generate_canonical_keypair(
        &mut self,
        key_type: EcKeyType,
    ) -> BackendResult<Self::BackendPublicKey> {
        let name = self.config.canonical_key_filename.clone();

        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let public_key = EcKey::from_public_key(secret_key.group(), secret_key.public_key())
            .map_err(BackendError::OpenSSL)?;

        Self::store_secret_key(&secret_key, name, &self.config.keys_password, &self.storage)?;
        self.canonical_secret_key = Some(secret_key);

        PKey::from_ec_key(public_key).map_err(BackendError::OpenSSL)
    }

    fn generate_enrollment_keypair(
        &mut self,
        key_type: EcKeyType,
    ) -> BackendResult<Self::BackendPublicKey> {
        let name = self.config.ec_key_filename.clone();

        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let public_key = EcKey::from_public_key(secret_key.group(), secret_key.public_key())
            .map_err(BackendError::OpenSSL)?;

        Self::store_secret_key(&secret_key, name, &self.config.keys_password, &self.storage)?;
        self.ec_cert_secret_key = Some(secret_key);

        PKey::from_ec_key(public_key).map_err(BackendError::OpenSSL)
    }

    fn generate_re_enrollment_keypair(
        &mut self,
        key_type: EcKeyType,
    ) -> BackendResult<Self::BackendPublicKey> {
        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let public_key = EcKey::from_public_key(secret_key.group(), secret_key.public_key())
            .map_err(BackendError::OpenSSL)?;

        self.ec_cert_rekeying_secret_key = Some(secret_key);
        PKey::from_ec_key(public_key).map_err(BackendError::OpenSSL)
    }

    fn generate_authorization_ticket_keypair(
        &mut self,
        key_type: EcKeyType,
        id: usize,
    ) -> BackendResult<Self::BackendPublicKey> {
        let name = self.config.at_key_filename_prefix.clone() + id.to_string().as_str() + ".pem";

        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let public_key = EcKey::from_public_key(secret_key.group(), secret_key.public_key())
            .map_err(BackendError::OpenSSL)?;

        Self::store_secret_key(&secret_key, name, &self.config.keys_password, &self.storage)?;
        self.at_certs_secret_keys.insert(id, secret_key);

        PKey::from_ec_key(public_key).map_err(BackendError::OpenSSL)
    }

    fn generate_ephemeral_keypair(
        &self,
        key_type: EcKeyType,
    ) -> BackendResult<KeyPair<Self::BackendSecretKey, Self::BackendPublicKey>> {
        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let public_key = EcKey::from_public_key(secret_key.group(), secret_key.public_key())
            .map_err(BackendError::OpenSSL)?;

        Ok(KeyPair {
            secret: PKey::from_ec_key(secret_key).map_err(BackendError::OpenSSL)?,
            public: PKey::from_ec_key(public_key).map_err(BackendError::OpenSSL)?,
        })
    }

    fn derive_canonical(&self, peer: &Self::BackendPublicKey) -> BackendResult<Vec<u8>> {
        let Some(secret_key) = &self.canonical_secret_key else {
            return Err(BackendError::NoCanonicalSecretKey);
        };

        let key = PKey::from_ec_key(secret_key.to_owned()).map_err(BackendError::OpenSSL)?;

        self.derive(&key, peer)
    }

    fn derive(
        &self,
        key: &Self::BackendSecretKey,
        peer: &Self::BackendPublicKey,
    ) -> BackendResult<Vec<u8>> {
        let mut deriver = Deriver::new(key).map_err(BackendError::OpenSSL)?;
        deriver.set_peer(peer).map_err(BackendError::OpenSSL)?;
        deriver.derive_to_vec().map_err(BackendError::OpenSSL)
    }

    fn generate_authorization_signature(
        &self,
        key_index: usize,
        data: &[u8],
    ) -> BackendResult<EcdsaSignature> {
        let Some(at_key) = self.at_certs_secret_keys.get(&key_index) else {
            return Err(BackendError::NoSigningCertSecretKey);
        };

        self.sign(data, at_key)
    }

    fn generate_enrollment_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature> {
        let Some(ec_key) = &self.ec_cert_secret_key else {
            return Err(BackendError::NoEnrollmentSecretKey);
        };

        self.sign(data, ec_key)
    }

    fn generate_re_enrollment_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature> {
        let Some(ec_key) = &self.ec_cert_rekeying_secret_key else {
            return Err(BackendError::NoEnrollmentSecretKey);
        };

        self.sign(data, ec_key)
    }

    fn generate_canonical_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature> {
        let Some(ec_key) = &self.canonical_secret_key else {
            return Err(BackendError::NoCanonicalSecretKey);
        };

        self.sign(data, ec_key)
    }

    fn commit_re_enrollment_key(&mut self) -> BackendResult<()> {
        let name = self.config.ec_key_filename.clone();

        let Some(secret_key) = self.ec_cert_rekeying_secret_key.take() else {
            return Err(BackendError::NoReEnrollmentSecretKey);
        };

        Self::store_secret_key(&secret_key, name, &self.config.keys_password, &self.storage)?;
        self.ec_cert_secret_key = Some(secret_key);

        Ok(())
    }

    fn encrypt_aes128_ccm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> BackendResult<Vec<u8>> {
        // Cannot use encrypt_aead() with aes128_ccm. See https://github.com/openssl/openssl/issues/23302
        let mut tag = [0u8; 16];
        let mut encrypted = vec![];
        let mut ctx = CipherCtx::new().map_err(BackendError::OpenSSL)?;

        ctx.encrypt_init(Some(Cipher::aes_128_ccm()), Some(key), None)
            .map_err(BackendError::OpenSSL)?;

        ctx.set_iv_length(nonce.len())
            .map_err(BackendError::OpenSSL)?;

        ctx.set_tag_length(tag.len())
            .map_err(BackendError::OpenSSL)?;

        ctx.encrypt_init(None, Some(key), Some(nonce))
            .map_err(BackendError::OpenSSL)?;

        ctx.cipher_update_vec(data, &mut encrypted)
            .map_err(BackendError::OpenSSL)?;
        ctx.cipher_final_vec(&mut encrypted)
            .map_err(BackendError::OpenSSL)?;
        ctx.tag(&mut tag).map_err(BackendError::OpenSSL)?;

        encrypted.extend_from_slice(&tag);

        Ok(encrypted)
    }

    fn decrypt_aes128_ccm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> BackendResult<Vec<u8>> {
        if data.len() < 16 {
            return Err(BackendError::InvalidData);
        }

        let encrypted = &data[..data.len() - 16];
        let tag = &data[data.len() - 16..];
        let mut output = vec![];

        let mut ctx = CipherCtx::new().map_err(BackendError::OpenSSL)?;
        ctx.decrypt_init(Some(Cipher::aes_128_ccm()), Some(key), None)
            .map_err(BackendError::OpenSSL)?;

        ctx.set_iv_length(nonce.len())
            .map_err(BackendError::OpenSSL)?;

        ctx.set_tag_length(tag.len())
            .map_err(BackendError::OpenSSL)?;

        ctx.decrypt_init(None, Some(key), Some(nonce))
            .map_err(BackendError::OpenSSL)?;

        ctx.set_tag(tag).map_err(BackendError::OpenSSL)?;

        ctx.cipher_update_vec(encrypted, &mut output)
            .map_err(BackendError::OpenSSL)?;
        ctx.cipher_final_vec(&mut output)
            .map_err(BackendError::OpenSSL)?;

        Ok(output)
    }

    fn hmac(
        &self,
        hash_algorithm: HashAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> BackendResult<Vec<u8>> {
        let msg_digest = match hash_algorithm {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            HashAlgorithm::SM3 => MessageDigest::sm3(),
        };

        let pkey = PKey::hmac(key).map_err(BackendError::OpenSSL)?;

        let mut signer = Signer::new(msg_digest, &pkey).map_err(BackendError::OpenSSL)?;
        signer.update(data).map_err(BackendError::OpenSSL)?;

        signer.sign_to_vec().map_err(BackendError::OpenSSL)
    }
}

impl TryFrom<EciesKey> for PKey<Public> {
    type Error = BackendError;

    fn try_from(key: EciesKey) -> Result<Self, Self::Error> {
        let (nid, point) = match key {
            EciesKey::NistP256r1(p) => (Nid::X9_62_PRIME256V1, p),
            EciesKey::BrainpoolP256r1(p) => (Nid::BRAINPOOL_P256R1, p),
            EciesKey::Sm2(p) => (Nid::SM2, p),
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

        let ec_key = EcKey::from_public_key(&group, &ec_point).map_err(BackendError::OpenSSL)?;
        ec_key.check_key().map_err(|_| BackendError::InvalidKey)?;

        PKey::from_ec_key(ec_key).map_err(BackendError::OpenSSL)
    }
}

impl TryFrom<EcdsaKey> for PKey<Public> {
    type Error = BackendError;

    fn try_from(key: EcdsaKey) -> Result<Self, Self::Error> {
        let (nid, point) = match key {
            EcdsaKey::NistP256r1(p) => (Nid::X9_62_PRIME256V1, p),
            EcdsaKey::BrainpoolP256r1(p) => (Nid::BRAINPOOL_P256R1, p),
            EcdsaKey::NistP384r1(p) => (Nid::SECP384R1, p),
            EcdsaKey::BrainpoolP384r1(p) => (Nid::BRAINPOOL_P384R1, p),
            EcdsaKey::Sm2(p) => (Nid::SM2, p),
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

        let ec_key = EcKey::from_public_key(&group, &ec_point).map_err(BackendError::OpenSSL)?;
        ec_key.check_key().map_err(|_| BackendError::InvalidKey)?;

        PKey::from_ec_key(ec_key).map_err(BackendError::OpenSSL)
    }
}

impl TryInto<EciesKey> for PKey<Public> {
    type Error = BackendError;

    fn try_into(self) -> Result<EciesKey, Self::Error> {
        let ec_key = self.ec_key().map_err(BackendError::OpenSSL)?;
        let group = ec_key.group();
        let mut ctx = BigNumContext::new().map_err(BackendError::OpenSSL)?;

        let bytes = ec_key
            .public_key()
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .map_err(BackendError::OpenSSL)?;

        let ecc_point = match bytes[0] {
            0x02 => EccPoint::CompressedY0(bytes[1..].to_vec()),
            0x03 => EccPoint::CompressedY1(bytes[1..].to_vec()),
            _ => return Err(BackendError::InternalError),
        };

        let res = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => EciesKey::NistP256r1(ecc_point),
            Some(Nid::BRAINPOOL_P256R1) => EciesKey::BrainpoolP256r1(ecc_point),
            _ => return Err(BackendError::UnsupportedKeyType),
        };

        Ok(res)
    }
}

impl TryInto<EcdsaKey> for PKey<Public> {
    type Error = BackendError;

    fn try_into(self) -> Result<EcdsaKey, Self::Error> {
        let ec_key = self.ec_key().map_err(BackendError::OpenSSL)?;
        let group = ec_key.group();
        let mut ctx = BigNumContext::new().map_err(BackendError::OpenSSL)?;

        let bytes = ec_key
            .public_key()
            .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
            .map_err(BackendError::OpenSSL)?;

        let ecc_point = match bytes[0] {
            0x02 => EccPoint::CompressedY0(bytes[1..].to_vec()),
            0x03 => EccPoint::CompressedY1(bytes[1..].to_vec()),
            _ => return Err(BackendError::InternalError),
        };

        let res = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => EcdsaKey::NistP256r1(ecc_point),
            Some(Nid::SECP384R1) => EcdsaKey::NistP384r1(ecc_point),
            Some(Nid::BRAINPOOL_P256R1) => EcdsaKey::BrainpoolP256r1(ecc_point),
            Some(Nid::BRAINPOOL_P384R1) => EcdsaKey::BrainpoolP384r1(ecc_point),
            _ => return Err(BackendError::UnsupportedKeyType),
        };

        Ok(res)
    }
}
