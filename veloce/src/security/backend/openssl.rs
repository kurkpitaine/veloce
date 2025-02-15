use directories::UserDirs;
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::{self, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private, Public},
    rand, sha,
    sign::{Signer, Verifier},
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    fmt,
    fs::{DirBuilder, File},
    io::{self, Read, Result as IoResult, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};

use super::{BackendError, BackendResult, BackendTrait, PkiBackendTrait};
use crate::security::{
    signature::{EcdsaSignature, EcdsaSignatureInner},
    EcKeyType, EccPoint, EcdsaKey, EciesKey, HashAlgorithm, KeyPair,
};

#[derive(Debug)]
pub struct OpensslBackendConfig {
    /// Veloce directory. If not set, the home directory of
    /// the user running the application is used as base,
    /// containing the `.veloce` directory.
    pub veloce_dir: Option<String>,
    /// Secret keys password.
    pub keys_password: SecretString,
    /// Canonical key filename.
    pub canonical_key_filename: String,
    /// AT key filename.
    pub at_key_filename: String,
    /// Enrollment credential key filename.
    pub ec_key_filename: String,
}

impl Default for OpensslBackendConfig {
    fn default() -> Self {
        Self {
            veloce_dir: None,
            keys_password: SecretString::new("".into()),
            canonical_key_filename: "canonical.pem".into(),
            at_key_filename: "AT.pem".into(),
            ec_key_filename: "EC.pem".into(),
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
    /// Home directory not found.
    HomeDirNotFound,
    /// Bad permissions. Should be 0o600.
    BadPermissions(PathBuf),
}

impl fmt::Display for OpensslBackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OpensslBackendError::Io(e) => write!(f, "io: {}", e),
            OpensslBackendError::OpenSSL(e) => write!(f, "openssl: {}", e),
            OpensslBackendError::HomeDirNotFound => write!(f, "home directory not found"),
            OpensslBackendError::BadPermissions(p) => {
                write!(f, "bad permissions, should be 0o600 on: {}", p.display())
            }
        }
    }
}

#[derive(Debug)]
pub struct OpensslBackend {
    /// Backend configuration.
    config: OpensslBackendConfig,
    /// Directory path for assets.
    assets_path: PathBuf,
    /* /// Directory path for keys.
    keys_path: PathBuf,
    /// Directory path for certificates.
    certs_path: PathBuf, */
    /// Canonical secret key. Used to encrypt PKI related communications.
    canonical_secret_key: Option<EcKey<Private>>,
    /// AT certificate secret key. Used to sign the messages over the air.
    at_cert_secret_key: Option<EcKey<Private>>,
    /// EC certificate secret key.
    ec_cert_secret_key: Option<EcKey<Private>>,
}

impl OpensslBackend {
    /// Constructs a new [OpensslBackend] with the provided `config`.
    pub fn new(config: OpensslBackendConfig) -> OpensslBackendResult<Self> {
        // Get veloce path.
        let veloce_path = match &config.veloce_dir {
            Some(p) => PathBuf::from(p),
            None => UserDirs::new()
                .ok_or(OpensslBackendError::HomeDirNotFound)?
                .home_dir()
                .join(".veloce"),
        };

        /* let keys_path = veloce_path.join("keys");
        let certs_path = veloce_path.join("certs");
        let canonical_key_path = keys_path.join(config.canonical_key_filename.clone());
        let at_key_path = keys_path.join(config.at_key_filename.clone()); */
        let assets_path = veloce_path.join("assets");
        let canonical_key_path = assets_path.join(config.canonical_key_filename.clone());
        let at_key_path = assets_path.join(config.at_key_filename.clone());
        let ec_key_path = assets_path.join(config.ec_key_filename.clone());

        // Check directory exists and if permissions are ok. Or create them.
        Self::check_or_create_directory(&veloce_path)?;
        Self::check_or_create_directory(&assets_path)?;
        /* Self::check_or_create_directory(&keys_path)?;
        Self::check_or_create_directory(&certs_path)?; */

        // Check canonical secret key permissions and load it if exist.
        let canonical_secret_key = Self::check_permissions(&canonical_key_path, 0o600)
            .map_or_else(
                |e| match e {
                    OpensslBackendError::Io(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                    e => Err(e),
                },
                |_| {
                    Self::load_secret_key(canonical_key_path.clone(), &config.keys_password)
                        .map(|k| Some(k))
                        .map_err(OpensslBackendError::Io)
                },
            )?;

        // Check AT secret key permissions and load it if exist.
        let at_cert_secret_key = Self::check_permissions(&at_key_path, 0o600).map_or_else(
            |e| match e {
                OpensslBackendError::Io(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                e => Err(e),
            },
            |_| {
                Self::load_secret_key(at_key_path.clone(), &config.keys_password)
                    .map(|k| Some(k))
                    .map_err(OpensslBackendError::Io)
            },
        )?;

        // Check EC secret key permissions and load it if exist.
        let ec_cert_secret_key = Self::check_permissions(&ec_key_path, 0o600).map_or_else(
            |e| match e {
                OpensslBackendError::Io(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                e => Err(e),
            },
            |_| {
                Self::load_secret_key(ec_key_path.clone(), &config.keys_password)
                    .map(|k| Some(k))
                    .map_err(OpensslBackendError::Io)
            },
        )?;

        Ok(Self {
            config,
            assets_path,
            canonical_secret_key,
            at_cert_secret_key,
            ec_cert_secret_key,
        })
    }

    /// Check if `path` exists and has correct permissions. If not, create it.
    fn check_or_create_directory(path: &PathBuf) -> Result<(), OpensslBackendError> {
        Self::check_permissions(path, 0o700).map_or_else(
            |e| match e {
                OpensslBackendError::Io(e) if e.kind() == io::ErrorKind::NotFound => {
                    Self::create_directory(path)
                }
                _ => Err(e),
            },
            |_| Ok(()),
        )
    }

    /// Check if permissions of `path` are equals to`mode`.
    /// Should be 0o600 for a file or 0o700 for a directory.
    fn check_permissions(path: &PathBuf, mode: u32) -> Result<(), OpensslBackendError> {
        match path.metadata().map(|m| m.permissions().mode()) {
            Ok(m) if (m & 0o777) == mode => Ok(()),
            Ok(_) => Err(OpensslBackendError::BadPermissions(path.to_owned())),
            Err(e) => Err(OpensslBackendError::Io(e)),
        }
    }

    /// Create directory at `path` with correct permissions.
    fn create_directory(path: &PathBuf) -> Result<(), OpensslBackendError> {
        DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(path.clone())
            .map_err(OpensslBackendError::Io)
    }

    /// Generate a secret key for a given `key_type`.
    fn generate_secret_key(key_type: EcKeyType) -> Result<EcKey<Private>, ErrorStack> {
        let nid = match key_type {
            EcKeyType::NistP256r1 => Nid::X9_62_PRIME256V1,
            EcKeyType::NistP384r1 => Nid::SECP384R1,
            EcKeyType::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            EcKeyType::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
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

    /// Loads the secret key at `path` protected with `password`.
    fn load_secret_key(path: PathBuf, password: &SecretString) -> IoResult<EcKey<Private>> {
        let mut content = File::open(path)?;
        let mut buf = Vec::new();
        content.read_to_end(&mut buf)?;

        let key = EcKey::private_key_from_pem_passphrase(&buf, password.expose_secret().as_bytes())
            .map_err(|_| io::ErrorKind::Other)?;

        Ok(key)
    }

    /// Stores `secret key` at `path` protected with `password`.
    fn store_secret_key(
        secret_key: EcKey<Private>,
        path: PathBuf,
        password: &SecretString,
    ) -> BackendResult<()> {
        let content = secret_key
            .private_key_to_pem_passphrase(
                Cipher::chacha20_poly1305(),
                password.expose_secret().as_bytes(),
            )
            .map_err(BackendError::OpenSSL)?;

        let mut file = File::create(path).map_err(BackendError::Io)?;
        file.write_all(&content).map_err(BackendError::Io)?;
        file.sync_all().map_err(BackendError::Io)
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
        let Some(ec_key) = &self.at_cert_secret_key else {
            return Err(BackendError::NoSigningCertSecretKey);
        };

        self.sign(data, ec_key)
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha::sha256(data)
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        sha::sha384(data)
    }

    fn sm3(&self, data: &[u8]) -> BackendResult<[u8; 32]> {
        let data = hash::hash(hash::MessageDigest::sm3(), data).map_err(BackendError::OpenSSL)?;
        Ok((*data)
            .try_into()
            .map_err(|_| BackendError::InvalidHashFormat)?)
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
            EcdsaKey::Sm2(p) => EcdsaKey::Sm2(self.compress_ecc_point(p, Nid::SM2)?),
        };

        Ok(res)
    }
}

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
            .map(|k| Some(k))
    }

    fn enrollment_pubkey(&self) -> BackendResult<Option<Self::BackendPublicKey>> {
        let Some(key) = &self.ec_cert_secret_key else {
            return Ok(None);
        };

        let ec_key =
            EcKey::from_public_key(key.group(), key.public_key()).map_err(BackendError::OpenSSL)?;

        PKey::from_ec_key(ec_key)
            .map_err(BackendError::OpenSSL)
            .map(|k| Some(k))
    }

    fn generate_canonical_keypair(
        &self,
        key_type: EcKeyType,
    ) -> BackendResult<Self::BackendPublicKey> {
        let key_path = self
            .assets_path
            .join(self.config.canonical_key_filename.clone());

        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let public_key = EcKey::from_public_key(secret_key.group(), secret_key.public_key())
            .map_err(BackendError::OpenSSL)?;

        Self::store_secret_key(secret_key, key_path, &self.config.keys_password)?;

        Ok(PKey::from_ec_key(public_key).map_err(BackendError::OpenSSL)?)
    }

    fn generate_enrollment_keypair(
        &self,
        key_type: EcKeyType,
    ) -> BackendResult<Self::BackendPublicKey> {
        let key_path = self.assets_path.join(self.config.at_key_filename.clone());

        let secret_key =
            OpensslBackend::generate_secret_key(key_type).map_err(BackendError::OpenSSL)?;
        let public_key = EcKey::from_public_key(secret_key.group(), secret_key.public_key())
            .map_err(BackendError::OpenSSL)?;

        Self::store_secret_key(secret_key, key_path, &self.config.keys_password)?;

        Ok(PKey::from_ec_key(public_key).map_err(BackendError::OpenSSL)?)
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

    fn generate_enrollment_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature> {
        let Some(ec_key) = &self.ec_cert_secret_key else {
            return Err(BackendError::NoEnrollmentSecretKey);
        };

        self.sign(data, ec_key)
    }

    fn generate_canonical_signature(&self, data: &[u8]) -> BackendResult<EcdsaSignature> {
        let Some(ec_key) = &self.ec_cert_secret_key else {
            return Err(BackendError::NoCanonicalSecretKey);
        };

        self.sign(data, ec_key)
    }

    fn encrypt_aes128_ccm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> BackendResult<Vec<u8>> {
        let mut tag = [0u8; 16];
        let mut encrypted =
            encrypt_aead(Cipher::aes_128_ccm(), key, Some(nonce), &[], data, &mut tag)
                .map_err(BackendError::OpenSSL)?;

        encrypted.extend_from_slice(&tag);

        Ok(encrypted)
    }

    fn decrypt_aes128_ccm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> BackendResult<Vec<u8>> {
        if data.len() < 16 {
            return Err(BackendError::InvalidData);
        }

        let encrypted = &data[..data.len() - 16];
        let tag = &data[data.len() - 16..];

        decrypt_aead(Cipher::aes_128_ccm(), key, Some(nonce), &[], encrypted, tag)
            .map_err(BackendError::OpenSSL)
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
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
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
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
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
