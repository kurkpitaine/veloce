use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

use crate::security::{
    backend::{
        openssl::{OpensslBackend, OpensslBackendConfig},
        BackendTrait,
    },
    EccPoint, EcdsaKey, EcdsaKeyType, UncompressedEccPoint,
};

#[test]
fn test_create_canonical_key() {
    let base_path = tempdir().unwrap();
    let canonical_key_path = base_path
        .path()
        .join("canonical.pem")
        .into_os_string()
        .into_string()
        .unwrap();

    let config = OpensslBackendConfig {
        canonical_key_path: canonical_key_path.clone(),
        canonical_key_passwd: "test1234".to_string().into(),
        signing_cert_secret_key_path: None,
        signing_cert_secret_key_passwd: None,
    };

    let backend = OpensslBackend::new(config).unwrap();
    let _pub_key = backend
        .generate_canonical_keypair(EcdsaKeyType::NistP384r1)
        .unwrap();

    assert!(Path::new(&canonical_key_path).exists());
}

#[test]
fn test_compress_point() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut bn_ctx = BigNumContext::new().unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();

    let _shared_key = EcKey::generate(&group).unwrap();
    _shared_key
        .public_key()
        .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
        .unwrap();

    let config = OpensslBackendConfig {
        canonical_key_path: String::new(),
        canonical_key_passwd: String::new().into(),
        signing_cert_secret_key_path: None,
        signing_cert_secret_key_passwd: None,
    };
    let backend = OpensslBackend::new(config).unwrap();

    let key = EcdsaKey::NistP256r1(EccPoint::Uncompressed(UncompressedEccPoint {
        x: x.to_vec(),
        y: y.to_vec(),
    }));

    backend.compress_ecdsa_key(key).unwrap();
}

#[test]
fn test_load_secret_key() {
    let mut key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_path.pop();
    key_path.push(file!());
    key_path.pop();
    key_path.push("assets/AT.pem");
    let key_path = std::fs::canonicalize(key_path).unwrap();

    let config = OpensslBackendConfig {
        canonical_key_path: "".to_string(),
        canonical_key_passwd: "".to_string().into(),
        signing_cert_secret_key_path: Some(key_path.into_os_string().into_string().unwrap()),
        signing_cert_secret_key_passwd: Some("test1234".to_string().into()),
    };

    OpensslBackend::new(config).unwrap();
}
