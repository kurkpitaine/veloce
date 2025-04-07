use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
};
use std::path::PathBuf;

use crate::security::{
    backend::{
        openssl::{OpensslBackend, OpensslBackendConfig},
        BackendTrait,
    },
    EccPoint, EcdsaKey, UncompressedEccPoint,
};

#[cfg(feature = "pki")]
use crate::security::{
    backend::PkiBackendTrait,
    certificate::{CertificateTrait, EnrollmentAuthorityCertificate, ExplicitCertificate},
    EcKeyType,
};

#[cfg(feature = "pki")]
use std::{fs::DirBuilder, os::unix::fs::DirBuilderExt, path::Path};

#[cfg(feature = "pki")]
use tempfile::tempdir;

#[cfg(feature = "pki")]
use super::certificate;

#[cfg(feature = "pki")]
#[test]
fn test_create_canonical_key() {
    let base_path = tempdir().unwrap();

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(base_path.path().join("veloce").join("assets"))
        .unwrap();

    let key_path = base_path
        .path()
        .join("veloce")
        .join("assets")
        .join("canonical.pem")
        .into_os_string()
        .into_string()
        .unwrap();

    let config = OpensslBackendConfig::new(
        "test1234".to_string().into(),
        Some(
            base_path
                .path()
                .join("veloce")
                .into_os_string()
                .into_string()
                .unwrap(),
        ),
    );

    let mut backend = OpensslBackend::new(config).unwrap();
    let _pub_key = backend
        .generate_canonical_keypair(EcKeyType::NistP384r1)
        .unwrap();

    assert!(Path::new(&key_path).exists());
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

    let backend = OpensslBackend::new(Default::default()).unwrap();

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
    let key_path = std::fs::canonicalize(key_path).unwrap();

    let config = OpensslBackendConfig::new(
        "test1234".to_string().into(),
        Some(key_path.into_os_string().into_string().unwrap()),
    );

    OpensslBackend::new(config).unwrap();
}

#[cfg(feature = "pki")]
#[test]
fn derive_key() {
    let backend = OpensslBackend::new(Default::default()).unwrap();

    let raw_ea_cert = certificate::load_ea_cert();
    let ea_cert = EnrollmentAuthorityCertificate::from_etsi_cert(raw_ea_cert.0, &backend).unwrap();

    let keypair = backend
        .generate_ephemeral_keypair(EcKeyType::NistP256r1)
        .unwrap();

    let _cert_hash = backend.sha256(ea_cert.raw_bytes());

    let peer_public_key = ea_cert.public_encryption_key().unwrap().unwrap();
    let peer_public_pkey =
        <OpensslBackend as PkiBackendTrait>::BackendPublicKey::try_from(peer_public_key).unwrap();
    let _derived = backend.derive(&keypair.secret, &peer_public_pkey).unwrap();
}
