use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
};

use crate::security::{
    backend::{openssl::OpensslBackend, BackendTrait},
    EccPoint, EcdsaKey, UncompressedEccPoint,
};

#[cfg(feature = "pki")]
use crate::security::{
    backend::PkiBackendTrait,
    certificate::{CertificateTrait, EnrollmentAuthorityCertificate, ExplicitCertificate},
    EcKeyType,
};

#[cfg(feature = "pki")]
use std::path::Path;

#[cfg(feature = "pki")]
#[test]
fn test_create_canonical_key() {
    let (base_path, _temp_dir) = super::create_temp_veloce_dir();

    let key_path = base_path
        .join("assets")
        .join("private")
        .join("canonical.pem")
        .into_os_string()
        .into_string()
        .unwrap();

    let (_, mut backend) = super::setup_storage_and_crypto(base_path);

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

    let (base_path, _temp_dir) = super::create_temp_veloce_dir();
    let (_, backend) = super::setup_storage_and_crypto(base_path);

    let key = EcdsaKey::NistP256r1(EccPoint::Uncompressed(UncompressedEccPoint {
        x: x.to_vec(),
        y: y.to_vec(),
    }));

    backend.compress_ecdsa_key(key).unwrap();
}

#[test]
fn test_load_secret_key() {
    let base_path = super::get_test_storage_path();
    let (_, mut backend) = super::setup_storage_and_crypto(base_path);
    backend.set_at_key_index(0).unwrap();

    backend
        .generate_authorization_signature(0, &[0x00, 0x00, 0x00, 0x00])
        .unwrap();
}

#[cfg(feature = "pki")]
#[test]
fn derive_key() {
    use crate::security::storage::StorageTrait;

    let base_path = super::get_test_storage_path();
    let (storage, backend) = super::setup_storage_and_crypto(base_path);

    let raw_ea_cert = storage.load_ea_certificate().unwrap();
    let ea_cert = EnrollmentAuthorityCertificate::from_bytes(&raw_ea_cert, &backend).unwrap();

    let keypair = backend
        .generate_ephemeral_keypair(EcKeyType::NistP256r1)
        .unwrap();

    let _cert_hash = backend.sha256(ea_cert.raw_bytes());

    let peer_public_key = ea_cert.public_encryption_key().unwrap().unwrap();
    let peer_public_pkey =
        <OpensslBackend as PkiBackendTrait>::BackendPublicKey::try_from(peer_public_key).unwrap();
    let _derived = backend.derive(&keypair.secret, &peer_public_pkey).unwrap();
}
