use std::path::Path;
use tempfile::tempdir;

use crate::security::{
    backend::{
        openssl::{OpensslBackend, OpensslBackendConfig},
        Backend,
    },
    EcdsaKeyType,
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
        canonical_key_passwd: "test1234".to_string(),
    };

    let backend = OpensslBackend::new(config);
    let _pub_key = backend
        .generate_canonical_keypair(EcdsaKeyType::NistP384r1)
        .unwrap();

    assert!(Path::new(&canonical_key_path).exists());
}
