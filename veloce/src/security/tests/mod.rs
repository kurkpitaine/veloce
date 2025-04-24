use std::{fs::DirBuilder, os::unix::fs::DirBuilderExt, path::PathBuf, rc::Rc};

use super::{DirectoryStorage, DirectoryStorageConfig, OpensslBackend, OpensslBackendConfig};

#[cfg(feature = "pki")]
use tempfile::{tempdir, TempDir};

pub(self) mod backend;
pub(self) mod certificate;
pub(self) mod secured_message;

/// Create a `veloce` temporary directory and return the path to it, along with the
/// [TempDir] to instance which should be kept alive until the tempdir is no longer needed.
pub fn create_temp_veloce_dir() -> (PathBuf, TempDir) {
    let base_path = tempdir().unwrap();

    // Create veloce directory in tempdir.
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(base_path.path().join("veloce"))
        .unwrap();

    (base_path.path().join("veloce"), base_path)
}

/// Get the path to the test assets in the local Veloce repository.
pub fn get_test_storage_path() -> PathBuf {
    let mut key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_path.pop();
    key_path.push(file!());
    key_path.pop();
    std::fs::canonicalize(key_path).unwrap()
}

/// Setup a [DirectoryStorage] with the path to a `storage_dir` and [OpensslBackend] for testing.
pub fn setup_storage_and_crypto(storage_dir: PathBuf) -> (Rc<DirectoryStorage>, OpensslBackend) {
    let storage_config =
        DirectoryStorageConfig::new(Some(storage_dir.into_os_string().into_string().unwrap()));
    let storage = Rc::new(DirectoryStorage::new(storage_config).unwrap());

    let config = OpensslBackendConfig::new("test1234".to_string().into());
    let backend = OpensslBackend::new(config, storage.clone()).unwrap();

    (storage, backend)
}
