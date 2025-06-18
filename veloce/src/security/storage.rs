#[cfg(not(feature = "std"))]
use alloc::collections::btree_map::BTreeMap;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use core::fmt;

#[cfg(feature = "proto-security-storage-directory")]
pub mod directory;

pub type StorageResult<T> = core::result::Result<T, StorageError>;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Storage {
    /// Inner storage backend.
    inner: InnerStorage,
    /// Storage AT certificates metadata
    metadata: StorageMetadata,
}

impl Storage {
    /// Create a new [Storage], based on the [directory::DirectoryStorage] implementation with the given `config`.
    #[cfg(feature = "proto-security-storage-directory")]
    pub fn new_directory(config: directory::DirectoryStorageConfig) -> StorageResult<Self> {
        let storage = directory::DirectoryStorage::new(config).map_err(StorageError::Directory)?;
        let metadata = storage.load_metadata().unwrap_or_default();

        Ok(Self {
            inner: InnerStorage::Directory(storage),
            metadata,
        })
    }
}

/// Inner storage backend type.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum InnerStorage {
    /// Directory based storage.
    #[cfg(feature = "proto-security-storage-directory")]
    Directory(directory::DirectoryStorage),
}

impl Storage {
    #[allow(unused)]
    #[inline]
    pub(super) fn inner(&self) -> &dyn StorageTrait {
        match &self.inner {
            InnerStorage::Directory(storage) => storage,
        }
    }

    #[allow(unused)]
    #[inline]
    pub(super) fn inner_mut(&mut self) -> &mut dyn StorageTrait {
        match &mut self.inner {
            InnerStorage::Directory(storage) => storage,
        }
    }

    /// Get a reference on the metadata.
    pub fn metadata(&self) -> &StorageMetadata {
        &self.metadata
    }

    /// Get a mutable reference on the metadata.s
    pub fn metadata_mut(&mut self) -> &mut StorageMetadata {
        &mut self.metadata
    }
}

/// Storage error types.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StorageError {
    /// Certificate not found.
    NotFound,
    /// Directory storage error.
    #[cfg(feature = "proto-security-storage-directory")]
    Directory(directory::DirectoryStorageError),
    /// Other opaque type of error, specific to one storage implementation.
    Other(Box<dyn core::error::Error>),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::NotFound => write!(f, "certificate not found"),
            #[cfg(feature = "proto-security-storage-directory")]
            StorageError::Directory(e) => write!(f, "directory storage error: {}", e),
            StorageError::Other(e) => write!(f, "{}", e),
        }
    }
}

pub trait StorageTrait {
    /// Load the Trust List Manager certificate from the storage.
    fn load_tlm_certificate(&self) -> StorageResult<Vec<u8>>;

    /// Load the ECTL from the storage.
    fn load_ectl(&self) -> StorageResult<Vec<u8>>;

    /// Load the root certificate from the storage.
    fn load_root_certificate(&self) -> StorageResult<Vec<u8>>;

    /// Load the Authorization Authority certificate from the storage.
    fn load_aa_certificate(&self) -> StorageResult<Vec<u8>>;

    /// Load the Enrollment Authority certificate from the storage.
    fn load_ea_certificate(&self) -> StorageResult<Vec<u8>>;

    /// Load the Enrollment Credential certificate from the storage.
    fn load_ec_certificate(&self) -> StorageResult<Vec<u8>>;

    /// Load the Authorization Ticket certificate with the given `index` from the storage.
    fn load_at_certificate(&self, index: usize) -> StorageResult<Vec<u8>>;

    /// Load the certificates metadata from the storage.
    fn load_metadata(&self) -> StorageResult<StorageMetadata>;

    /// Store the Trust List Manager certificate in the storage.
    fn store_tlm_certificate(&self, cert: &[u8]) -> StorageResult<()>;

    /// Store the ECTL in the storage.
    fn store_ectl(&self, cert: &[u8]) -> StorageResult<()>;

    /// Store the root certificate in the storage.
    fn store_root_certificate(&self, cert: &[u8]) -> StorageResult<()>;

    /// Store the Authorization Authority certificate in the storage.
    fn store_aa_certificate(&self, cert: &[u8]) -> StorageResult<()>;

    /// Store the Enrollment Authority certificate in the storage.
    fn store_ea_certificate(&self, cert: &[u8]) -> StorageResult<()>;

    /// Store the Enrollment Credential certificate in the storage.
    fn store_ec_certificate(&self, cert: &[u8]) -> StorageResult<()>;

    /// Store the Authorization Ticket certificate with the given `index` in the storage.
    fn store_at_certificate(&self, cert: &[u8], index: usize) -> StorageResult<()>;

    /// Store the certificates metadata in the storage.
    fn store_metadata(&self, meta: StorageMetadata) -> StorageResult<()>;
}

/// Metadata for the AT certificates.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StorageMetadata {
    /// Statistics on the elections of the AT certificates.
    pub(crate) at_elections_stats: BTreeMap<usize, usize>,
}

impl StorageMetadata {
    /// Constructs a new [StorageMetadata].
    pub fn new() -> Self {
        Self {
            at_elections_stats: BTreeMap::new(),
        }
    }

    /// Get the election statistics for AT certificate at the given `index`.
    pub fn elections_stats(&self, index: usize) -> Option<usize> {
        self.at_elections_stats.get(&index).copied()
    }

    /// Set the statistics on the elections of the AT certificates.
    pub fn set_elections_stats(&mut self, index: usize, stats: usize) {
        self.at_elections_stats.insert(index, stats);
    }

    /// Increment the election statistics for AT certificate at the given `index`.
    pub fn increment_elections_stats(&mut self, index: usize) {
        self.at_elections_stats.entry(index).and_modify(|e| *e += 1);
    }
}

impl Default for StorageMetadata {
    fn default() -> Self {
        Self::new()
    }
}
