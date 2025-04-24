pub mod directory;

pub type StorageResult<T> = core::result::Result<T, StorageError>;

/// Storage backend.
#[derive(Debug)]
pub enum Storage {
    /// Directory based storage.
    Directory(directory::DirectoryStorage),
}

impl Storage {
    #[inline]
    pub(super) fn inner(&self) -> &impl StorageTrait {
        match self {
            Storage::Directory(storage) => storage,
        }
    }

    #[allow(unused)]
    #[inline]
    pub(super) fn inner_mut(&mut self) -> &mut impl StorageTrait {
        match self {
            Storage::Directory(storage) => storage,
        }
    }
}

/// Storage error types.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StorageError {
    /// Certificate not found.
    NotFound,
    /// Other opaque type of error, specific to one storage implementation.
    Other(Box<dyn core::error::Error>),
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
}
