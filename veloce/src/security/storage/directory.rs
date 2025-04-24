use core::fmt;
use std::{
    fs::{self},
    io::{self, Read, Result as IoResult, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

use directories::UserDirs;

use super::{StorageError, StorageResult, StorageTrait};

#[derive(Debug)]
pub struct DirectoryStorageConfig {
    /// Veloce directory. If not set, the home directory of
    /// the user running the application is used as base,
    /// containing the `.veloce` directory.
    pub veloce_dir: Option<String>,
    /// ECTL filename.
    ectl_filename: String,
    /// Trust List Manager certificate filename.
    tlm_cert_filename: String,
    /// Root certificate filename.
    root_cert_filename: String,
    /// Authorization Authority certificate filename.
    aa_cert_filename: String,
    /// Enrollment Authority certificate filename.
    ea_cert_filename: String,
    /// Enrollment credential certificate filename.
    ec_cert_filename: String,
    /// AT certs filename prefix.
    at_cert_filename_prefix: String,
}

impl DirectoryStorageConfig {
    /// Constructs a new [DirectoryStorageConfig] with the provided `veloce_dir`.
    /// If `veloce_dir` is not set, the home directory of
    /// the user running the application is used as base,
    /// containing the `.veloce` directory.
    pub fn new(veloce_dir: Option<String>) -> Self {
        Self {
            veloce_dir,
            ..Default::default()
        }
    }
}

impl Default for DirectoryStorageConfig {
    fn default() -> Self {
        Self {
            veloce_dir: None,
            ectl_filename: "ECTL.oer".into(),
            tlm_cert_filename: "TLM.cert".into(),
            root_cert_filename: "RCA.cert".into(),
            aa_cert_filename: "AA.cert".into(),
            ea_cert_filename: "EA.cert".into(),
            ec_cert_filename: "EC.cert".into(),
            at_cert_filename_prefix: "AT_".into(),
        }
    }
}

type DirectoryStorageResult<T> = core::result::Result<T, DirectoryStorageError>;

/// Directory storage error types.
#[derive(Debug)]
pub enum DirectoryStorageError {
    /// IO error.
    Io(io::Error),
    /// Home directory not found.
    HomeDirNotFound,
    /// Bad permissions. Expected value is the second parameter.
    BadPermissions(PathBuf, u32),
}

impl fmt::Display for DirectoryStorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DirectoryStorageError::Io(e) => write!(f, "io: {}", e),
            DirectoryStorageError::HomeDirNotFound => write!(f, "home directory not found"),
            DirectoryStorageError::BadPermissions(p, m) => {
                write!(f, "bad permissions, should be {:#o} on: {}", m, p.display())
            }
        }
    }
}

#[derive(Debug)]
pub struct DirectoryStorage {
    /// Storage configuration.
    config: DirectoryStorageConfig,
    /// Directory path for assets.
    assets_path: PathBuf,
    /// Directory path for private assets.
    private_path: PathBuf,
}

impl DirectoryStorage {
    /// Constructs a new [DirectoryStorage] with the provided `config`.
    pub fn new(config: DirectoryStorageConfig) -> DirectoryStorageResult<Self> {
        // Get veloce path.
        let veloce_path = match &config.veloce_dir {
            Some(p) => PathBuf::from(p),
            None => UserDirs::new()
                .ok_or(DirectoryStorageError::HomeDirNotFound)?
                .home_dir()
                .join(".veloce"),
        };

        let assets_path = veloce_path.join("assets");
        let private_path = assets_path.join("private");

        // Check directory exists and if permissions are ok. Or create them.
        Self::check_or_create_directory(&veloce_path, None)?;
        Self::check_or_create_directory(&assets_path, None)?;
        Self::check_or_create_directory(&private_path, Some(0o700))?;

        // Check permissions of files inside private directory.
        let private_files = Self::list_files(&private_path).map_err(DirectoryStorageError::Io)?;
        for file in private_files {
            Self::check_permissions(&file, 0o600)?;
        }

        Ok(Self {
            config,
            assets_path,
            private_path,
        })
    }

    /// Check if `path` exists with `permissions`, if any.
    /// If not, create it with permissions inherited from the parent folder or `permissions` if
    /// provided.
    fn check_or_create_directory(
        path: &PathBuf,
        permissions: Option<u32>,
    ) -> DirectoryStorageResult<()> {
        let exists = if let Some(permissions) = permissions {
            Self::check_permissions(path, permissions)
        } else {
            path.metadata()
                .map(|_| ())
                .map_err(DirectoryStorageError::Io)
        };

        match exists {
            Ok(_) => Ok(()),
            Err(DirectoryStorageError::BadPermissions(_, _)) => exists,
            Err(DirectoryStorageError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                Self::create_directory(path.to_owned(), permissions)
                    .map_err(DirectoryStorageError::Io)
            }
            Err(e) => Err(e),
        }
    }

    /// Check if permissions of `path` are equals to`mode`.
    /// Should be 0o600 for a file or 0o700 for a directory.
    fn check_permissions(path: &PathBuf, mode: u32) -> DirectoryStorageResult<()> {
        match path.metadata().map(|m| m.permissions().mode()) {
            Ok(m) if (m & 0o777) == mode => Ok(()),
            Ok(_) => Err(DirectoryStorageError::BadPermissions(path.to_owned(), mode)),
            Err(e) => Err(DirectoryStorageError::Io(e)),
        }
    }

    /// Create directory at `path` with optional `permissions`.
    /// If no permissions are provided, the folder is created with inherited permissions.
    fn create_directory(path: PathBuf, permissions: Option<u32>) -> IoResult<()> {
        let mut dir_builder = fs::DirBuilder::new();
        dir_builder.recursive(false);

        if let Some(permissions) = permissions {
            dir_builder.mode(permissions);
        }

        dir_builder.create(path)
    }

    /// List files in `path`.
    fn list_files(path: &PathBuf) -> IoResult<Vec<PathBuf>> {
        let mut res = Vec::new();

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                res.push(path);
            }
        }

        Ok(res)
    }

    /// Loads the file at `path`.
    fn load_file(path: PathBuf) -> IoResult<Vec<u8>> {
        let mut content = fs::File::open(path)?;
        let mut buf = Vec::new();
        content.read_to_end(&mut buf)?;

        Ok(buf)
    }

    /// Stores `content` at `path`, with optional `permissions`.
    /// If no permissions are provided, the file is created with inherited folder permissions.
    /// Blocks until the file contents and it's metadata are written to the disk.
    fn store_file(path: PathBuf, content: &[u8], permissions: Option<u32>) -> IoResult<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true);
        opts.create(true);

        if let Some(permissions) = permissions {
            opts.mode(permissions);
        }

        let mut file = opts.open(path)?;

        file.write_all(&content)?;
        file.sync_all()
    }

    /// Loads the file identified by `name` from the private directory.
    pub fn load_private_file(&self, name: String) -> IoResult<Vec<u8>> {
        let file_path = self.private_path.join(name);
        Self::load_file(file_path)
    }

    /// List file names from the private directory where the `f` returns true, along with
    /// `M` generic metadata.
    pub fn list_private_files_where<F, M>(&self, f: F) -> IoResult<Vec<(String, M)>>
    where
        F: Fn(&str) -> (bool, M),
    {
        let res = Self::list_files(&self.private_path)?
            .iter()
            .filter_map(|path| {
                let Some(filename) = path.file_name() else {
                    return None;
                };

                let Some(name_str) = filename.to_str() else {
                    return None;
                };

                let call = f(name_str);

                if !call.0 {
                    return None;
                }

                Some((name_str.to_string(), call.1))
            })
            .collect();

        Ok(res)
    }

    /// Stores `content` into the file identified by `name` in the private directory.
    /// Permissions of the file are enforced to 0o600 to ensure the file is not readable by
    /// other users.
    /// Any existing file with the same name will be overwritten.
    /// Blocks until the file contents and it's metadata are written to the disk.
    pub fn store_private_file(&self, name: String, content: &[u8]) -> IoResult<()> {
        let file_path = self.private_path.join(name);
        Self::store_file(file_path, content, Some(0o600))
    }
}

macro_rules! load_file_storage_map {
    ($path:expr) => {
        Self::load_file($path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Other(e.into())
            }
        })
    };
}

impl StorageTrait for DirectoryStorage {
    fn load_tlm_certificate(&self) -> StorageResult<Vec<u8>> {
        let path = self.assets_path.join(self.config.tlm_cert_filename.clone());
        load_file_storage_map!(path)
    }

    fn load_ectl(&self) -> StorageResult<Vec<u8>> {
        let path = self.assets_path.join(self.config.ectl_filename.clone());
        load_file_storage_map!(path)
    }

    fn load_root_certificate(&self) -> StorageResult<Vec<u8>> {
        let path = self
            .assets_path
            .join(self.config.root_cert_filename.clone());

        load_file_storage_map!(path)
    }

    fn load_aa_certificate(&self) -> StorageResult<Vec<u8>> {
        let path = self.assets_path.join(self.config.aa_cert_filename.clone());
        load_file_storage_map!(path)
    }

    fn load_ea_certificate(&self) -> StorageResult<Vec<u8>> {
        let path = self.assets_path.join(self.config.ea_cert_filename.clone());
        load_file_storage_map!(path)
    }

    fn load_ec_certificate(&self) -> StorageResult<Vec<u8>> {
        let path = self.assets_path.join(self.config.ec_cert_filename.clone());
        load_file_storage_map!(path)
    }

    fn load_at_certificate(&self, index: usize) -> StorageResult<Vec<u8>> {
        let file_name =
            self.config.at_cert_filename_prefix.clone() + index.to_string().as_str() + ".cert";
        let path = self.assets_path.join(file_name);

        load_file_storage_map!(path)
    }

    fn store_tlm_certificate(&self, cert: &[u8]) -> StorageResult<()> {
        let path = self.assets_path.join(self.config.tlm_cert_filename.clone());
        Self::store_file(path, cert, None).map_err(|e| StorageError::Other(e.into()))
    }

    fn store_ectl(&self, cert: &[u8]) -> StorageResult<()> {
        let path = self.assets_path.join(self.config.ectl_filename.clone());
        Self::store_file(path, cert, None).map_err(|e| StorageError::Other(e.into()))
    }

    fn store_root_certificate(&self, cert: &[u8]) -> StorageResult<()> {
        let path = self
            .assets_path
            .join(self.config.root_cert_filename.clone());
        Self::store_file(path, cert, None).map_err(|e| StorageError::Other(e.into()))
    }

    fn store_aa_certificate(&self, cert: &[u8]) -> StorageResult<()> {
        let path = self.assets_path.join(self.config.aa_cert_filename.clone());
        Self::store_file(path, cert, None).map_err(|e| StorageError::Other(e.into()))
    }

    fn store_ea_certificate(&self, cert: &[u8]) -> StorageResult<()> {
        let path = self.assets_path.join(self.config.ea_cert_filename.clone());
        Self::store_file(path, cert, None).map_err(|e| StorageError::Other(e.into()))
    }

    fn store_ec_certificate(&self, cert: &[u8]) -> StorageResult<()> {
        let path = self.assets_path.join(self.config.ec_cert_filename.clone());
        Self::store_file(path, cert, None).map_err(|e| StorageError::Other(e.into()))
    }

    fn store_at_certificate(&self, cert: &[u8], index: usize) -> StorageResult<()> {
        let file_name =
            self.config.at_cert_filename_prefix.clone() + index.to_string().as_str() + ".cert";
        let path = self.assets_path.join(file_name);
        Self::store_file(path, cert, None).map_err(|e| StorageError::Other(e.into()))
    }
}
