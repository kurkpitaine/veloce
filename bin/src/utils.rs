use core::fmt;
use std::{
    fs::File,
    io::{self, Write},
    rc::Rc,
    str::{self},
};

use crate::{Cli, config::Config};

use env_logger::Builder;
use log::{Level, LevelFilter};
use secrecy::ExposeSecret;
use veloce::{
    security::{
        DirectoryStorage, DirectoryStorageConfig, OpensslBackend, OpensslBackendConfig,
        backend::openssl::OpensslBackendError, storage::directory::DirectoryStorageError,
    },
    time::Instant,
};

#[derive(Debug)]
pub enum UtilError {
    /// Error while creating the PID file.
    CreatePidFile(String, io::Error),
    /// Error while writing the PID file.
    WritePidFile(String, io::Error),
    /// Error while syncing the PID file.
    SyncPidFile(String, io::Error),
    /// Error while getting the configuration file path.
    GetConfigFilePath,
    /// Directory storage error.
    Storage(DirectoryStorageError),
    /// Crypto backend error.
    CryptoBackend(OpensslBackendError),
    /// Error while reading a file.
    Reading {
        path: String,
        io_error: std::io::Error,
    },
}

impl fmt::Display for UtilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtilError::CreatePidFile(path, err) => {
                write!(f, "cannot create pid file {path}: {err}")
            }
            UtilError::WritePidFile(path, err) => {
                write!(f, "cannot write pid file {path}: {err}")
            }
            UtilError::SyncPidFile(path, err) => write!(f, "cannot sync pid file {path}: {err}"),
            UtilError::GetConfigFilePath => write!(
                f,
                "No configuration file specified. Either use -c with the start command, or use the VELOCE_CFG_PATH environment variable when building Veloce."
            ),
            UtilError::Storage(e) => write!(f, "directory storage error {e}"),
            UtilError::CryptoBackend(e) => write!(f, "crypto backend error {e}"),
            UtilError::Reading { path, io_error } => {
                write!(f, "cannot read file {}: {}", path, io_error)
            }
        }
    }
}

/// Load a file as a string, at `path`.
pub fn load_file(path: &str) -> Result<String, UtilError> {
    std::fs::read_to_string(path).map_err(|io_error| UtilError::Reading {
        path: path.to_owned(),
        io_error,
    })
}

pub fn write_pid_file(config: &Config) -> Result<(), UtilError> {
    let cfg_pid_file_path: Option<&str> = config.pid_file_path.as_ref().map(|p| p.as_ref());

    let maybe_path = match (cfg_pid_file_path, option_env!("VELOCE_PID_FILE_PATH")) {
        (Some(fp), _) => Some(fp),
        (None, Some(fp)) => Some(fp),
        (None, None) => None,
    };

    if let Some(path) = maybe_path {
        let mut file = File::create(path)
            .map_err(|io_err| UtilError::CreatePidFile(path.to_owned(), io_err))?;

        let pid = unsafe { libc::getpid() };

        file.write_all(format!("{pid}").as_bytes())
            .map_err(|write_err| UtilError::WritePidFile(path.to_owned(), write_err))?;
        file.sync_all()
            .map_err(|sync_err| UtilError::SyncPidFile(path.to_owned(), sync_err))?;
    }

    Ok(())
}

pub fn get_config_file_path(args: &Cli) -> Result<&str, UtilError> {
    match args.config.as_ref() {
        Some(config_file) => Ok(config_file.as_str()),
        None => option_env!("VELOCE_CFG_PATH").ok_or(UtilError::GetConfigFilePath),
    }
}

pub fn setup_logging_with_clock<F>(filter: &str, since_startup: F)
where
    F: Fn() -> Instant + Send + Sync + 'static,
{
    Builder::new()
        .format(move |buf, record| {
            let elapsed = since_startup();
            let timestamp = format!("[{elapsed}]");
            if record.target().starts_with("veloce::") {
                writeln!(
                    buf,
                    "\x1b[0m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target().replace("veloce::", ""),
                    record.args()
                )
            } else if record.level() == Level::Trace {
                let message = format!("{}", record.args());
                writeln!(
                    buf,
                    "\x1b[37m{} {}\x1b[0m",
                    timestamp,
                    message.replace('\n', "\n             ")
                )
            } else {
                writeln!(
                    buf,
                    "\x1b[32m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target(),
                    record.args()
                )
            }
        })
        .filter(None, LevelFilter::Trace)
        .parse_filters(filter)
        .parse_env("VELOCE_LOG")
        .init();
}

pub fn setup_logging(filter: &str) {
    setup_logging_with_clock(filter, Instant::now)
}

pub fn setup_openssl_and_directory_storage(
    config: &Config,
) -> Result<(OpensslBackend, Rc<DirectoryStorage>), UtilError> {
    let storage_config = DirectoryStorageConfig::new(config.security.storage_path.clone());
    let dr = DirectoryStorage::new(storage_config).map_err(UtilError::Storage)?;
    let storage = Rc::new(dr);

    let crypto_config =
        OpensslBackendConfig::new(config.security.secret.expose_secret().0.as_str().into());
    let backend =
        OpensslBackend::new(crypto_config, storage.clone()).map_err(UtilError::CryptoBackend)?;

    Ok((backend, storage))
}
