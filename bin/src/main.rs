mod cli;
mod config;
mod device;
mod gnss;
mod ipc;
mod router;
mod security;
mod utils;

use std::fmt;

use clap::Parser;
use cli::Cli;
use config::{Config, ConfigError};
use device::{AnyDevice, DeviceError};
use log::info;
use router::{Router, RouterError};
use security::SecurityError;
use utils::{UtilError, get_config_file_path, setup_logging, write_pid_file};

pub type VeloceResult<T> = core::result::Result<T, VeloceError>;

/// Error returned by the Veloce executable.
#[derive(Debug)]
pub enum VeloceError {
    /// Failed to locate configuration file.
    ConfigPath(UtilError),
    /// Error while loading configuration file.
    ConfigLoad(ConfigError),
    /// Error while configuring PHY network device.
    PhyDevice(DeviceError),
    /// Error while writing PID file.
    PidFile(UtilError),
    /// Security setup error.
    Security(SecurityError),
    /// Router setup error.
    Router(RouterError),
}

impl fmt::Display for VeloceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VeloceError::ConfigPath(e) => write!(f, "Cannot get path of configuration file: {e}"),
            VeloceError::ConfigLoad(e) => write!(f, "Failed to load configuration file: {e}"),
            VeloceError::PhyDevice(e) => write!(f, "Failed to setup PHY device: {e}"),
            VeloceError::PidFile(e) => write!(f, "Failed to write PID file: {e}"),
            VeloceError::Security(e) => write!(f, "Failed to setup security: {e}"),
            VeloceError::Router(e) => write!(f, "Failed to setup router: {e}"),
        }
    }
}

pub fn main() -> VeloceResult<()> {
    let cli = Cli::parse();

    // Get configuration file path and load configuration.
    let config_file_path = get_config_file_path(&cli).map_err(VeloceError::ConfigPath)?;
    let config = Config::load(config_file_path).map_err(VeloceError::ConfigLoad)?;

    setup_logging(&config.log_level);
    info!("Starting Veloce");

    write_pid_file(&config).map_err(VeloceError::PidFile)?;

    info!("Configuring PHY network device");
    let device = AnyDevice::setup_phy_device(&config).map_err(VeloceError::PhyDevice)?;

    let maybe_security_and_storage_config =
        security::setup_security(&config).map_err(VeloceError::Security)?;

    let mut router = Router::new(&config, device, maybe_security_and_storage_config)
        .map_err(VeloceError::Router)?;

    router.run();

    info!("Veloce stopped");
    Ok(())
}
