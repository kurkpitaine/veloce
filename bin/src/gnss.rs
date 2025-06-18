use core::fmt;
use std::{io, path::Path};

use log::info;
use mio::{Registry, Token};
use veloce::time::{Duration, Instant};
use veloce_gnss::{Fixed, FixedError, Gpsd, Replay, ReplayError};

use crate::config::{Config, GnssConfig};

pub type GnssSourceResult<T> = Result<T, GnssSourceError>;

/// Error returned by the GNSS source.
#[derive(Debug)]
pub enum GnssSourceError {
    ///Fixed position error.
    Fixed(FixedError),
    /// GPSD error.
    Gpsd(io::Error),
    /// Replay error.
    Replay(ReplayError),
}

impl fmt::Display for GnssSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GnssSourceError::Fixed(e) => write!(f, "Fixed position error: {e}"),
            GnssSourceError::Gpsd(e) => write!(f, "GPSD error: {e}"),
            GnssSourceError::Replay(e) => write!(f, "Replay error: {e}"),
        }
    }
}

/// GNSS source.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum GnssSource {
    /// Fixed position (static) source.
    Fixed(Fixed),
    /// GPSD server source.
    Gpsd(Gpsd),
    /// Replay from an NMEA file source.
    Replay(Box<Replay>),
}

impl GnssSource {
    pub fn new(config: &Config, poll_registry: Registry, token: Token) -> GnssSourceResult<Self> {
        let res = match &config.gnss {
            GnssConfig::FixedPosition {
                latitude,
                longitude,
                altitude,
            } => {
                info!("Using Fixed position provider");
                let fixed =
                    Fixed::new(*latitude, *longitude, *altitude).map_err(GnssSourceError::Fixed)?;
                GnssSource::Fixed(fixed)
            }
            GnssConfig::Gpsd(socket_addr) => {
                info!("Using Gpsd position server: {}", socket_addr);
                let gpsd = Gpsd::new(*socket_addr, poll_registry, token, Instant::now())
                    .map_err(GnssSourceError::Gpsd)?;
                GnssSource::Gpsd(gpsd)
            }
            GnssConfig::Replay(file) => {
                info!("Using replay file at: {}", file);
                let path = Path::new(&file).to_owned();
                let replay =
                    Replay::new(path, Duration::from_secs(1)).map_err(GnssSourceError::Replay)?;
                GnssSource::Replay(replay.into())
            }
        };

        Ok(res)
    }
}
