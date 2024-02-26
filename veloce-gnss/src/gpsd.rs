use std::io::{ErrorKind, Read, Result, Write};
use std::mem;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use gpsd_proto::{Mode as GpsdMode, UnifiedResponse as GpsdResponse};
use log::{debug, error, info, trace};
use mio::event::Event;
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use uom::si::angle::degree;
use uom::si::f32::{Angle, Length, Velocity};
use uom::si::length::meter;
use uom::si::velocity::meter_per_second;

use crate::{FixMode, GpsInfo};

const RETRY: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct ConnectingState {
    retry_at: Instant,
    stream: TcpStream,
}

/// Describes the status of the state machine
/// managing the connection to the GPSD server.
#[derive(Debug)]
enum ClientState {
    /// Idle state.
    Idle,
    /// Initial state.
    Initial(Instant),
    /// Client is connecting to the GPSD server.
    Connecting(ConnectingState),
    /// Client is connected to the GPSD server.
    Connected(TcpStream),
    /// Client is enabling data stream from GPSD server.
    Enabling(TcpStream),
    /// Client is reading data stream from GPSD server.
    Reading(TcpStream),
}

/// GPSD client.
pub struct Gpsd {
    /// Gps position.
    position: GpsInfo,
    /// Gps data temp cache. Used for constructing `position`.
    cache: GpsInfo,
    /// Last time at which we received valid data
    /// from the GPSD server.
    last_rx_time: DateTime<Utc>,
    /// Connection state.
    state: ClientState,
    /// Mio poll registry.
    registry: Registry,
    /// Registry token for the TcpStream.
    token: Token,
    /// GPSD server address.
    server_addr: SocketAddr,
}

impl Gpsd {
    /// Constructs a new [Gpsd]. The connection is not launched until the Gpsd
    /// client is polled.
    pub fn new(server: String, registry: Registry, reg_token: Token) -> Result<Gpsd> {
        let server_addr = server.parse().map_err(|_| ErrorKind::InvalidInput)?;

        Ok(Gpsd {
            position: GpsInfo::default(),
            cache: GpsInfo::default(),
            last_rx_time: DateTime::default(),
            state: ClientState::Initial(Instant::now()),
            registry: registry,
            token: reg_token,
            server_addr,
        })
    }

    /// Fetch the position.
    pub fn fetch_position(&self) -> GpsInfo {
        self.position
    }

    pub fn poll(&mut self) -> Result<()> {
        let timestamp = Instant::now();

        // Move state into a local variable to be able to change it.
        let client_state = mem::replace(&mut self.state, ClientState::Idle);

        match client_state {
            ClientState::Initial(when) if when <= timestamp => {
                trace!("start connection to GPSD server {}", self.server_addr);
                self.state = ClientState::Connecting(ConnectingState {
                    retry_at: timestamp + RETRY,
                    stream: self.try_connect_and_register()?,
                });
            }
            ClientState::Connecting(ConnectingState {
                retry_at,
                mut stream,
            }) if retry_at <= timestamp => {
                error!(
                    "timeout when connecting to GPSD server {}, retry in {} secs",
                    self.server_addr,
                    RETRY.as_secs(),
                );
                self.registry.deregister(&mut stream)?;
                self.state = ClientState::Connecting(ConnectingState {
                    retry_at: timestamp + RETRY,
                    stream: self.try_connect_and_register()?,
                });
            }
            ClientState::Connected(mut stream) => {
                trace!("enabling stream from GPSD server {}", self.server_addr);
                stream.write_all(gpsd_proto::ENABLE_WATCH_CMD.as_bytes())?;
                self.state = ClientState::Enabling(stream);
            }
            state => {
                self.state = state;
            }
        };

        Ok(())
    }

    pub fn ready(&mut self, event: &Event) {
        if event.token() != self.token {
            error!("event token does not match");
            return;
        }

        let timestamp = Instant::now();

        if event.is_readable() {
            // Move state into a local variable to be able to change it.
            let client_state = mem::replace(&mut self.state, ClientState::Idle);

            // Handle disconnects.
            if event.is_read_closed() {
                self.state = ClientState::Initial(timestamp + RETRY);
                error!(
                    "unexpected disconnect from GPSD server, restarting connection in {} secs",
                    RETRY.as_secs()
                );
                return;
            }

            let maybe_resp = match client_state {
                ClientState::Enabling(mut stream) => {
                    match self.read_and_parse(&mut stream) {
                        Ok(resp) => {
                            if let GpsdResponse::Version(v) = resp {
                                if v.proto_major < gpsd_proto::PROTO_MAJOR_MIN {
                                    error!(
                                        "GPSD major version mismatch - {}<{} ",
                                        v.proto_major,
                                        gpsd_proto::PROTO_MAJOR_MIN
                                    );
                                    self.state = ClientState::Initial(timestamp + RETRY);
                                } else {
                                    debug!("GPSD protocol enabled");
                                    self.state = ClientState::Reading(stream);
                                }
                            }
                        }
                        Err(_) => {
                            error!(
                                "failed to enable GPSD protocol - retry in {} secs",
                                RETRY.as_secs()
                            );
                            self.state = ClientState::Initial(timestamp + RETRY);
                        }
                    }
                    None
                }
                ClientState::Reading(mut stream) => {
                    let res = self.read_and_parse(&mut stream).ok();
                    self.state = ClientState::Reading(stream);
                    res
                }
                state => {
                    self.state = state;
                    None
                }
            };

            let Some(resp) = maybe_resp else {
                return;
            };

            debug!("cache updated: {}", self.update_cache(resp));
            debug!("position updated: {}", self.update_position());
        }

        if event.is_writable() {
            let client_state = mem::replace(&mut self.state, ClientState::Idle);

            match client_state {
                ClientState::Connecting(state) => match state.stream.peer_addr() {
                    Ok(_) => {
                        info!("connected to GPSD server {}", self.server_addr);
                        self.state = ClientState::Connected(state.stream);
                    }
                    Err(e)
                        if e.kind() == ErrorKind::WouldBlock
                            || e.raw_os_error() == Some(libc::EINPROGRESS) =>
                    {
                        self.state = ClientState::Connecting(state);
                    }
                    Err(e) => {
                        error!(
                            "failed to connect to GPSD server {}, retry in {} secs - {}",
                            self.server_addr,
                            RETRY.as_secs(),
                            e
                        );
                        self.state = ClientState::Initial(timestamp + RETRY);
                    }
                },
                state => self.state = state,
            }
        }
    }

    fn try_connect_and_register(&self) -> Result<TcpStream> {
        match TcpStream::connect(self.server_addr) {
            Ok(mut stream) => {
                self.registry.register(
                    &mut stream,
                    self.token,
                    Interest::READABLE | Interest::WRITABLE,
                )?;
                Ok(stream)
            }
            Err(e) => Err(e),
        }
    }

    fn read_and_parse(&self, stream: &mut TcpStream) -> Result<GpsdResponse> {
        loop {
            let mut buf = vec![0; 8192];
            match stream.read(&mut buf) {
                Ok(num_bytes) => {
                    debug!("received {num_bytes} bytes");
                    buf.resize(num_bytes, 0);

                    match String::from_utf8(buf) {
                        Ok(content) => {
                            for sentence in content.split_terminator('\n').into_iter() {
                                match serde_json::from_str(&sentence) {
                                    Ok(resp) => {
                                        return Ok(resp);
                                    }
                                    Err(e) => {
                                        error!("failed to parse JSON: {e}");
                                        trace!("{}", sentence);
                                        return Err(ErrorKind::InvalidData.into());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("failed to perform conversion to string: {e}");
                            return Err(ErrorKind::InvalidData.into());
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    error!("failed to read() stream");
                    return Err(e);
                }
            }
        }
    }

    /// Updates `self.last_rx_time`, `self.position` and reset
    /// `self.cache` if position is valid.
    /// Returns `true` if position is updated.
    fn update_position(&mut self) -> bool {
        match self.cache.fix.mode {
            FixMode::NotUpdated => {
                // Ignore fix if not updated.
                trace!("FixMode::NotUpdated");
                return false;
            }
            FixMode::NoFix => {
                // Send NoFix to notify no GPS signal or GPS loss.
                trace!("FixMode::NoFix");
                return true;
            }
            _ => {}
        }

        // Only update of we have time, latitude, longitude, speed and track.
        match self.cache.fix.time_position_and_kinematics_values() {
            Some((time, ..)) if time > self.last_rx_time => {
                trace!("time > last_rx_time : {} > {}", time, self.last_rx_time);

                // Update last reception time.
                self.last_rx_time = time;

                // Fill confidence values.
                self.cache.self_confidence();

                // Set values into position.
                self.position = self.cache;

                // Reset cache
                self.cache = GpsInfo::default();
                true
            }
            Some((time, ..)) => {
                trace!("time <= last_rx_time : {} <= {}", time, self.last_rx_time);
                false
            }
            _ => {
                trace!("time_position_and_kinematics_values() = false");
                false
            }
        }
    }

    /// Fill a [GpsInfo] from a [GpsdResponse].
    /// Returns `true` if cache is updated.
    fn update_cache(&mut self, data: GpsdResponse) -> bool {
        match data {
            GpsdResponse::Tpv(tpv) => {
                // Reset cache if no signal from GPS.
                match (tpv.mode, tpv.status) {
                    (GpsdMode::NoFix, _) | (_, Some(0)) => {
                        trace!("NoFix or status = 0");
                        self.cache = GpsInfo::default();
                    }
                    _ => {
                        self.cache.fix.mode = tpv.mode.into();
                    }
                }

                match tpv.time {
                    Some(datetime_str) => {
                        let utc_time = match DateTime::parse_from_rfc3339(&datetime_str) {
                            Ok(datetime) => datetime.to_utc(),
                            Err(_) => {
                                error!("failed to parse TPV time - using system time");
                                Utc::now()
                            }
                        };
                        self.cache.fix.time = Some(utc_time);
                    }
                    None => {
                        // If no fix time info from GPSD, get the local system time.
                        self.cache.fix.time = Some(Utc::now());
                    }
                }

                self.cache.fix.ept = tpv.ept.map(|ept| Duration::from_secs_f32(ept));
                self.cache.fix.latitude = tpv
                    .lat
                    .map(|latitude| Angle::new::<degree>(latitude as f32));
                self.cache.fix.epy = tpv.epy.map(|epy| Length::new::<meter>(epy as f32));
                self.cache.fix.longitude = tpv
                    .lon
                    .map(|longitude| Angle::new::<degree>(longitude as f32));
                self.cache.fix.epx = tpv.epx.map(|epx| Length::new::<meter>(epx as f32));
                self.cache.fix.altitude = tpv.alt_hae.map(|alt| Length::new::<meter>(alt as f32));
                self.cache.fix.epv = tpv.epv.map(|epv| Length::new::<meter>(epv as f32));
                self.cache.fix.track = tpv.track.map(|track| Angle::new::<degree>(track));
                self.cache.fix.epd = tpv.epd.map(|epd| Angle::new::<degree>(epd));
                self.cache.fix.speed = tpv
                    .speed
                    .map(|speed| Velocity::new::<meter_per_second>(speed));
                self.cache.fix.eps = tpv.eps.map(|eps| Velocity::new::<meter_per_second>(eps));
                self.cache.fix.climb = tpv
                    .climb
                    .map(|climb| Velocity::new::<meter_per_second>(climb));
                self.cache.fix.epc = tpv.epc.map(|epc| Velocity::new::<meter_per_second>(epc));

                true
            }
            GpsdResponse::Gst(gst) => {
                self.cache.gst.time = if let Some(datetime_str) = gst.time {
                    match DateTime::parse_from_rfc3339(&datetime_str) {
                        Ok(datetime) => Some(datetime.to_utc()),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                self.cache.gst.rms_deviation = gst.rms;
                self.cache.gst.major_deviation =
                    gst.major.map(|major_dev| Length::new::<meter>(major_dev));
                self.cache.gst.minor_deviation =
                    gst.minor.map(|minor_dev| Length::new::<meter>(minor_dev));
                self.cache.gst.major_orientation = gst
                    .orient
                    .map(|major_orient| Angle::new::<degree>(major_orient));
                self.cache.gst.lat_err_deviation =
                    gst.lat.map(|lat_dev| Length::new::<meter>(lat_dev));
                self.cache.gst.lon_err_deviation =
                    gst.lon.map(|lon_dev| Length::new::<meter>(lon_dev));
                self.cache.gst.alt_err_deviation =
                    gst.minor.map(|minor_dev| Length::new::<meter>(minor_dev));

                true
            }
            _ => false,
        }
    }
}
