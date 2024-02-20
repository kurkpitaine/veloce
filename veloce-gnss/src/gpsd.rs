use std::io::{self, BufReader, BufWriter, Result};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use gpsd_proto::{GpsdError, Mode as GpsdMode, ResponseData};
use log::{error, info, trace};
use uom::si::angle::degree;
use uom::si::f32::{Angle, Length, Velocity};
use uom::si::length::meter;
use uom::si::velocity::meter_per_second;

use crate::{FixMode, GpsInfo};

const TIMEOUT: Duration = Duration::from_secs(2);
const RETRY: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct TcpConn {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

/// Describes the status of the state machine
/// managing the connection to the GPSD server.
#[derive(Debug)]
enum ClientState {
    /// Client is connecting to the GPSD server.
    Connecting, /* (ConnectingState) */
    /// Client is enabling data stream from GPSD server.
    Enabling(TcpConn), /* (EnablingState) */
    /// Client is reading data stream from GPSD server.
    Reading(TcpConn),
}

/// GPSD client.
pub struct Gpsd {
    /// Channel on which we receive newly received [GpsInfo].
    rx_channel: Receiver<GpsInfo>,
}

impl Gpsd {
    /// Connects to the specified GPSD `server`.
    pub fn connect(server: String) -> Result<Gpsd> {
        let addr = server.parse().map_err(|_| io::ErrorKind::InvalidInput)?;

        let (tx_channel, rx_channel) = mpsc::channel();

        thread::spawn(move || {
            let mut state = ClientState::Connecting;
            let mut gps_info_cache: GpsInfo = GpsInfo::default();
            let mut last_gps_time: DateTime<Utc> = DateTime::default();

            loop {
                match state {
                    ClientState::Connecting => match TcpStream::connect_timeout(&addr, TIMEOUT) {
                        Ok(tcp_stream) => match tcp_stream.try_clone() {
                            Ok(reader_stream) => {
                                let reader = BufReader::new(reader_stream);
                                let writer = BufWriter::new(tcp_stream);
                                info!("Connected to GPSD server {}", server);
                                state = ClientState::Enabling(TcpConn { reader, writer });
                            }
                            Err(e) => {
                                error!("Failed to clone TCP stream for server {}, retry in {} secs - {}", server, RETRY.as_secs(), e);
                                thread::sleep(RETRY);
                            }
                        },
                        Err(e) => {
                            error!(
                                "Failed to connect to GPSD server {}, retry in {} secs - {}",
                                server,
                                RETRY.as_secs(),
                                e
                            );
                            thread::sleep(RETRY);
                        }
                    },
                    ClientState::Enabling(mut conn) => {
                        match gpsd_proto::handshake(&mut conn.reader, &mut conn.writer) {
                            Ok(_) => {
                                state = ClientState::Reading(conn);
                            }
                            Err(e) => {
                                error!(
                                    "Failed to handshake to GPSD server {}, retry in {} secs - {}",
                                    server,
                                    RETRY.as_secs(),
                                    e
                                );
                                state = ClientState::Connecting;
                                thread::sleep(RETRY);
                            }
                        }
                    }
                    ClientState::Reading(ref mut conn) => {
                        match gpsd_proto::get_data(&mut conn.reader) {
                            Ok(data) => {
                                Gpsd::update_cache(data, &mut gps_info_cache);
                                if Gpsd::should_send(&gps_info_cache, &mut last_gps_time) {
                                    // Fill confidence values.
                                    gps_info_cache.self_confidence();
                                    if tx_channel.send(gps_info_cache).is_err() {
                                        error!("GpsInfo receiver gone, terminating thread");
                                        break;
                                    }
                                    gps_info_cache = GpsInfo::default();
                                }
                            }
                            Err(GpsdError::IoError(e)) => {
                                error!(
                                    "Io error while getting data, restarting connection in {} secs - {}",
                                    RETRY.as_secs(), e
                                );
                                state = ClientState::Connecting;
                                thread::sleep(RETRY);
                            }
                            Err(GpsdError::JsonError(e)) if e.is_eof() => {
                                error!("Error while getting data, restarting connection in {} secs - {}", RETRY.as_secs(), e);
                                state = ClientState::Connecting;
                                thread::sleep(RETRY);
                            }
                            Err(e) => {
                                error!("Error while getting data - {}", e);
                            }
                        }
                    }
                }
            }
        });

        Ok(Gpsd { rx_channel })
    }

    pub fn recv(&self) {
        //let info = self.rx_channel.try_recv().unwrap();
        let info = self.rx_channel.recv().unwrap();
        info!("{:?}", info);
    }

    fn should_send(cache: &GpsInfo, last_rx_time: &mut DateTime<Utc>) -> bool {
        match cache.fix.mode {
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

        trace!("{:?}", cache);

        // Only send of we have time, latitude, longitude, speed and track.
        let res = match cache.fix.time_position_and_kinematics_values() {
            Some((time, ..)) if time > *last_rx_time => {
                trace!("time > last_rx_time : {} > {}", time, last_rx_time);
                *last_rx_time = time;
                true
            }
            Some((time, ..)) => {
                trace!("time <= last_rx_time : {} <= {}", time, last_rx_time);
                false
            }
            _ => {
                trace!("time_position_and_kinematics_values() = false");
                false
            }
        };

        trace!("should_send() = {}", res);
        res
    }

    /// Fill a [GpsInfo] from a [ResponseData].
    fn update_cache(data: ResponseData, cache: &mut GpsInfo) {
        match data {
            ResponseData::Tpv(tpv) => {
                // Reset cache if no signal from GPS.
                match (tpv.mode, tpv.status) {
                    (GpsdMode::NoFix, _) | (_, Some(0)) => {
                        trace!("NoFix or status = 0");
                        *cache = GpsInfo::default();
                    }
                    _ => {
                        cache.fix.mode = tpv.mode.into();
                    }
                }

                match tpv.time {
                    Some(datetime_str) => {
                        let utc_time = match DateTime::parse_from_rfc3339(&datetime_str) {
                            Ok(datetime) => datetime.to_utc(),
                            Err(_) => {
                                error!("Failed to parse TPV time - using system time");
                                Utc::now()
                            }
                        };
                        cache.fix.time = Some(utc_time);
                    }
                    None => {
                        // If no fix time info from GPSD, get the local system time.
                        cache.fix.time = Some(Utc::now());
                    }
                }

                cache.fix.ept = tpv.ept.map(|ept| Duration::from_secs_f32(ept));
                cache.fix.latitude = tpv
                    .lat
                    .map(|latitude| Angle::new::<degree>(latitude as f32));
                cache.fix.epy = tpv.epy.map(|epy| Length::new::<meter>(epy as f32));
                cache.fix.longitude = tpv
                    .lon
                    .map(|longitude| Angle::new::<degree>(longitude as f32));
                cache.fix.epx = tpv.epx.map(|epx| Length::new::<meter>(epx as f32));
                cache.fix.altitude = tpv.alt_hae.map(|alt| Length::new::<meter>(alt as f32));
                cache.fix.epv = tpv.epv.map(|epv| Length::new::<meter>(epv as f32));
                cache.fix.track = tpv.track.map(|track| Angle::new::<degree>(track));
                cache.fix.epd = tpv.epd.map(|epd| Angle::new::<degree>(epd));
                cache.fix.speed = tpv
                    .speed
                    .map(|speed| Velocity::new::<meter_per_second>(speed));
                cache.fix.eps = tpv.eps.map(|eps| Velocity::new::<meter_per_second>(eps));
                cache.fix.climb = tpv
                    .climb
                    .map(|climb| Velocity::new::<meter_per_second>(climb));
                cache.fix.epc = tpv.epc.map(|epc| Velocity::new::<meter_per_second>(epc));
            }
            ResponseData::Gst(gst) => {
                cache.gst.time = if let Some(datetime_str) = gst.time {
                    match DateTime::parse_from_rfc3339(&datetime_str) {
                        Ok(datetime) => Some(datetime.to_utc()),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                cache.gst.rms_deviation = gst.rms;
                cache.gst.major_deviation =
                    gst.major.map(|major_dev| Length::new::<meter>(major_dev));
                cache.gst.minor_deviation =
                    gst.minor.map(|minor_dev| Length::new::<meter>(minor_dev));
                cache.gst.major_orientation = gst
                    .orient
                    .map(|major_orient| Angle::new::<degree>(major_orient));
                cache.gst.lat_err_deviation = gst.lat.map(|lat_dev| Length::new::<meter>(lat_dev));
                cache.gst.lon_err_deviation = gst.lon.map(|lon_dev| Length::new::<meter>(lon_dev));
                cache.gst.alt_err_deviation =
                    gst.minor.map(|minor_dev| Length::new::<meter>(minor_dev));
            }
            _ => {}
        }
    }
}
