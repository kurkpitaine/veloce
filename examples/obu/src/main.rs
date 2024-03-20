use std::io;
use std::os::fd::AsRawFd;

use clap::Parser;
use log::{debug, error, info, trace};

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use veloce::iface::{Config, Interface, SocketSet};
use veloce::network::{GnAddrConfigMode, GnCore, GnCoreGonfig};
use veloce::phy::{Medium, RawSocket as VeloceRawSocket};
use veloce::socket;
use veloce::time::Instant;
use veloce::types::Pseudonym;
use veloce::utils;
use veloce::wire::{EthernetAddress, StationType};
use veloce_gnss::Gpsd;

#[derive(Parser, Default, Debug)]
struct Arguments {
    dev: String,
    log_level: String,
}

const DEV_TOKEN: Token = Token(0);
const GPSD_TOKEN: Token = Token(1);

fn main() {
    let args = Arguments::parse();
    utils::setup_logging(args.log_level.as_str());

    // Mio setup
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);

    let ll_addr = EthernetAddress([0x04, 0xe5, 0x48, 0xfa, 0xde, 0xca]);

    // Configure Raw socket device
    let mut device = RawSocket::new(args.dev.as_str(), Medium::Ethernet).unwrap();

    // Register it into the polling registry
    poll.registry()
        .register(&mut device, DEV_TOKEN, Interest::READABLE)
        .unwrap();

    // Build GnCore
    let mut router_config = GnCoreGonfig::new(StationType::PassengerCar, Pseudonym(0xabcd));
    router_config.random_seed = 0xfadecafedeadbeef;
    router_config.addr_config_mode = GnAddrConfigMode::Managed(ll_addr);
    let mut router = GnCore::new(router_config, Instant::now());

    // Configure interface
    let mut config = Config::new(ll_addr.into(), None);
    let mut iface = Interface::new(config, device.inner_mut());

    // Create CAM socket
    let cam_socket = socket::cam::Socket::new();

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let cam_handle: veloce::iface::SocketHandle = sockets.add(cam_socket);

    // Create GPSD client
    let mut gpsd = Gpsd::new(
        "10.29.2.229:2947".to_string(),
        //"127.0.0.1:2947".to_string(),
        poll.registry().try_clone().unwrap(),
        GPSD_TOKEN,
    )
    .expect("malformed GPSD server address");

    loop {
        // Update timestamp.
        let now = Instant::now();
        router.set_timestamp(now);

        // Process each event.
        for event in events.iter() {
            match event.token() {
                GPSD_TOKEN => {
                    gpsd.ready(event);
                    gpsd.fetch_position()
                        .try_into()
                        .map(|fix| {
                            router.set_position(fix);
                        })
                        .ok();
                }
                DEV_TOKEN => {
                    debug!("Rx available");
                }
                // We don't expect any events with tokens other than those we provided.
                _ => unreachable!(),
            }
        }

        trace!("gpsd poll");
        let _ = gpsd.poll();

        trace!("iface poll");
        iface.poll(&mut router, device.inner_mut(), &mut sockets);
        let socket = sockets.get_mut::<socket::cam::Socket>(cam_handle);

        if socket.can_recv() {
            match socket.recv() {
                Ok(msg) => {
                    info!("Received CAM msg: {:?}", msg);
                }
                Err(e) => error!("Error cam.recv() : {}", e),
            }
        }

        let iface_timeout = iface.poll_delay(now, &sockets);
        trace!("timeout: {:?}", iface_timeout);

        // Poll Mio for events, blocking until we get an event or a timeout.
        poll.poll(&mut events, iface_timeout.map(|t| t.into()))
            .unwrap();
    }
}

pub struct RawSocket {
    inner: VeloceRawSocket,
}

impl RawSocket {
    pub fn new(name: &str, medium: Medium) -> io::Result<RawSocket> {
        Ok(RawSocket {
            inner: VeloceRawSocket::new(name, medium)?,
        })
    }

    pub fn inner_mut(&mut self) -> &mut VeloceRawSocket {
        &mut self.inner
    }
}

impl Source for RawSocket {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        SourceFd(&self.inner.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        SourceFd(&self.inner.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        SourceFd(&self.inner.as_raw_fd()).deregister(registry)
    }
}
