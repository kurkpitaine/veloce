use std::io;

use clap::Parser;
use log::{debug, error, info, trace};

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use veloce::iface::{Config, CongestionControl, Interface, SocketSet};
use veloce::network::{GnAddrConfigMode, GnCore, GnCoreGonfig};
use veloce::socket;
use veloce::time::Instant;
use veloce::types::{Power, Pseudonym};
use veloce::utils;
use veloce::wire::{EthernetAddress, StationType};
use veloce_gnss::Gpsd;
use veloce_nxp_phy::{NxpChannel, NxpConfig, NxpRadio, NxpUsbDevice, NxpWirelessChannel};

#[derive(Parser, Default, Debug)]
struct Arguments {
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

    let config = NxpConfig::new(
        NxpRadio::A,
        NxpChannel::Zero,
        NxpWirelessChannel::Chan180,
        Power::from_dbm_i32(23),
        ll_addr,
    );
    // Configure NXP device
    let mut device = UsbSocket::new(config).unwrap();
    device
        .inner_mut()
        .commit_config()
        .expect("Cannot configure device");

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
    let config = Config::new(ll_addr.into());
    let mut iface = Interface::new(config, device.inner_mut());
    iface.set_congestion_control(CongestionControl::Limeric);

    // Create CAM socket
    let cam_socket = socket::cam::Socket::new();

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let cam_handle: veloce::iface::SocketHandle = sockets.add(cam_socket);

    // Create GPSD client
    let mut gpsd = Gpsd::new(
        "127.0.0.1:2947".to_string(),
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

        // trace!("gpsd poll");
        let _ = gpsd.poll();

        // trace!("iface poll");
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
        // trace!("timeout: {:?}", iface_timeout);

        // Poll Mio for events, blocking until we get an event or a timeout.
        poll.poll(&mut events, iface_timeout.map(|t| t.into()))
            .unwrap();
    }
}

pub struct UsbSocket {
    inner: NxpUsbDevice,
}

impl UsbSocket {
    pub fn new(config: NxpConfig) -> io::Result<UsbSocket> {
        Ok(UsbSocket {
            inner: NxpUsbDevice::new(config).map_err(|_| io::ErrorKind::Other)?,
        })
    }

    pub fn inner_mut(&mut self) -> &mut NxpUsbDevice {
        &mut self.inner
    }
}

// Not very clean here, but USB support is only for development purposes. So
// keep it this way for now.
impl Source for UsbSocket {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        let fd = self.inner.pollfds()[0];
        SourceFd(&fd).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        let fd = self.inner.pollfds()[0];
        SourceFd(&fd).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        let fd = self.inner.pollfds()[0];
        SourceFd(&fd).deregister(registry)
    }
}
