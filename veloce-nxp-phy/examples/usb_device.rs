use log::{debug, error, info, trace};

use veloce::iface::{Config, Interface, SocketSet};
use veloce::network::{GnCore, GnCoreGonfig};
use veloce::socket;
use veloce::time::Instant;
use veloce::types::Pseudonym;
use veloce::utils;
use veloce::wire::{EthernetAddress, GnAddress, StationType};

use veloce_nxp_phy::NxpUsbDevice;

use clap::Parser;

#[derive(Parser, Default, Debug)]
struct Arguments {
    log_level: String,
}

fn main() {
    let args = Arguments::parse();
    utils::setup_logging(args.log_level.as_str());

    let ll_addr = EthernetAddress([0x04, 0xe5, 0x48, 0xfa, 0xde, 0xca]);

    // Configure NXP device
    let mut device = NxpUsbDevice::new().unwrap();
    device.configure().expect("Cannot configure device");

    // Configure interface
    let mut config = Config::new(ll_addr.into());
    config.random_seed = 0xfadecafedeadbeef;
    let mut iface = Interface::new(config, &mut device);

    // Build GnCore
    let router_addr = GnAddress::new(true, StationType::RoadSideUnit, ll_addr);
    let router_config = GnCoreGonfig::new(router_addr, Pseudonym(0xabcd));
    let mut router = GnCore::new(router_config, Instant::now());

    // Create CAM socket
    let cam_socket = socket::cam::Socket::new();

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let cam_handle: veloce::iface::SocketHandle = sockets.add(cam_socket);

    loop {
        // Update timestamp.
        let timestamp = Instant::now();
        router.now = timestamp;

        trace!("iface poll");
        iface.poll(&mut router, &mut device, &mut sockets);
        let socket = sockets.get_mut::<socket::cam::Socket>(cam_handle);

        if socket.can_recv() {
            match socket.recv() {
                Ok(msg) => {
                    info!("Received CAM msg: {:?}", msg);
                }
                Err(e) => error!("Error cam.recv() : {}", e),
            }
        }

        let iface_timeout = iface.poll_delay(timestamp, &sockets);

        trace!("poll_wait");
        match device.poll_wait(iface_timeout) {
            Ok(avail) => debug!("{} bytes available", avail),
            Err(e) => debug!("Error while polling : {}", e),
        }
    }
}
