use std::os::fd::AsRawFd;

use log::{error, info, trace};
use thread_priority::*;

use veloce::iface::{Config, Interface, SocketSet};
use veloce::network::{GnCore, GnCoreGonfig};
use veloce::phy::wait as phy_wait;
use veloce::socket;
use veloce::time::Instant;
use veloce::types::Pseudonym;
use veloce::utils;
use veloce::wire::{EthernetAddress, GnAddress, StationType};

use veloce_nxp_phy::NxpLlcDevice;

use clap::Parser;

#[derive(Parser, Default, Debug)]
struct Arguments {
    dev: String,
    log_level: String,
}

fn main() {
    let args = Arguments::parse();
    utils::setup_logging(args.log_level.as_str());
    assert!(set_current_thread_priority(ThreadPriority::Max).is_ok());

    let ll_addr = EthernetAddress([0x04, 0xe5, 0x48, 0xfa, 0xde, 0xca]);

    // Configure NXP device
    let mut device = NxpLlcDevice::new(args.dev.as_str()).unwrap();
    let dev_fd = device.as_raw_fd();

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
        println!("iface_timeout: {:?}", iface_timeout);

        trace!("phy_wait");
        phy_wait(dev_fd, iface_timeout).expect("wait error");
    }
}
