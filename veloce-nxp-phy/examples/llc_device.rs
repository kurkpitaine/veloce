use std::os::fd::AsRawFd;

use log::{debug, trace};

use veloce::iface::{Config, Interface, SocketSet};
use veloce::network::{GnAddrConfigMode, GnCore, GnCoreGonfig};
use veloce::phy::wait as phy_wait;
use veloce::socket;
use veloce::time::Instant;
use veloce::types::{Power, Pseudonym};
use veloce::wire::{EthernetAddress, StationType};

use veloce_nxp_phy::{NxpChannel, NxpConfig, NxpLlcDevice, NxpRadio, NxpWirelessChannel};

use clap::Parser;

#[derive(Parser, Default, Debug)]
struct Arguments {
    dev: String,
    log_level: String,
}

fn main() {
    let args = Arguments::parse();
    let ll_addr = EthernetAddress([0x04, 0xe5, 0x48, 0xfa, 0xde, 0xca]);

    let config = NxpConfig::new(
        NxpRadio::A,
        NxpChannel::Zero,
        NxpWirelessChannel::Chan180,
        Power::from_dbm_i32(23),
        ll_addr,
    );

    // Configure NXP device
    let mut device = NxpLlcDevice::new(args.dev.as_str(), config).unwrap();

    // Wait for the device to be ready.
    let mut device = device.wait_for_ready().unwrap();

    let dev_fd = device.as_raw_fd();

    // Configure interface
    let config = Config::new(ll_addr.into());
    let mut iface = Interface::new(config, &mut device);

    // Build GnCore
    let mut router_config = GnCoreGonfig::new(StationType::RoadSideUnit, Pseudonym(0xabcd));
    router_config.random_seed = 0xfadecafedeadbeef;
    router_config.addr_config_mode = GnAddrConfigMode::Managed(ll_addr);
    let mut router = GnCore::new(router_config, Instant::now());

    // Create CAM socket
    let cam_socket = socket::cam::Socket::new();

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let _cam_handle: veloce::iface::SocketHandle = sockets.add(cam_socket);

    loop {
        // Update timestamp.
        let timestamp = Instant::now();
        router.set_timestamp(timestamp);

        trace!("iface poll");
        iface.poll(&mut router, &mut device, &mut sockets);

        let iface_timeout = iface.poll_delay(timestamp, &sockets);
        debug!("iface_timeout: {:?}", iface_timeout);

        trace!("phy_wait");
        phy_wait(dev_fd, iface_timeout).expect("wait error");
    }
}
