use std::io;
use std::net::UdpSocket;

use log::{debug, info, trace};

use veloce::iface::{Config, Interface, SocketSet};
use veloce::network::{GnCore, GnCoreGonfig};
use veloce::phy::{wait_many, Medium, RawSocket};
use veloce::socket;
use veloce::storage::PacketBuffer;
use veloce::time::Instant;
use veloce::utils;
use veloce::wire::{EthernetAddress, GnAddress, StationType};

use veloce::conformance::etsi::State as UpperTester;

use std::os::unix::io::AsRawFd;

fn main() {
    utils::setup_logging("info");

    let udp_socket = UdpSocket::bind("0.0.0.0:29000").expect("Failed to bind to address");
    udp_socket
        .set_nonblocking(true)
        .expect("Failed to set UDP socket as non-blocking");
    let mut udp_buffer = [0; 4096];
    let udp_fd = udp_socket.as_raw_fd();
    info!("Uppertester server listening on 0.0.0.0:29000");

    // Configure geonetworking device
    let ll_addr = EthernetAddress([0x00, 0x0c, 0x6c, 0x0d, 0x14, 0x70]);
    let mut device = RawSocket::new("en0", Medium::Ethernet).unwrap();
    let dev_fd = device.as_raw_fd();
    let fds = vec![udp_fd, dev_fd];

    // Configure interface
    let mut config = Config::new(ll_addr.into());
    config.random_seed = 0xfadecafedeadbeef;
    let mut iface = Interface::new(config, &mut device);

    // Build GnCore
    let router_addr = GnAddress::new(true, StationType::RoadSideUnit, ll_addr);
    let router_config = GnCoreGonfig::new(router_addr);
    let mut router = GnCore::new(router_config, Instant::now());

    // Create gn socket
    let gn_rx_buffer =
        PacketBuffer::new(vec![socket::geonet::RxPacketMetadata::EMPTY], vec![0; 4096]);
    let gn_tx_buffer =
        PacketBuffer::new(vec![socket::geonet::TxPacketMetadata::EMPTY], vec![0; 4096]);
    let gn_socket = socket::geonet::Socket::new(gn_rx_buffer, gn_tx_buffer);

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let gn_handle: veloce::iface::SocketHandle = sockets.add(gn_socket);

    // Configure UpperTester
    let ut = UpperTester::new(router_addr, gn_handle);

    loop {
        // Update timestamp.
        let timestamp = Instant::now();
        router.now = timestamp;

        match udp_socket.recv_from(&mut udp_buffer) {
            Ok((size, source)) => {
                debug!("Received {} bytes from {}", size, source);
                if size > 0 {
                    let res_opt = ut.ut_dispatcher(
                        timestamp,
                        &mut iface,
                        &mut router,
                        &mut sockets,
                        &udp_buffer,
                    );
                    if let Some(res) = res_opt {
                        udp_socket.send_to(&res, source).unwrap();
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("Failed to read data in UDP socket: {e}"),
        };

        trace!("poll");
        iface.poll(&mut router, &mut device, &mut sockets);

        trace!("wait_many");
        wait_many(&fds, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
