use std::io;
use std::net::UdpSocket;
use std::rc::Rc;

use log::{debug, info};

use veloce::conformance::etsi::State as UpperTester;
use veloce::iface::{Config, Interface, SocketSet};
use veloce::network::{GnAddrConfigMode, GnCore, GnCoreGonfig};
use veloce::phy::{wait_many, Medium, RawSocket};
use veloce::socket;
use veloce::storage::PacketBuffer;
use veloce::time::Instant;
use veloce::types::{degree, Latitude, Longitude, Pseudonym};
use veloce::wire::{EthernetAddress, StationType};

use std::os::unix::io::AsRawFd;

use clap::Parser;
use thread_priority::*;

#[derive(Parser, Default, Debug)]
struct Arguments {
    dev: String,
    log_level: String,
}

fn main() {
    assert!(set_current_thread_priority(ThreadPriority::Max).is_ok());

    let args = Arguments::parse();

    let ll_addr = mac_address::mac_address_by_name(args.dev.as_str())
        .unwrap()
        .expect("Failed to get device mac address");

    let udp_socket = Rc::new(UdpSocket::bind("0.0.0.0:29000").expect("Failed to bind to address"));
    udp_socket
        .set_nonblocking(true)
        .expect("Failed to set UDP socket as non-blocking");
    let mut udp_buffer = [0; 4096];
    let udp_fd = udp_socket.as_raw_fd();
    info!("Uppertester server listening on 0.0.0.0:29000");

    // Configure geonetworking device
    let ll_addr = EthernetAddress(ll_addr.bytes());
    let mut device = RawSocket::new(args.dev.as_str(), Medium::Ethernet).unwrap();
    let dev_fd = device.as_raw_fd();
    let fds = vec![udp_fd, dev_fd];

    // Configure interface
    let config = Config::new(ll_addr.into());
    let mut iface = Interface::new(config, &mut device);

    // Build GnCore
    let mut router_config = GnCoreGonfig::new(StationType::PassengerCar, Pseudonym(0xabcd));
    router_config.random_seed = 0xfadecafedeadbeef;
    router_config.addr_config_mode = GnAddrConfigMode::Managed(ll_addr);
    router_config.latitude = Latitude::new::<degree>(48.276463);
    router_config.longitude = Longitude::new::<degree>(-3.551840);

    router_config.position_accurate = true;
    let mut router = GnCore::new(router_config, Instant::now());

    // Create gn socket
    let gn_rx_buffer =
        PacketBuffer::new(vec![socket::geonet::RxPacketMetadata::EMPTY], vec![0; 4096]);
    let gn_tx_buffer =
        PacketBuffer::new(vec![socket::geonet::TxPacketMetadata::EMPTY], vec![0; 4096]);
    let gn_socket = socket::geonet::Socket::new(gn_rx_buffer, gn_tx_buffer);

    // Create denm socket
    let denm_socket = socket::denm::Socket::new(vec![], vec![]);

    // Add them to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let gn_handle: veloce::iface::SocketHandle = sockets.add(gn_socket);
    let denm_handle: veloce::iface::SocketHandle = sockets.add(denm_socket);

    // Configure UpperTester
    let mut ut = UpperTester::new(router.address(), gn_handle, denm_handle);

    loop {
        // Update timestamp.
        let timestamp = Instant::now();
        router.set_timestamp(timestamp);

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
                        source,
                    );
                    if let Some(res) = res_opt {
                        udp_socket.send_to(&res, source).unwrap();
                        debug!("Sent {} bytes to {}", res.len(), source);
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("Failed to read data in UDP socket: {e}"),
        };

        iface.poll(&mut router, &mut device, &mut sockets);

        let gn_socket = sockets.get_mut::<socket::geonet::Socket>(gn_handle);
        if gn_socket.can_recv() {
            let (buf, meta) = gn_socket.recv().unwrap();
            if let Some((dst, data)) = ut.ut_gn_event(meta, buf) {
                udp_socket.send_to(&data, dst).unwrap();
                debug!("Sent {} bytes to {}", data.len(), dst);
            }
        }

        let denm_socket = sockets.get_mut::<socket::denm::Socket>(denm_handle);
        if let Some((dst, data)) = ut.ut_denm_event(denm_socket.poll(timestamp)) {
            udp_socket.send_to(&data, dst).unwrap();
            debug!("Sent {} bytes to {}", data.len(), dst);
        }

        wait_many(&fds, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
