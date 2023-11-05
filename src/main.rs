pub mod geonet;

#[macro_use]
extern crate uom;

use geonet::config::GN_DEFAULT_HOP_LIMIT;
use geonet::iface::{Config, Interface, SocketSet};
use geonet::network::{GnCore, GnCoreGonfig};
use geonet::phy::{wait as phy_wait, Medium, RawSocket};
use geonet::storage::PacketBuffer;
use geonet::time::Instant;
use geonet::{socket, time};
//use geonet::types::*;
use geonet::wire::{EthernetAddress, GnAddress, StationType};

//use std::io;
use std::os::unix::io::AsRawFd;

use crate::geonet::config::{GN_DEFAULT_PACKET_LIFETIME, GN_DEFAULT_TRAFFIC_CLASS};
use crate::geonet::network::{Request, Transport, UpperProtocol};
use crate::geonet::time::Duration;
//use tokio::net::UdpSocket;

fn main() {
    let ll_addr = EthernetAddress([0x00, 0x0c, 0x6c, 0x0d, 0x14, 0x70]);

    // Configure device
    let mut device = RawSocket::new("en0", Medium::Ethernet).unwrap();
    let fd = device.as_raw_fd();

    // Configure interface
    let mut config = Config::new(ll_addr.into());
    config.random_seed = 0xfadecafedeadbeef;
    let mut iface = Interface::new(config, &mut device);

    // Build GnCore
    let router_addr = GnAddress::new(true, StationType::RoadSideUnit, ll_addr);
    let router_config = GnCoreGonfig::new(router_addr);
    let mut router = GnCore::new(router_config, Instant::now());

    // Create socket
    let gn_rx_buffer = PacketBuffer::new(
        vec![
            socket::geonet::RxPacketMetadata::EMPTY,
            socket::geonet::RxPacketMetadata::EMPTY,
        ],
        vec![0; 65535],
    );
    let gn_tx_buffer = PacketBuffer::new(
        vec![
            socket::geonet::TxPacketMetadata::EMPTY,
            socket::geonet::TxPacketMetadata::EMPTY,
        ],
        vec![0; 65535],
    );
    let gn_socket = socket::geonet::Socket::new(gn_rx_buffer, gn_tx_buffer);

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let gn_handle = sockets.add(gn_socket);

    let mut next_transmit = Instant::now();
    let mut next_uc_transmit = Instant::now() /* + Duration::from_secs(5) */;

    loop {
        let timestamp = Instant::now();
        router.now = timestamp;
        iface.poll(&mut router, &mut device, &mut sockets);
        let socket = sockets.get_mut::<socket::geonet::Socket>(gn_handle);

        if timestamp >= next_transmit {
            let data = [0xfe, 0xbe, 0x1c, 0x09];
            let req_meta = Request {
                upper_proto: UpperProtocol::Any,
                transport: Transport::SingleHopBroadcast,
                ali_id: (),
                its_aid: (),
                max_lifetime: GN_DEFAULT_PACKET_LIFETIME,
                max_hop_limit: 1,
                traffic_class: GN_DEFAULT_TRAFFIC_CLASS,
            };
            socket.send_slice(&data, req_meta).unwrap();
            next_transmit = timestamp + Duration::from_secs(10);
        }

        if timestamp >= next_uc_transmit {
            let data = [0xbe, 0x1c, 0x90];
            let req_meta = Request {
                upper_proto: UpperProtocol::Any,
                transport: Transport::Unicast(GnAddress::new(
                    true,
                    StationType::PassengerCar,
                    EthernetAddress([0xb0, 0xde, 0x6c, 0x0d, 0x65, 0xfe]),
                )),
                ali_id: (),
                its_aid: (),
                max_lifetime: GN_DEFAULT_PACKET_LIFETIME,
                max_hop_limit: GN_DEFAULT_HOP_LIMIT,
                traffic_class: GN_DEFAULT_TRAFFIC_CLASS,
            };
            socket.send_slice(&data, req_meta).unwrap();
            next_uc_transmit = timestamp + Duration::from_secs(15);
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}

/* #[tokio::main]
async fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:60000").await?;
    loop {
        let mut buf = [0u8; 1460];
        let mut eth_frame = geonet::wire::EthernetFrame::new_checked(&mut buf).unwrap();
        let eth_repr = geonet::wire::EthernetRepr {
            src_addr: geonet::wire::EthernetAddress::from_bytes(&[
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ]),
            dst_addr: geonet::wire::EthernetAddress::from_bytes(&[
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ]),
            ethertype: geonet::wire::ethernet::EtherType::Geonet,
        };

        eth_repr.emit(&mut eth_frame);

        let mut basic_hdr =
            geonet::wire::geonet::basic_header::Header::new_checked(eth_frame.payload_mut())
                .unwrap();
        let bh_repr = geonet::wire::geonet::basic_header::Repr {
            version: 1,
            next_header: geonet::wire::geonet::basic_header::NextHeader::CommonHeader,
            lifetime: Duration::from_secs(1),
            remaining_hop_limit: 1,
        };

        bh_repr.emit(&mut basic_hdr);

        let mut common_hdr =
            geonet::wire::geonet::common_header::Header::new_checked(basic_hdr.payload_mut())
                .unwrap();
        let common_repr = geonet::wire::geonet::common_header::Repr {
            next_header: geonet::wire::GnProtocol::Any,
            header_type: geonet::wire::geonet::common_header::HeaderType::Beacon,
            traffic_class: geonet::wire::geonet::TrafficClass::new(false, false, 1),
            mobile: false,
            payload_len: 0,
            max_hop_limit: 1,
        };

        common_repr.emit(&mut common_hdr);

        let mut beacon_hdr =
            geonet::wire::geonet::beacon_header::Header::new_checked(common_hdr.payload_mut())
                .unwrap();
        let beacon_repr = geonet::wire::geonet::beacon_header::Repr {
            source_position_vector: geonet::wire::geonet::long_position_vector::Repr {
                address: geonet::wire::GnAddress::new(
                    true,
                    geonet::wire::geonet::StationType::RoadSideUnit,
                    eth_repr.src_addr.clone(),
                ),
                timestamp: geonet::time::Instant::from_millis(123456789),
                latitude: geonet::types::Latitude::new::<degree>(48.271883),
                longitude: geonet::types::Longitude::new::<degree>(-3.6149876),
                is_accurate: true,
                speed: Speed::new::<kilometer_per_hour>(145.2),
                heading: Heading::new::<degree>(180.0),
            },
        };
        println!("{}", beacon_repr);

        beacon_repr.emit(&mut beacon_hdr);

        let len = sock.send_to(&buf, "10.129.1.1:60000").await?;
        //let len = sock.send_to(&buf, "192.168.1.254:60000").await?;
        println!("{:?} bytes sent", len);
    }
}
 */
