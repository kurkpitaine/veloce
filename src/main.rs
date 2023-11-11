pub mod geonet;

use log::trace;

#[macro_use]
extern crate uom;

use geonet::common::area::{Area, Circle, GeoPosition, Shape};
use geonet::iface::{Config, Interface, SocketSet};
use geonet::network::{GnCore, GnCoreGonfig, Request, Transport};
use geonet::phy::{wait as phy_wait, Medium, RawSocket};
use geonet::storage::PacketBuffer;
use geonet::time::{Duration, Instant};
use geonet::types::{degree, meter, Distance, Latitude};
use geonet::utils;
use geonet::wire::{BtpBHeader, EthernetAddress, GnAddress, StationType};
use geonet::{socket, time};
use uom::si::f32::Angle;

use std::os::unix::io::AsRawFd;

use crate::geonet::network::UpperProtocol;
use crate::geonet::wire::{btp, BtpBRepr};

fn main() {
    utils::setup_logging("trace");
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
            socket::geonet::RxPacketMetadata::EMPTY,
        ],
        vec![0; 65535],
    );
    let gn_tx_buffer = PacketBuffer::new(
        vec![
            socket::geonet::TxPacketMetadata::EMPTY,
            socket::geonet::TxPacketMetadata::EMPTY,
            socket::geonet::TxPacketMetadata::EMPTY,
        ],
        vec![0; 65535],
    );
    let gn_socket = socket::geonet::Socket::new(gn_rx_buffer, gn_tx_buffer);

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let gn_handle = sockets.add(gn_socket);

    let mut next_shb_transmit = Instant::now() + Duration::from_millis(500);
    let mut next_tsb_transmit = Instant::now() + Duration::from_secs(2);
    let mut next_uc_transmit = Instant::now() + Duration::from_secs(5);
    let mut next_gbc_transmit = Instant::now() + Duration::from_secs(7);
    let mut next_gac_transmit = Instant::now() + Duration::from_secs(8);

    loop {
        let timestamp = Instant::now();
        router.now = timestamp;
        trace!("poll");
        iface.poll(&mut router, &mut device, &mut sockets);
        let socket = sockets.get_mut::<socket::geonet::Socket>(gn_handle);

        if timestamp >= next_shb_transmit {
            trace!("next_shb_transmit");
            let data = [0xfe, 0xbe, 0x1c, 0x09];
            let req_meta = Request {
                transport: Transport::SingleHopBroadcast,
                ..Default::default()
            };
            socket.send_slice(&data, req_meta).unwrap();
            next_shb_transmit = timestamp + Duration::from_secs(10);
        }

        if timestamp >= next_tsb_transmit {
            trace!("next_tsb_transmit");
            let data = [0xba, 0xba, 0xbe, 0xbe];
            let req_meta = Request {
                transport: Transport::TopoBroadcast,
                ..Default::default()
            };
            socket.send_slice(&data, req_meta).unwrap();
            next_tsb_transmit = timestamp + Duration::from_secs(5);
        }

        if timestamp >= next_uc_transmit {
            trace!("next_uc_transmit");
            let data = [0xbe, 0x1c, 0x90];
            let req_meta = Request {
                transport: Transport::Unicast(GnAddress::new(
                    true,
                    StationType::PassengerCar,
                    EthernetAddress([0xb0, 0xde, 0x6c, 0x0d, 0x65, 0xfe]),
                )),
                ..Default::default()
            };
            socket.send_slice(&data, req_meta).unwrap();
            next_uc_transmit = timestamp + Duration::from_secs(15);
        }

        if timestamp >= next_gbc_transmit {
            trace!("next_gbc_transmit");
            let data = [0xfe, 0x1e, 0xe7];
            let mut buf = [0u8; 7];
            let mut btp_hdr = BtpBHeader::new_unchecked(&mut buf);
            let btp_repr = BtpBRepr {
                dst_port: btp::ports::CAM,
                dst_port_info: 0,
            };
            btp_repr.emit(&mut btp_hdr);
            btp_hdr.payload_mut().copy_from_slice(&data);

            let req_meta = Request {
                upper_proto: UpperProtocol::BtpB,
                transport: Transport::Broadcast(Area {
                    shape: Shape::Circle(Circle {
                        radius: Distance::new::<meter>(500.0),
                    }),
                    position: GeoPosition {
                        latitude: Latitude::new::<degree>(48.271947),
                        longitude: Latitude::new::<degree>(-3.614961),
                        /* latitude: Latitude::new::<degree>(48.276434),
                        longitude: Latitude::new::<degree>(-3.5519532), */
                    },
                    angle: Angle::new::<degree>(0.0),
                }),
                ..Default::default()
            };
            socket.send_slice(&buf, req_meta).unwrap();
            next_gbc_transmit = timestamp + Duration::from_secs(7);
        }

        if timestamp >= next_gac_transmit {
            trace!("next_gac_transmit");
            let data = [0x51, 0x16, 0x64];
            let req_meta = Request {
                transport: Transport::Anycast(Area {
                    shape: Shape::Circle(Circle {
                        radius: Distance::new::<meter>(500.0),
                    }),
                    position: GeoPosition {
                        latitude: Latitude::new::<degree>(48.271947),
                        longitude: Latitude::new::<degree>(-3.614961),
                        /* latitude: Latitude::new::<degree>(48.276434),
                        longitude: Latitude::new::<degree>(-3.5519532), */
                    },
                    angle: Angle::new::<degree>(0.0),
                }),
                ..Default::default()
            };
            socket.send_slice(&data, req_meta).unwrap();
            next_gac_transmit = timestamp + Duration::from_secs(8);
        }

        router.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
        router.ego_position_vector.longitude = Latitude::new::<degree>(-3.5519532);

        let main_timeout = [
            next_shb_transmit,
            next_tsb_transmit,
            next_uc_transmit,
            next_gbc_transmit,
            next_gac_transmit,
        ]
        .iter()
        .min()
        .and_then(|t| Some(timestamp - *t));
        let iface_timeout = iface.poll_delay(timestamp, &sockets);

        let poll_timeout = [main_timeout, iface_timeout].into_iter().flatten().min();
        trace!("phy_wait");
        phy_wait(fd, poll_timeout).expect("wait error");
    }
}
