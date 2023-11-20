pub mod geonet;

use geonet::wire::etsi_its::{self, ItsPduHeader};
use log::trace;

#[macro_use]
extern crate uom;

use geonet::common::geo_area::{Circle, GeoArea, GeoPosition, Shape};
use geonet::iface::{Config, Interface, SocketSet};
use geonet::network::{GnCore, GnCoreGonfig, Request, Transport};
use geonet::phy::{wait as phy_wait, Medium, RawSocket};
use geonet::socket::btp::Request as BtpRequest;
use geonet::storage::PacketBuffer;
use geonet::time::{Duration, Instant};
use geonet::types::{degree, meter, Distance, Latitude};
use geonet::utils;
use geonet::wire::{EthernetAddress, GnAddress, StationType};
use geonet::{socket, time};
use rasn::types::SequenceOf;
use uom::si::f32::Angle;

use std::os::unix::io::AsRawFd;

use crate::geonet::types::tenth_of_microdegree;
use crate::geonet::wire::btp;
use crate::geonet::wire::etsi_its::*;

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

    // Create gn socket
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

    // Create BTP-B socket
    let btp_b_rx_buffer = PacketBuffer::new(
        vec![
            socket::btp::RxPacketMetadata::EMPTY,
            socket::btp::RxPacketMetadata::EMPTY,
            socket::btp::RxPacketMetadata::EMPTY,
        ],
        vec![0; 65535],
    );

    let btp_b_tx_buffer = PacketBuffer::new(
        vec![
            socket::btp::TxPacketMetadata::EMPTY,
            socket::btp::TxPacketMetadata::EMPTY,
            socket::btp::TxPacketMetadata::EMPTY,
        ],
        vec![0; 65535],
    );
    let btp_b_socket = socket::btp::SocketB::new(btp_b_rx_buffer, btp_b_tx_buffer);

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let gn_handle = sockets.add(gn_socket);
    let btp_b_handle = sockets.add(btp_b_socket);

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

        if timestamp >= next_gac_transmit {
            trace!("next_gac_transmit");
            let data = [0x51, 0x16, 0x64];
            let req_meta = Request {
                transport: Transport::Anycast(GeoArea {
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

        let socket = sockets.get_mut::<socket::btp::SocketB>(btp_b_handle);
        if !socket.is_open() {
            socket.bind(btp::ports::CAM).unwrap()
        }

        if timestamp >= next_gbc_transmit {
            trace!("next_gbc_transmit");
            let lat = Latitude::new::<degree>(48.271947);
            let lon = Latitude::new::<degree>(-3.614961);

            let cam = fill_cam(
                etsi_its::Latitude(lat.get::<tenth_of_microdegree>() as i32),
                etsi_its::Longitude(lon.get::<tenth_of_microdegree>() as i32),
            );

            let buf = rasn::uper::encode(&cam).unwrap();

            let req_meta = BtpRequest {
                transport: Transport::Broadcast(GeoArea {
                    shape: Shape::Circle(Circle {
                        radius: Distance::new::<meter>(500.0),
                    }),
                    position: GeoPosition {
                        latitude: lat,
                        longitude: lon,
                    },
                    angle: Angle::new::<degree>(0.0),
                }),
                ..Default::default()
            };
            socket.send_slice(&buf, req_meta).unwrap();
            next_gbc_transmit = timestamp + Duration::from_secs(7);
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

/// Fills a CAM message with basic content
fn fill_cam(lat: etsi_its::Latitude, lon: etsi_its::Longitude) -> CAM {
    let header = ItsPduHeader::new(2, 2, StationID(123));

    let station_type = StationType(15);

    let alt = etsi_its::Altitude::new(AltitudeValue(1000), AltitudeConfidence::Unavailable);

    let pos_confidence = PosConfidenceEllipse::new(
        SemiAxisLength(4095),
        SemiAxisLength(4095),
        HeadingValue(3601),
    );
    let ref_pos = ReferencePosition::new(lat.clone(), lon.clone(), pos_confidence, alt);
    let basic_container = BasicContainer::new(station_type, ref_pos);

    let prot_zone = ProtectedCommunicationZone::new(
        ProtectedZoneType::PermanentCenDsrcTolling,
        None,
        lat,
        lon,
        None,
        Some(ProtectedZoneID(0xfe)),
    );

    let mut prot_zones = ProtectedCommunicationZonesRSU(SequenceOf::new());
    prot_zones.0.push(prot_zone);

    let hf_container = HighFrequencyContainer::RsuContainerHighFrequency(
        RSUContainerHighFrequency::new(Some(prot_zones)),
    );

    let cam_params = CamParameters::new(basic_container, hf_container, None, None);
    let gen_time = GenerationDeltaTime(12345);
    let coop_awareness = CoopAwareness::new(gen_time, cam_params);

    CAM::new(header, coop_awareness)
}
