use log::{debug, trace};

use rasn::types::SequenceOf;
use veloce::iface::{Config, Interface, SocketSet};
use veloce::network::{GnCore, GnCoreGonfig, Transport};
use veloce::socket;
use veloce::socket::btp::Request as BtpRequest;
use veloce::storage::PacketBuffer;
use veloce::time::{Duration, Instant, TAI2004};
use veloce::types::{degree, tenth_of_microdegree, Latitude, Longitude};
use veloce::utils;
use veloce::wire::{
    btp,
    etsi_its::{self, *},
    EthernetAddress, GnAddress, StationType,
};

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
    let router_config = GnCoreGonfig::new(router_addr);
    let mut router = GnCore::new(router_config, Instant::now());

    // Create BTP-B socket
    let btp_b_rx_buffer =
        PacketBuffer::new(vec![socket::btp::b::RxPacketMetadata::EMPTY], vec![0; 4096]);

    let btp_b_tx_buffer =
        PacketBuffer::new(vec![socket::btp::b::TxPacketMetadata::EMPTY], vec![0; 4096]);
    let btp_b_socket = socket::btp::SocketB::new(btp_b_rx_buffer, btp_b_tx_buffer);

    // Add it to a SocketSet
    let mut sockets = SocketSet::new(vec![]);
    let btp_b_handle: veloce::iface::SocketHandle = sockets.add(btp_b_socket);

    let mut next_cam_tx = Instant::now() + Duration::from_secs(1);

    loop {
        // Update timestamp.
        let timestamp = Instant::now();
        router.now = timestamp;

        trace!("iface poll");
        iface.poll(&mut router, &mut device, &mut sockets);
        let socket = sockets.get_mut::<socket::btp::SocketB>(btp_b_handle);
        if !socket.is_open() {
            socket.bind(btp::ports::CAM).unwrap()
        }

        if timestamp >= next_cam_tx {
            trace!("next_cam_tx");
            let lat = Latitude::new::<degree>(48.271947);
            let lon = Longitude::new::<degree>(-3.614961);
            router.ego_position_vector.latitude = lat;
            router.ego_position_vector.longitude = lon;
            router.ego_position_vector.timestamp = TAI2004::from_unix_instant(timestamp).into();

            let cam = fill_cam(
                etsi_its::Latitude(lat.get::<tenth_of_microdegree>() as i32),
                etsi_its::Longitude(lon.get::<tenth_of_microdegree>() as i32),
            );

            let buf = rasn::uper::encode(&cam).unwrap();

            let req_meta = BtpRequest {
                transport: Transport::SingleHopBroadcast,
                ..Default::default()
            };
            socket.send_slice(&buf, req_meta).unwrap();
            next_cam_tx = timestamp + Duration::from_millis(100);
        }

        let iface_timeout = iface.poll_delay(timestamp, &sockets);

        let poll_timeout = [Some(timestamp - next_cam_tx), iface_timeout]
            .into_iter()
            .flatten()
            .min();

        trace!("poll_wait");
        match device.poll_wait(poll_timeout) {
            Ok(avail) => debug!("{} bytes available", avail),
            Err(e) => debug!("Error while polling : {}", e),
        }
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
