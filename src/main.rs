pub mod geonet;

#[macro_use]
extern crate uom;

use geonet::time::Duration;
use geonet::types::*;
use std::io;
use tokio::net::UdpSocket;

#[tokio::main]
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
            next_header: geonet::wire::geonet::common_header::NextHeader::Any,
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
