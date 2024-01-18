use uom::si::{angle::degree, velocity::meter_per_second};

use crate::{
    config,
    iface::ContextMeta,
    types::{Heading, Latitude, Longitude, Speed},
    wire::{
        BHNextHeader, BasicHeaderRepr, CommonHeaderRepr, EthernetRepr, GeonetPacketType,
        GeonetSingleHop, GnAddress, GnProtocol, LongPositionVectorRepr, SingleHopHeaderRepr,
        StationType, BASIC_HEADER_LEN, COMMON_HEADER_LEN, SINGLE_HOP_HEADER_LEN,
    },
};

use super::*;

/// Length of a SHB packet, without payload.
const SHB_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + SINGLE_HOP_HEADER_LEN;

/// Make a SHB packet
fn make_shb_packet() -> (EthernetRepr, GeonetSingleHop) {
    let sender_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let shb = GeonetSingleHop {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: 1,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::TsbSingleHop,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: 1,
        },
        extended_header: SingleHopHeaderRepr {
            source_position_vector: LongPositionVectorRepr {
                address: GnAddress::new(true, StationType::PassengerCar, sender_ll_addr),
                timestamp: TAI2004::now().into(),
                latitude: Latitude::new::<degree>(48.271947),
                longitude: Longitude::new::<degree>(-3.614961),
                is_accurate: true,
                speed: Speed::new::<meter_per_second>(0.0),
                heading: Heading::new::<degree>(0.0),
            },
        },
    };

    let ethernet = EthernetRepr {
        src_addr: sender_ll_addr,
        dst_addr: EthernetAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ethertype: EthernetProtocol::Geonet,
    };

    (ethernet, shb)
}

#[test]
fn test_receive_shb() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    let (ethernet, shb) = make_shb_packet();

    let ctx_meta = meta!(core, iface);

    let mut buf = [0u8; SHB_LEN];
    shb.emit(&mut buf);

    let res = iface
        .inner
        .process_geonet_packet(ctx_meta, &mut sockets, &buf, ethernet);

    // Processing a SHB packet should return nothing.
    assert!(res.is_none());

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(
        &shb.extended_header
            .source_position_vector
            .address
            .mac_addr(),
    );
    assert!(entry_opt.is_some());

    // Should be a neighbor
    let entry = entry_opt.unwrap();
    assert!(entry.is_neighbour);
}
