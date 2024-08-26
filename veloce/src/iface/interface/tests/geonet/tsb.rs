use approx::assert_relative_eq;
use uom::si::{
    angle::degree,
    velocity::{centimeter_per_second, meter_per_second},
};

use crate::{
    config,
    iface::ContextMeta,
    types::{tenth_of_microdegree, Heading, Latitude, Longitude, Speed},
    wire::{
        BHNextHeader, BasicHeaderRepr, CommonHeaderRepr, EthernetRepr, GeonetPacketType,
        GeonetTopoBroadcast, GnAddress, GnProtocol, LongPositionVectorRepr, StationType,
        TopoBroadcastRepr, BASIC_HEADER_LEN, COMMON_HEADER_LEN, TOPO_BROADCAST_HEADER_LEN,
    },
};

use super::*;

/// Length of a TSB packet, without payload.
const TSB_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + TOPO_BROADCAST_HEADER_LEN;

/// Make a TSB packet
fn make_tsb_packet() -> (EthernetRepr, GeonetTopoBroadcast) {
    let sender_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let tsb = GeonetTopoBroadcast {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::TsbMultiHop,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        extended_header: TopoBroadcastRepr {
            sequence_number: SequenceNumber(1664),
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

    (ethernet, tsb)
}

#[test]
fn test_receive_tsb() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    let (ethernet, tsb) = make_tsb_packet();

    let ctx_meta = meta!(core, iface);
    let pkt_meta = PacketMeta::default();
    let mut sec_buf = SecuredDataBuffer::default();

    let mut buf = [0u8; TSB_LEN];
    tsb.emit(&mut buf);

    let res = iface.inner.process_geonet_packet(
        ctx_meta,
        &mut sockets,
        pkt_meta,
        &buf,
        ethernet,
        &mut sec_buf,
    );

    // Processing a TSB packet with a remaining hop limit > 1 should return.
    assert!(res.is_some());

    let (_, dst_ll_addr, forwarded) = res.unwrap();

    // Link layer destination address should be broadcast
    assert!(dst_ll_addr.is_broadcast());

    // Packet type
    let gn_repr = forwarded.repr().inner();
    assert!(matches!(gn_repr, GeonetVariant::TopoBroadcast(_)));

    if let GeonetVariant::TopoBroadcast(topo) = gn_repr {
        let topo_spv = topo.extended_header.source_position_vector;
        let tsb_spv = tsb.extended_header.source_position_vector;

        assert_eq!(
            topo.extended_header.sequence_number,
            tsb.extended_header.sequence_number
        );
        assert_eq!(topo_spv.address, tsb_spv.address);
        assert_eq!(topo_spv.timestamp, tsb_spv.timestamp);
        assert_eq!(topo_spv.is_accurate, tsb_spv.is_accurate);

        assert_relative_eq!(
            topo_spv.latitude.get::<tenth_of_microdegree>(),
            tsb_spv.latitude.get::<tenth_of_microdegree>(),
            max_relative = 0.1
        );
        assert_relative_eq!(
            topo_spv.longitude.get::<tenth_of_microdegree>(),
            tsb_spv.longitude.get::<tenth_of_microdegree>(),
            max_relative = 0.1
        );

        assert_relative_eq!(
            topo_spv.speed.get::<centimeter_per_second>(),
            tsb_spv.speed.get::<centimeter_per_second>()
        );
        assert_relative_eq!(
            topo_spv.heading.get::<degree>(),
            tsb_spv.heading.get::<degree>()
        );
    };

    // Basic header
    assert_eq!(gn_repr.basic_header().version, tsb.basic_header.version);
    assert_eq!(
        gn_repr.basic_header().next_header,
        tsb.basic_header.next_header
    );
    assert_eq!(gn_repr.basic_header().lifetime, tsb.basic_header.lifetime);
    assert_eq!(
        gn_repr.basic_header().remaining_hop_limit,
        tsb.basic_header.remaining_hop_limit - 1
    );

    // Common header
    assert_eq!(gn_repr.common_header(), tsb.common_header);

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(
        &tsb.extended_header
            .source_position_vector
            .address
            .mac_addr(),
    );
    assert!(entry_opt.is_some());

    // Should not be a neighbor
    let entry = entry_opt.unwrap();
    assert!(!entry.is_neighbour);
}
