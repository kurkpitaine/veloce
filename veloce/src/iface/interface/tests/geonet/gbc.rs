use approx::assert_relative_eq;
use uom::si::{
    angle::degree,
    f32::{Angle, Length},
    length::meter,
    velocity::{centimeter_per_second, meter_per_second},
};

use crate::{
    config,
    iface::ContextMeta,
    types::{tenth_of_microdegree, Heading, Latitude, Longitude, Speed},
    wire::{
        BHNextHeader, BasicHeaderRepr, CommonHeaderRepr, EthernetRepr, GeoBroadcastRepr,
        GeonetGeoBroadcast, GeonetPacketType, GnAddress, GnProtocol, LongPositionVectorRepr,
        StationType, BASIC_HEADER_LEN, COMMON_HEADER_LEN, GEO_BROADCAST_HEADER_LEN,
    },
};

use super::*;

/// Length of a GBC packet, without payload.
const GBC_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + GEO_BROADCAST_HEADER_LEN;

/// Make a GBC packet
fn make_gbc_packet() -> (EthernetRepr, GeonetGeoBroadcast) {
    let sender_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let gbc = GeonetGeoBroadcast {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::GeoBroadcastRect,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        extended_header: GeoBroadcastRepr {
            sequence_number: SequenceNumber(1664),
            source_position_vector: LongPositionVectorRepr {
                address: GnAddress::new(true, StationType::PassengerCar, sender_ll_addr),
                timestamp: TAI2004::now().into(),
                latitude: Latitude::new::<degree>(48.271947),
                longitude: Longitude::new::<degree>(-3.6149619),
                is_accurate: true,
                speed: Speed::new::<meter_per_second>(0.0),
                heading: Heading::new::<degree>(0.0),
            },
            latitude: Latitude::new::<degree>(48.271947),
            longitude: Longitude::new::<degree>(-3.6149619),
            distance_a: Length::new::<meter>(500.0),
            distance_b: Length::new::<meter>(250.0),
            angle: Angle::new::<degree>(20.0),
        },
    };

    let ethernet = EthernetRepr {
        src_addr: sender_ll_addr,
        dst_addr: EthernetAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ethertype: EthernetProtocol::Geonet,
    };

    (ethernet, gbc)
}

#[test]
fn test_receive_gbc() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    let (ethernet, gbc) = make_gbc_packet();

    let ctx_meta = meta!(core, iface);
    let pkt_meta = PacketMeta::default();
    let mut sec_buf = SecuredDataBuffer::default();

    let mut buf = [0u8; GBC_LEN];
    gbc.emit(&mut buf);

    let res = iface.inner.process_geonet_packet(
        ctx_meta,
        &mut sockets,
        pkt_meta,
        &buf,
        ethernet,
        &mut sec_buf,
    );

    // Processing a GBC packet with a remaining hop limit > 1 should return.
    assert!(res.is_some());

    let (_, dst_ll_addr, forwarded) = res.unwrap();

    // Link layer destination address should be broadcast
    assert!(dst_ll_addr.is_broadcast());

    // Packet type
    let gn_repr = forwarded.repr().inner();
    assert!(matches!(gn_repr, GeonetVariant::Broadcast(_)));

    if let GeonetVariant::Broadcast(broadcast) = gn_repr {
        let broadcast_spv = broadcast.extended_header.source_position_vector;
        let gbc_spv = gbc.extended_header.source_position_vector;

        assert_eq!(
            broadcast.extended_header.sequence_number,
            gbc.extended_header.sequence_number
        );
        assert_eq!(broadcast_spv.address, gbc_spv.address);
        assert_eq!(broadcast_spv.timestamp, gbc_spv.timestamp);
        assert_eq!(broadcast_spv.is_accurate, gbc_spv.is_accurate);

        assert_relative_eq!(
            broadcast_spv.latitude.get::<tenth_of_microdegree>(),
            gbc_spv.latitude.get::<tenth_of_microdegree>()
        );
        assert_relative_eq!(
            broadcast_spv.longitude.get::<tenth_of_microdegree>(),
            gbc_spv.longitude.get::<tenth_of_microdegree>()
        );

        assert_relative_eq!(
            broadcast_spv.speed.get::<centimeter_per_second>(),
            gbc_spv.speed.get::<centimeter_per_second>()
        );
        assert_relative_eq!(
            broadcast_spv.heading.get::<degree>(),
            gbc_spv.heading.get::<degree>()
        );

        assert_relative_eq!(
            broadcast.extended_header.latitude.get::<degree>(),
            gbc.extended_header.latitude.get::<degree>()
        );
        assert_relative_eq!(
            broadcast.extended_header.longitude.get::<degree>(),
            gbc.extended_header.longitude.get::<degree>()
        );
        assert_relative_eq!(
            broadcast.extended_header.distance_a.get::<meter>(),
            gbc.extended_header.distance_a.get::<meter>()
        );
        assert_relative_eq!(
            broadcast.extended_header.distance_b.get::<meter>(),
            gbc.extended_header.distance_b.get::<meter>()
        );
        assert_relative_eq!(
            broadcast.extended_header.angle.get::<degree>(),
            gbc.extended_header.angle.get::<degree>()
        );
    };

    // Basic header
    assert_eq!(gn_repr.basic_header().version, gbc.basic_header.version);
    assert_eq!(
        gn_repr.basic_header().next_header,
        gbc.basic_header.next_header
    );
    assert_eq!(gn_repr.basic_header().lifetime, gbc.basic_header.lifetime);
    assert_eq!(
        gn_repr.basic_header().remaining_hop_limit,
        gbc.basic_header.remaining_hop_limit - 1
    );

    // Common header
    assert_eq!(gn_repr.common_header(), gbc.common_header);

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(
        &gbc.extended_header
            .source_position_vector
            .address
            .mac_addr(),
    );
    assert!(entry_opt.is_some());

    // Should not be a neighbor
    let entry = entry_opt.unwrap();
    assert!(!entry.is_neighbour);
}
