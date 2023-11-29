use approx::assert_relative_eq;
use uom::si::{
    angle::degree,
    f32::{Angle, Length},
    length::meter,
    velocity::{centimeter_per_second, meter_per_second},
};

use crate::geonet::{
    config,
    iface::ContextMeta,
    types::{tenth_of_microdegree, Heading, Latitude, Longitude, Speed},
    wire::{
        BHNextHeader, BasicHeaderRepr, CommonHeaderRepr, EthernetRepr, GeoAnycastRepr,
        GeonetGeoAnycast, GeonetPacketType, GnAddress, GnProtocol, LongPositionVectorRepr,
        StationType, BASIC_HEADER_LEN, COMMON_HEADER_LEN, GEO_ANYCAST_HEADER_LEN,
    },
};

use super::*;

/// Length of a GAC packet, without payload.
const GAC_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + GEO_ANYCAST_HEADER_LEN;

/// Make a GAC packet
fn make_gac_packet() -> (EthernetRepr, GeonetGeoAnycast) {
    let sender_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let gac = GeonetGeoAnycast {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::GeoAnycastRect,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        extended_header: GeoAnycastRepr {
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

    (ethernet, gac)
}

#[test]
fn test_receive_gac() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    let (ethernet, gac) = make_gac_packet();

    let ctx_meta = meta!(core, iface);

    let mut buf = [0u8; GAC_LEN];
    gac.emit(&mut buf);

    let res = iface
        .inner
        .process_geonet_packet(ctx_meta, &mut sockets, &buf, ethernet);

    // Processing a GAC packet with a remaining hop limit > 1 should return.
    assert!(res.is_some());

    let (_, dst_ll_addr, forwarded) = res.unwrap();

    // Link layer destination address should be broadcast
    assert!(dst_ll_addr.is_broadcast());

    // Packet type
    let gn_repr = forwarded.geonet_repr();
    assert!(matches!(gn_repr, GeonetRepr::Anycast(_)));

    if let GeonetRepr::Anycast(anycast) = gn_repr {
        let anycast_spv = anycast.extended_header.source_position_vector;
        let gac_spv = gac.extended_header.source_position_vector;

        assert_eq!(
            anycast.extended_header.sequence_number,
            gac.extended_header.sequence_number
        );
        assert_eq!(anycast_spv.address, gac_spv.address);
        assert_eq!(anycast_spv.timestamp, gac_spv.timestamp);
        assert_eq!(anycast_spv.is_accurate, gac_spv.is_accurate);

        assert_relative_eq!(
            anycast_spv.latitude.get::<tenth_of_microdegree>(),
            gac_spv.latitude.get::<tenth_of_microdegree>()
        );
        assert_relative_eq!(
            anycast_spv.longitude.get::<tenth_of_microdegree>(),
            gac_spv.longitude.get::<tenth_of_microdegree>()
        );

        assert_relative_eq!(
            anycast_spv.speed.get::<centimeter_per_second>(),
            gac_spv.speed.get::<centimeter_per_second>()
        );
        assert_relative_eq!(
            anycast_spv.heading.get::<degree>(),
            gac_spv.heading.get::<degree>()
        );

        assert_relative_eq!(
            anycast.extended_header.latitude.get::<degree>(),
            gac.extended_header.latitude.get::<degree>()
        );
        assert_relative_eq!(
            anycast.extended_header.longitude.get::<degree>(),
            gac.extended_header.longitude.get::<degree>()
        );
        assert_relative_eq!(
            anycast.extended_header.distance_a.get::<meter>(),
            gac.extended_header.distance_a.get::<meter>()
        );
        assert_relative_eq!(
            anycast.extended_header.distance_b.get::<meter>(),
            gac.extended_header.distance_b.get::<meter>()
        );
        assert_relative_eq!(
            anycast.extended_header.angle.get::<degree>(),
            gac.extended_header.angle.get::<degree>()
        );
    };

    // Basic header
    assert_eq!(forwarded.basic_header().version, gac.basic_header.version);
    assert_eq!(
        forwarded.basic_header().next_header,
        gac.basic_header.next_header
    );
    assert_eq!(forwarded.basic_header().lifetime, gac.basic_header.lifetime);
    assert_eq!(
        forwarded.basic_header().remaining_hop_limit,
        gac.basic_header.remaining_hop_limit - 1
    );

    // Common header
    assert_eq!(forwarded.common_header(), gac.common_header);

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(
        &gac.extended_header
            .source_position_vector
            .address
            .mac_addr(),
    );
    assert!(entry_opt.is_some());

    // Should not be a neighbor
    let entry = entry_opt.unwrap();
    assert!(!entry.is_neighbour);
}
