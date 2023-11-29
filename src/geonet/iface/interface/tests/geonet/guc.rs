use approx::assert_relative_eq;
use uom::si::{
    angle::degree,
    velocity::{centimeter_per_second, meter_per_second},
};

use crate::geonet::{
    config,
    iface::ContextMeta,
    types::{tenth_of_microdegree, Heading, Latitude, Longitude, Speed},
    wire::{
        BHNextHeader, BasicHeaderRepr, CommonHeaderRepr, EthernetRepr,
        GeonetPacketType, GnAddress, GnProtocol, LongPositionVectorRepr, ShortPositionVectorRepr,
        StationType, BASIC_HEADER_LEN, COMMON_HEADER_LEN, UNICAST_HEADER_LEN, UnicastRepr,
    },
};

use super::*;

/// Length of a Geo Unicast packet.
const GUC_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + UNICAST_HEADER_LEN;

/// Make a Geo Unicast packet
fn make_guc_packet() -> (EthernetRepr, GeonetUnicast) {
    let sender_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let geo_uc = GeonetUnicast {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::GeoUnicast,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        extended_header: UnicastRepr {
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
            destination_position_vector: ShortPositionVectorRepr {
                address: GnAddress::new(
                    true,
                    StationType::PassengerCar,
                    EthernetAddress([0x04, 0x04, 0x04, 0x04, 0x04, 0x04]),
                ),
                timestamp: TAI2004::now().into(),
                latitude: Latitude::new::<degree>(48.278316),
                longitude: Longitude::new::<degree>(-3.553161),
            },
        },
    };

    let ethernet = EthernetRepr {
        src_addr: sender_ll_addr,
        dst_addr: EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
        ethertype: EthernetProtocol::Geonet,
    };

    (ethernet, geo_uc)
}

#[test]
fn test_receive_ls_rep() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    let (ethernet, geo_uc) = make_guc_packet();

    let ctx_meta = meta!(core, iface);

    let mut buf = [0u8; GUC_LEN];
    geo_uc.emit(&mut buf);

    let res = iface
        .inner
        .process_geonet_packet(ctx_meta, &mut sockets, &buf, ethernet);

    // Processing an Geo Unicast packet with a remaining hop limit > 1 should return.
    assert!(res.is_some());

    let (_, dst_ll_addr, forwarded) = res.unwrap();

    // Link layer destination address should be broadcast
    assert!(dst_ll_addr.is_broadcast());

    // Packet type
    let gn_repr = forwarded.geonet_repr();
    assert!(matches!(gn_repr, GeonetRepr::Unicast(_)));

    if let GeonetRepr::LocationServiceReply(lsr) = gn_repr {
        let guc_spv = lsr.extended_header.source_position_vector;
        let geo_uc_spv = geo_uc.extended_header.source_position_vector;
        let lsr_dpv = lsr.extended_header.destination_position_vector;
        let geo_uc_dpv = geo_uc.extended_header.destination_position_vector;

        assert_eq!(
            lsr.extended_header.sequence_number,
            geo_uc.extended_header.sequence_number
        );
        assert_eq!(guc_spv.address, geo_uc_spv.address);
        assert_eq!(guc_spv.timestamp, geo_uc_spv.timestamp);
        assert_eq!(guc_spv.is_accurate, geo_uc_spv.is_accurate);

        assert_relative_eq!(
            guc_spv.latitude.get::<tenth_of_microdegree>(),
            geo_uc_spv.latitude.get::<tenth_of_microdegree>()
        );
        assert_relative_eq!(
            guc_spv.longitude.get::<tenth_of_microdegree>(),
            geo_uc_spv.longitude.get::<tenth_of_microdegree>()
        );

        assert_relative_eq!(
            guc_spv.speed.get::<centimeter_per_second>(),
            geo_uc_spv.speed.get::<centimeter_per_second>()
        );
        assert_relative_eq!(
            guc_spv.heading.get::<degree>(),
            geo_uc_spv.heading.get::<degree>()
        );

        assert_eq!(lsr_dpv.address, geo_uc_dpv.address);
        assert_eq!(lsr_dpv.timestamp, geo_uc_dpv.timestamp);

        assert_relative_eq!(
            lsr_dpv.latitude.get::<tenth_of_microdegree>(),
            geo_uc_dpv.latitude.get::<tenth_of_microdegree>()
        );
        assert_relative_eq!(
            lsr_dpv.longitude.get::<tenth_of_microdegree>(),
            geo_uc_dpv.longitude.get::<tenth_of_microdegree>()
        );
    };

    // Basic header
    assert_eq!(
        forwarded.basic_header().version,
        geo_uc.basic_header.version
    );
    assert_eq!(
        forwarded.basic_header().next_header,
        geo_uc.basic_header.next_header
    );
    assert_eq!(
        forwarded.basic_header().lifetime,
        geo_uc.basic_header.lifetime
    );
    assert_eq!(
        forwarded.basic_header().remaining_hop_limit,
        geo_uc.basic_header.remaining_hop_limit - 1
    );

    // Common header
    assert_eq!(forwarded.common_header(), geo_uc.common_header);

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(
        &geo_uc
            .extended_header
            .source_position_vector
            .address
            .mac_addr(),
    );
    assert!(entry_opt.is_some());

    // Should not be a neighbor
    let entry = entry_opt.unwrap();
    assert!(!entry.is_neighbour);
}
