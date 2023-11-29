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
        BHNextHeader, BasicHeaderRepr, CommonHeaderRepr, EthernetRepr, GeonetLocationServiceReply,
        GeonetLocationServiceRequest, GeonetPacketType, GnAddress, GnProtocol,
        LocationServiceReplyRepr, LocationServiceRequestRepr, LongPositionVectorRepr,
        ShortPositionVectorRepr, StationType, BASIC_HEADER_LEN, COMMON_HEADER_LEN,
        LOCATION_SERVICE_REP_HEADER_LEN, LOCATION_SERVICE_REQ_HEADER_LEN,
    },
};

use super::*;

/// Length of a Location Service Request packet.
const LS_REQ_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + LOCATION_SERVICE_REQ_HEADER_LEN;
/// Length of a Location Service Reply packet.
const LS_REP_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + LOCATION_SERVICE_REP_HEADER_LEN;

/// Make a LS Request packet
fn make_ls_req_packet() -> (EthernetRepr, GeonetLocationServiceRequest) {
    let sender_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let ls_req = GeonetLocationServiceRequest {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::LsRequest,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        extended_header: LocationServiceRequestRepr {
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
            request_address: GnAddress::new(
                false,
                StationType::Unknown(0),
                EthernetAddress([0x04, 0x04, 0x04, 0x04, 0x04, 0x04]),
            ),
        },
    };

    let ethernet = EthernetRepr {
        src_addr: sender_ll_addr,
        dst_addr: EthernetAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ethertype: EthernetProtocol::Geonet,
    };

    (ethernet, ls_req)
}

/// Make a LS Reply packet
fn make_ls_rep_packet() -> (EthernetRepr, GeonetLocationServiceReply) {
    let sender_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let ls_rep = GeonetLocationServiceReply {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::LsReply,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: config::GN_DEFAULT_HOP_LIMIT,
        },
        extended_header: LocationServiceReplyRepr {
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

    (ethernet, ls_rep)
}

#[test]
fn test_receive_ls_req() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    let (ethernet, ls_req) = make_ls_req_packet();

    let ctx_meta = meta!(core, iface);

    let mut buf = [0u8; LS_REQ_LEN];
    ls_req.emit(&mut buf);

    let res = iface
        .inner
        .process_geonet_packet(ctx_meta, &mut sockets, &buf, ethernet);

    // Processing an LS request packet with a remaining hop limit > 1 should return.
    assert!(res.is_some());

    let (_, dst_ll_addr, forwarded) = res.unwrap();

    // Link layer destination address should be broadcast
    assert!(dst_ll_addr.is_broadcast());

    // Packet type
    let gn_repr = forwarded.geonet_repr();
    assert!(matches!(gn_repr, GeonetRepr::LocationServiceRequest(_)));

    if let GeonetRepr::LocationServiceRequest(lsr) = gn_repr {
        let lsr_spv = lsr.extended_header.source_position_vector;
        let ls_req_spv = ls_req.extended_header.source_position_vector;

        assert_eq!(
            lsr.extended_header.sequence_number,
            ls_req.extended_header.sequence_number
        );
        assert_eq!(lsr_spv.address, ls_req_spv.address);
        assert_eq!(lsr_spv.timestamp, ls_req_spv.timestamp);
        assert_eq!(lsr_spv.is_accurate, ls_req_spv.is_accurate);

        assert_relative_eq!(
            lsr_spv.latitude.get::<tenth_of_microdegree>(),
            ls_req_spv.latitude.get::<tenth_of_microdegree>()
        );
        assert_relative_eq!(
            lsr_spv.longitude.get::<tenth_of_microdegree>(),
            ls_req_spv.longitude.get::<tenth_of_microdegree>()
        );

        assert_relative_eq!(
            lsr_spv.speed.get::<centimeter_per_second>(),
            ls_req_spv.speed.get::<centimeter_per_second>()
        );
        assert_relative_eq!(
            lsr_spv.heading.get::<degree>(),
            ls_req_spv.heading.get::<degree>()
        );

        assert_eq!(
            lsr.extended_header.request_address,
            ls_req.extended_header.request_address
        );
    };

    // Basic header
    assert_eq!(
        forwarded.basic_header().version,
        ls_req.basic_header.version
    );
    assert_eq!(
        forwarded.basic_header().next_header,
        ls_req.basic_header.next_header
    );
    assert_eq!(
        forwarded.basic_header().lifetime,
        ls_req.basic_header.lifetime
    );
    assert_eq!(
        forwarded.basic_header().remaining_hop_limit,
        ls_req.basic_header.remaining_hop_limit - 1
    );

    // Common header
    assert_eq!(forwarded.common_header(), ls_req.common_header);

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(
        &ls_req
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

#[test]
fn test_receive_ls_rep() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    let (ethernet, ls_rep) = make_ls_rep_packet();

    let ctx_meta = meta!(core, iface);

    let mut buf = [0u8; LS_REP_LEN];
    ls_rep.emit(&mut buf);

    let res = iface
        .inner
        .process_geonet_packet(ctx_meta, &mut sockets, &buf, ethernet);

    // Processing an LS request packet with a remaining hop limit > 1 should return.
    assert!(res.is_some());

    let (_, dst_ll_addr, forwarded) = res.unwrap();

    // Link layer destination address should be broadcast
    assert!(dst_ll_addr.is_broadcast());

    // Packet type
    let gn_repr = forwarded.geonet_repr();
    assert!(matches!(gn_repr, GeonetRepr::LocationServiceReply(_)));

    if let GeonetRepr::LocationServiceReply(lsr) = gn_repr {
        let lsr_spv = lsr.extended_header.source_position_vector;
        let ls_rep_spv = ls_rep.extended_header.source_position_vector;
        let lsr_dpv = lsr.extended_header.destination_position_vector;
        let ls_rep_dpv = ls_rep.extended_header.destination_position_vector;

        assert_eq!(
            lsr.extended_header.sequence_number,
            ls_rep.extended_header.sequence_number
        );
        assert_eq!(lsr_spv.address, ls_rep_spv.address);
        assert_eq!(lsr_spv.timestamp, ls_rep_spv.timestamp);
        assert_eq!(lsr_spv.is_accurate, ls_rep_spv.is_accurate);

        assert_relative_eq!(
            lsr_spv.latitude.get::<tenth_of_microdegree>(),
            ls_rep_spv.latitude.get::<tenth_of_microdegree>()
        );
        assert_relative_eq!(
            lsr_spv.longitude.get::<tenth_of_microdegree>(),
            ls_rep_spv.longitude.get::<tenth_of_microdegree>()
        );

        assert_relative_eq!(
            lsr_spv.speed.get::<centimeter_per_second>(),
            ls_rep_spv.speed.get::<centimeter_per_second>()
        );
        assert_relative_eq!(
            lsr_spv.heading.get::<degree>(),
            ls_rep_spv.heading.get::<degree>()
        );

        assert_eq!(lsr_dpv.address, ls_rep_dpv.address);
        assert_eq!(lsr_dpv.timestamp, ls_rep_dpv.timestamp);

        assert_relative_eq!(
            lsr_dpv.latitude.get::<tenth_of_microdegree>(),
            ls_rep_dpv.latitude.get::<tenth_of_microdegree>()
        );
        assert_relative_eq!(
            lsr_dpv.longitude.get::<tenth_of_microdegree>(),
            ls_rep_dpv.longitude.get::<tenth_of_microdegree>()
        );
    };

    // Basic header
    assert_eq!(
        forwarded.basic_header().version,
        ls_rep.basic_header.version
    );
    assert_eq!(
        forwarded.basic_header().next_header,
        ls_rep.basic_header.next_header
    );
    assert_eq!(
        forwarded.basic_header().lifetime,
        ls_rep.basic_header.lifetime
    );
    assert_eq!(
        forwarded.basic_header().remaining_hop_limit,
        ls_rep.basic_header.remaining_hop_limit - 1
    );

    // Common header
    assert_eq!(forwarded.common_header(), ls_rep.common_header);

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(
        &ls_rep
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
