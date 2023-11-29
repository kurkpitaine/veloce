mod gac;
mod gbc;
mod guc;
mod ls;
mod shb;
mod tsb;

use uom::si::{angle::degree, velocity::meter_per_second};

use crate::geonet::{
    config,
    iface::ContextMeta,
    time::TAI2004,
    types::{Heading, Latitude, Longitude, Speed},
    wire::{
        BHNextHeader, BasicHeaderRepr, BeaconHeaderRepr, CommonHeaderRepr, EthernetRepr,
        GeonetBeacon, GeonetPacketType, GnAddress, GnProtocol, LongPositionVectorRepr, StationType,
        BASIC_HEADER_LEN, BEACON_HEADER_LEN, COMMON_HEADER_LEN,
    },
};

use super::*;

macro_rules! meta {
    ($core: ident, $iface: ident) => {
        ContextMeta {
            core: &mut $core,
            ls: &mut $iface.location_service,
            ls_buffer: &mut $iface.ls_buffer,
            uc_forwarding_buffer: &mut $iface.uc_forwarding_buffer,
            bc_forwarding_buffer: &mut $iface.bc_forwarding_buffer,
            cb_forwarding_buffer: &mut $iface.cb_forwarding_buffer,
        }
    };
}

use meta;

#[test]
fn test_receive_beacon() {
    let (mut core, mut iface, mut sockets, _device) = setup(Medium::Ethernet);

    core.ego_position_vector.latitude = Latitude::new::<degree>(48.276434);
    core.ego_position_vector.longitude = Longitude::new::<degree>(-3.5519532);
    core.now = Instant::now();

    // GeonetPacket::new_beacon(basic_header, common_header, beacon_header);
    const BEACON_LEN: usize = BASIC_HEADER_LEN + COMMON_HEADER_LEN + BEACON_HEADER_LEN;

    let recv_ll_addr = EthernetAddress([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);

    let beacon = GeonetBeacon {
        basic_header: BasicHeaderRepr {
            version: config::GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: config::GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: 1,
        },
        common_header: CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::Beacon,
            traffic_class: config::GN_DEFAULT_TRAFFIC_CLASS,
            mobile: true,
            payload_len: 0,
            max_hop_limit: 1,
        },
        extended_header: BeaconHeaderRepr {
            source_position_vector: LongPositionVectorRepr {
                address: GnAddress::new(true, StationType::PassengerCar, recv_ll_addr),
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
        src_addr: recv_ll_addr,
        dst_addr: EthernetAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ethertype: EthernetProtocol::Geonet,
    };

    let ctx_meta = meta!(core, iface);

    let mut buf = [0u8; BEACON_LEN];
    beacon.emit(&mut buf);

    let res = iface
        .inner
        .process_geonet_packet(ctx_meta, &mut sockets, &buf, ethernet);

    // Processing a beacon packet should return nothing.
    assert!(res.is_none());

    // Station should be in Location table
    let entry_opt = iface.inner.location_table.find(&recv_ll_addr);
    assert!(entry_opt.is_some());

    // Should be a neighbor
    let entry = entry_opt.unwrap();
    assert!(entry.is_neighbour);
}
