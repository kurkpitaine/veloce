use super::{check, core::Core};
use crate::geonet::{
    common::{
        geonet_packet::{ExtendedHeader, GeonetPacket},
        location_table::LocationTable,
        PacketBuffer, PacketBufferNode,
    },
    config::{
        GN_LOCATION_SERVICE_PACKET_BUFFER_ENTRY_COUNT as LS_BUF_ENTRY_NUM,
        GN_LOCATION_SERVICE_PACKET_BUFFER_SIZE as LS_BUF_SIZE, GN_PROTOCOL_VERSION,
        GN_UC_FORWARDING_PACKET_BUFFER_ENTRY_COUNT as UC_BUF_ENTRY_NUM,
        GN_UC_FORWARDING_PACKET_BUFFER_SIZE as UC_BUF_SIZE,
    },
    time::Instant,
    wire::{
        BHNextHeader, BasicHeader, BasicHeaderRepr, BeaconHeader, BeaconHeaderRepr, CommonHeader,
        CommonHeaderRepr, GeonetPacketType, HardwareAddress, SequenceNumber, SingleHopHeader,
        SingleHopHeaderRepr,
    },
};

/// Geonetworking Access Layer Interface Handler.
pub struct AccessHandler<'a> {
    /// Location Table of the Access Handler.
    location_table: LocationTable,
    /// Sequence Number of the Access Handler.
    sequence_number: SequenceNumber,
    /// Location Service packet buffer.
    ls_buffer: PacketBuffer<GeonetPacket<'a>, LS_BUF_ENTRY_NUM, LS_BUF_SIZE>,
    /// Unicast forwarding packet buffer.
    uc_forwarding_buffer: PacketBuffer<GeonetPacket<'a>, UC_BUF_ENTRY_NUM, UC_BUF_SIZE>,
    /// Core instance.
    gn_core: &'a mut Core<'a>,
}

impl AccessHandler<'_> {
    /// Processes a Geonetworking packet.
    pub(super) fn process_geonet_packet<'packet>(
        &mut self,
        timestamp: Instant,
        gn_packet: &'packet [u8],
        src_addr: HardwareAddress,
        dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        self.process_basic_header(timestamp, gn_packet, src_addr, dst_addr)
    }

    /// Processes the Basic Header of a Geonetworking packet.
    pub(super) fn process_basic_header<'packet>(
        &mut self,
        timestamp: Instant,
        gn_packet: &'packet [u8],
        src_addr: HardwareAddress,
        dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let bh = check!(BasicHeader::new_checked(gn_packet));
        let bh_repr = check!(BasicHeaderRepr::parse(&bh));

        // Check Geonetworking protocol version.
        if bh_repr.version != GN_PROTOCOL_VERSION {
            println!(
                "network: {}",
                stringify!(bh_repr.version != GN_PROTOCOL_VERSION)
            );
            return None;
        }

        match bh_repr.next_header {
            BHNextHeader::Any | BHNextHeader::CommonHeader => {
                self.process_common_header(timestamp, bh_repr, bh.payload(), src_addr, dst_addr)
            }
            BHNextHeader::SecuredHeader => todo!(),
            BHNextHeader::Unknown(_) => {
                println!("network: unknown basic header next header field value");
                return None;
            }
        }
    }

    /// Processes the Common Header of a Geonetworking packet.
    pub(super) fn process_common_header<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        bh_payload: &'packet [u8],
        src_addr: HardwareAddress,
        dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let ch = check!(CommonHeader::new_checked(bh_payload));
        let ch_repr = check!(CommonHeaderRepr::parse(&ch));

        if ch_repr.max_hop_limit < bh_repr.remaining_hop_limit {
            println!(
                "network: malformed {}",
                stringify!(ch_repr.max_hop_limit < bh_repr.remaining_hop_limit)
            );
            return None;
        }

        // TODO: Process the BC forwarding packet buffer and the forwarding algorithm having caused the buffering needs to be re-executed.

        match ch_repr.header_type {
            GeonetPacketType::Any => {
                println!("network: discard 'Any' packet type");
                return None;
            }
            GeonetPacketType::Beacon => self.process_beacon(
                timestamp,
                bh_repr,
                ch_repr,
                ch.payload(),
                src_addr,
                // dst_addr,
            ),
            GeonetPacketType::GeoUnicast => todo!(),
            GeonetPacketType::GeoAnycastCircle
            | GeonetPacketType::GeoAnycastRect
            | GeonetPacketType::GeoAnycastElip => todo!(),
            GeonetPacketType::GeoBroadcastCircle
            | GeonetPacketType::GeoBroadcastRect
            | GeonetPacketType::GeoBroadcastElip => todo!(),
            GeonetPacketType::TsbSingleHop => todo!(),
            GeonetPacketType::TsbMultiHop => todo!(),
            GeonetPacketType::LsRequest => todo!(),
            GeonetPacketType::LsReply => todo!(),
            GeonetPacketType::Unknown(_) => todo!(),
        }
    }

    /// Processes a Beaconing packet.
    pub(super) fn process_beacon<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        // dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let beacon = check!(BeaconHeader::new_checked(ch_payload));
        let beacon_repr = check!(BeaconHeaderRepr::parse(&beacon));

        // TODO: check if payload length is 0.

        /* Step 3: perform duplicate address detection. */
        self.gn_core
            .duplicate_address_detection(src_addr, beacon_repr.source_position_vector.address);

        /* Step 4: update Location table */
        self.location_table.update(
            timestamp,
            beacon_repr.source_position_vector,
            bh_repr.version,
        );

        /* Step 5: update PDR in Location table */
        let packet_size = bh_repr.buffer_len() + ch_repr.buffer_len() + beacon_repr.buffer_len();
        self.location_table
            .update_pdr(beacon_repr.source_position_vector, packet_size, timestamp)
            .ok();

        /* Step 6: set ìs_neighbour` flag in Location table */
        self.location_table
            .update_neighbour_flag(beacon_repr.source_position_vector, true)
            .ok();

        None
    }

    /// Processes a Single-Hop Broadcast packet.
    pub(super) fn process_single_hop_roadcast<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        // dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let shb = check!(SingleHopHeader::new_checked(ch_payload));
        let shb_repr = check!(SingleHopHeaderRepr::parse(&shb));

        /* Step 3: perform duplicate address detection. */
        self.gn_core
            .duplicate_address_detection(src_addr, shb_repr.source_position_vector.address);

        /* Step 4: update Location table */
        self.location_table
            .update(timestamp, shb_repr.source_position_vector, bh_repr.version);

        /* Step 5: update PDR in Location table */
        let packet_size = bh_repr.buffer_len() + ch_repr.buffer_len() + shb_repr.buffer_len();
        self.location_table
            .update_pdr(shb_repr.source_position_vector, packet_size, timestamp)
            .ok();

        /* Step 6: set ìs_neighbour` flag in Location table */
        self.location_table
            .update_neighbour_flag(shb_repr.source_position_vector, true)
            .ok();

        /* Step 7: Go to upper layer */
        None
    }
}
