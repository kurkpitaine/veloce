use super::{check, core::Core};
use crate::geonet::{
    common::{
        area::Area,
        location_table::{compare_position_vector_freshness, LocationTable},
        packet::{GeonetPacket, GeonetPayload, PacketMetadata},
        PacketBuffer,
    },
    config::{
        GnAreaForwardingAlgorithm, GnNonAreaForwardingAlgorithm, GN_AREA_FORWARDING_ALGORITHM,
        GN_BC_FORWARDING_PACKET_BUFFER_ENTRY_COUNT as BC_BUF_ENTRY_NUM,
        GN_BC_FORWARDING_PACKET_BUFFER_SIZE as BC_BUF_SIZE, GN_DEFAULT_HOP_LIMIT,
        GN_DEFAULT_PACKET_LIFETIME, GN_DEFAULT_TRAFFIC_CLASS, GN_IS_MOBILE,
        GN_LOCATION_SERVICE_PACKET_BUFFER_ENTRY_COUNT as LS_BUF_ENTRY_NUM,
        GN_LOCATION_SERVICE_PACKET_BUFFER_SIZE as LS_BUF_SIZE, GN_NON_AREA_FORWARDING_ALGORITHM,
        GN_PROTOCOL_VERSION, GN_UC_FORWARDING_PACKET_BUFFER_ENTRY_COUNT as UC_BUF_ENTRY_NUM,
        GN_UC_FORWARDING_PACKET_BUFFER_SIZE as UC_BUF_SIZE,
    },
    time::Instant,
    wire::{
        BHNextHeader, BasicHeader, BasicHeaderRepr, BeaconHeader, BeaconHeaderRepr, CHNextHeader,
        CommonHeader, CommonHeaderRepr, GeoAnycastHeader, GeoAnycastRepr, GeoBroadcastHeader,
        GeoBroadcastRepr, GeonetPacketType, HardwareAddress, LocationServiceReplyHeader,
        LocationServiceReplyRepr, LocationServiceRequestHeader, LocationServiceRequestRepr,
        SequenceNumber, SingleHopHeader, SingleHopHeaderRepr, TopoBroadcastHeader,
        TopoBroadcastRepr, UnicastHeader, UnicastRepr,
    },
};

/// Geonetworking Access Layer Interface Handler.
pub struct AccessHandler<'a> {
    /// Location Table of the Access Handler.
    location_table: LocationTable,
    /// Sequence Number of the Access Handler.
    sequence_number: SequenceNumber,
    /// Location Service packet buffer.
    ls_buffer: PacketBuffer<PacketMetadata, LS_BUF_ENTRY_NUM, LS_BUF_SIZE>,
    /// Unicast forwarding packet buffer.
    uc_forwarding_buffer: PacketBuffer<PacketMetadata, UC_BUF_ENTRY_NUM, UC_BUF_SIZE>,
    /// Broadcast forwarding packet buffer.
    bc_forwarding_buffer: PacketBuffer<PacketMetadata, BC_BUF_ENTRY_NUM, BC_BUF_SIZE>,
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
        let ch_payload = ch.payload();
        match ch_repr.header_type {
            GeonetPacketType::Any => {
                println!("network: discard 'Any' packet type");
                return None;
            }
            GeonetPacketType::Beacon => {
                self.process_beacon(timestamp, bh_repr, ch_repr, ch_payload, src_addr)
            }
            GeonetPacketType::GeoUnicast => {
                self.process_unicast(timestamp, bh_repr, ch_repr, ch_payload, src_addr)
            }
            GeonetPacketType::GeoAnycastCircle
            | GeonetPacketType::GeoAnycastRect
            | GeonetPacketType::GeoAnycastElip => {
                self.process_geo_anycast(timestamp, bh_repr, ch_repr, ch_payload, src_addr)
            }
            GeonetPacketType::GeoBroadcastCircle
            | GeonetPacketType::GeoBroadcastRect
            | GeonetPacketType::GeoBroadcastElip => {
                self.process_geo_broadcast(timestamp, bh_repr, ch_repr, ch_payload, src_addr)
            }
            GeonetPacketType::TsbSingleHop => {
                self.process_single_hop_broadcast(timestamp, bh_repr, ch_repr, ch_payload, src_addr)
            }
            GeonetPacketType::TsbMultiHop => self
                .process_topo_scoped_broadcast(timestamp, bh_repr, ch_repr, ch_payload, src_addr),
            GeonetPacketType::LsRequest => {
                self.process_ls_request(timestamp, bh_repr, ch_repr, ch_payload, src_addr)
            }
            GeonetPacketType::LsReply => {
                self.process_ls_reply(timestamp, bh_repr, ch_repr, ch_payload, src_addr)
            }
            GeonetPacketType::Unknown(u) => {
                println!("network: discard 'Unknown={}' packet type", u);
                return None;
            }
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
        let entry = self
            .location_table
            .update_mut(timestamp, &beacon_repr.source_position_vector);

        /* Step 5: update PDR in Location table */
        let packet_size = bh_repr.buffer_len() + ch_repr.buffer_len() + beacon_repr.buffer_len();
        entry.update_pdr(packet_size, timestamp);

        /* Step 6: set ìs_neighbour` flag in Location table */
        entry.is_neighbour = true;

        /* Step 7: Do nothing */

        /* Step 8: flush location service and unicast buffers for this packet source address */
        if entry.ls_pending {
            self.ls_buffer.flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address()
                    == beacon_repr.source_position_vector.address
            });

            entry.ls_pending = false;
        }

        self.uc_forwarding_buffer
            .flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address()
                    == beacon_repr.source_position_vector.address
            });

        None
    }

    /// Processes a Location Service request packet.
    pub(super) fn process_ls_request<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        //dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let ls_req = check!(LocationServiceRequestHeader::new_checked(ch_payload));
        let ls_req_repr = check!(LocationServiceRequestRepr::parse(&ls_req));

        // TODO: check if there are no bytes following the LS Request header.

        /* Steps 3 to 6 are equal on both destination and forwarder operations */

        /* Step 3: duplicate packet detection */
        let dup_opt = self
            .location_table
            .duplicate_packet_detection(ls_req_repr.request_address, ls_req_repr.sequence_number);

        if dup_opt.is_some_and(|x| x) {
            /* Packet is duplicate, discard packet. */
            return None;
        }

        /* Step 4: perform duplicate address detection. */
        self.gn_core
            .duplicate_address_detection(src_addr, ls_req_repr.source_position_vector.address);

        /* Step 5-6: add/update location table */
        let entry = self
            .location_table
            .update_mut(timestamp, &ls_req_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(ls_req_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len() + ch_repr.buffer_len() + ls_req_repr.buffer_len();
        entry.update_pdr(packet_size, timestamp);

        /* Determine if we are the location service destination */
        if ls_req_repr.request_address.mac_addr() == self.gn_core.address().mac_addr() {
            /* We are the destination */
            /* Step 8: create LS reply packet */
            let reply_bh_repr = BasicHeaderRepr {
                version: GN_PROTOCOL_VERSION,
                next_header: BHNextHeader::CommonHeader,
                lifetime: GN_DEFAULT_PACKET_LIFETIME,
                remaining_hop_limit: GN_DEFAULT_HOP_LIMIT,
            };

            let reply_ch_repr = CommonHeaderRepr {
                next_header: CHNextHeader::Any,
                header_type: GeonetPacketType::LsReply,
                traffic_class: GN_DEFAULT_TRAFFIC_CLASS,
                mobile: GN_IS_MOBILE,
                payload_len: 0,
                max_hop_limit: GN_DEFAULT_HOP_LIMIT,
            };

            let reply_ls_repr = LocationServiceReplyRepr {
                sequence_number: self.sequence_number,
                source_position_vector: self.gn_core.ego_position_vector(),
                destination_position_vector: entry.position_vector.into(),
            };

            /* Step 9: TODO: Forwarding algorithm. */

            /* Step 10: TODO: Security sign packet. */

            /* Step 11: TODO: Media dependent procedures. */

            /* Step 12: Return packet. */
            let packet = GeonetPacket::new_location_service_reply(
                reply_bh_repr,
                reply_ch_repr,
                reply_ls_repr,
            );
            Some(packet)
        } else {
            /* We are a forwarder */
            /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
            that are destined to the source of the incoming Location Service Request packet. */
            /* Step 8a */
            if entry.ls_pending {
                self.ls_buffer.flush_with(timestamp, |packet_node| {
                    packet_node.metadata().source_address()
                        == ls_req_repr.source_position_vector.address
                });

                entry.ls_pending = false;
            }

            /* Step 8b */
            self.uc_forwarding_buffer
                .flush_with(timestamp, |packet_node| {
                    packet_node.metadata().source_address()
                        == ls_req_repr.source_position_vector.address
                });

            /* Step 9: decrement Remaining Hop limit */
            if bh_repr.remaining_hop_limit == 0 {
                /* Remaining Hop Limit is reached, discard packet. */
                return None;
            }

            let reply_bh_repr = BasicHeaderRepr {
                version: bh_repr.version,
                next_header: bh_repr.next_header,
                lifetime: bh_repr.lifetime,
                remaining_hop_limit: bh_repr.remaining_hop_limit - 1,
            };

            /* Step 10: Buffering.
            There is no point buffering LS Request packets as described in TSB handling.
            Test specification TS 102 871-2 V1.4.1 expects forwarded LS Request packets to
            be broadcasted immediately.
             */

            /* Step 11: TODO: Media dependent procedures. */

            /* Step 12: Return packet. */
            let packet =
                GeonetPacket::new_location_service_request(reply_bh_repr, ch_repr, ls_req_repr);
            Some(packet)
        }
    }

    /// Processes a Location Service reply packet.
    pub(super) fn process_ls_reply<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        //dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let ls_rep = check!(LocationServiceReplyHeader::new_checked(ch_payload));
        let ls_rep_repr = check!(LocationServiceReplyRepr::parse(&ls_rep));

        // TODO: check if there are no bytes following the LS Reply header.

        /* Determine if we are the location service reply destination */
        if ls_rep_repr.destination_position_vector.address.mac_addr()
            == self.gn_core.address().mac_addr()
        {
            /* We are the destination. */
            /* Step 3: duplicate packet detection */
            let dup_opt = self.location_table.duplicate_packet_detection(
                ls_rep_repr.source_position_vector.address,
                ls_rep_repr.sequence_number,
            );

            if dup_opt.is_some_and(|x| x) {
                return None;
            }

            /* Step 3: perform duplicate address detection. */
            self.gn_core
                .duplicate_address_detection(src_addr, ls_rep_repr.source_position_vector.address);

            /* Step 4: update Location table */
            let entry = self
                .location_table
                .update_mut(timestamp, &ls_rep_repr.source_position_vector);

            /* Add received packet sequence number to the duplicate packet list */
            if dup_opt.is_none() {
                entry.dup_packet_list.write(ls_rep_repr.sequence_number);
            }

            /* Step 5: update PDR in Location table */
            let packet_size =
                bh_repr.buffer_len() + ch_repr.buffer_len() + ls_rep_repr.buffer_len();
            entry.update_pdr(packet_size, timestamp);

            /* Step 6-7-8: Flush packets inside Location Service and Unicast forwarding buffers
            that are destined to the source of the incoming Location Service Reply packet. */
            if entry.ls_pending {
                self.ls_buffer.flush_with(timestamp, |packet_node| {
                    packet_node.metadata().source_address()
                        == ls_rep_repr.source_position_vector.address
                });

                entry.ls_pending = false;
            }

            self.uc_forwarding_buffer
                .flush_with(timestamp, |packet_node| {
                    packet_node.metadata().source_address()
                        == ls_rep_repr.source_position_vector.address
                });

            None
        } else {
            /* We are forwarder. */
            self.forward_unicast(
                timestamp,
                bh_repr,
                ch_repr,
                ls_rep_repr,
                ls_rep.payload(),
                src_addr,
                //dst_addr,
            )
        }
    }

    /// Processes a Single-Hop Broadcast packet.
    pub(super) fn process_single_hop_broadcast<'packet>(
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
        let entry = self
            .location_table
            .update_mut(timestamp, &shb_repr.source_position_vector);

        /* Step 5: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + shb_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, timestamp);

        /* Step 6: set ìs_neighbour` flag in Location table */
        entry.is_neighbour = true;

        /* Step 7: TODO: Go to upper layer */

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming SHB packet. */
        if entry.ls_pending {
            self.ls_buffer.flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == shb_repr.source_position_vector.address
            });

            entry.ls_pending = false;
        }

        self.uc_forwarding_buffer
            .flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == shb_repr.source_position_vector.address
            });

        None
    }

    /// Processes a Topologically Scoped Broadcast packet.
    pub(super) fn process_topo_scoped_broadcast<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        // dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let tsb = check!(TopoBroadcastHeader::new_checked(ch_payload));
        let tsb_repr = check!(TopoBroadcastRepr::parse(&tsb));

        /* Step 3: duplicate packet detection */
        let dup_opt = self.location_table.duplicate_packet_detection(
            tsb_repr.source_position_vector.address,
            tsb_repr.sequence_number,
        );

        if dup_opt.is_some_and(|x| x) {
            return None;
        }

        /* Step 4: perform duplicate address detection. */
        self.gn_core
            .duplicate_address_detection(src_addr, tsb_repr.source_position_vector.address);

        /* Step 5-6: update Location table */
        let entry = self
            .location_table
            .update_mut(timestamp, &tsb_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(tsb_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + tsb_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, timestamp);

        /* Step 7: TODO: Go to upper layer */

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming TSB packet. */
        if entry.ls_pending {
            self.ls_buffer.flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == tsb_repr.source_position_vector.address
            });

            entry.ls_pending = false;
        }

        self.uc_forwarding_buffer
            .flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == tsb_repr.source_position_vector.address
            });

        /* Step 9: Build packet and decrement RHL. */
        if bh_repr.remaining_hop_limit == 0 {
            /* Remaining Hop Limit is reached, discard packet. */
            return None;
        }

        let fwd_bh_repr = BasicHeaderRepr {
            version: bh_repr.version,
            next_header: bh_repr.next_header,
            lifetime: bh_repr.lifetime,
            remaining_hop_limit: bh_repr.remaining_hop_limit - 1,
        };

        /* Step 10: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && ch_repr.traffic_class.store_carry_forward() {
            /* Buffer the packet into the broadcast buffer */
            let metadata =
                PacketMetadata::new_topo_scoped_broadcast(fwd_bh_repr, ch_repr, tsb_repr);
            self.bc_forwarding_buffer
                .enqueue(metadata, tsb.payload(), timestamp)
                .ok();

            return None;
        }

        // Packet is sent with a broadcast link layer destination address.
        let packet = GeonetPacket::new_topo_scoped_broadcast(
            fwd_bh_repr,
            ch_repr,
            tsb_repr,
            GeonetPayload::Raw(tsb.payload()),
        );

        /* Step 11: TODO: execute media dependent procedures */
        /* Step 12: return packet */
        Some(packet)
    }

    /// Process a unicast packet.
    pub(super) fn process_unicast<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        //dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let uc = check!(UnicastHeader::new_checked(ch_payload));
        let uc_repr = check!(UnicastRepr::parse(&uc));

        /* Determine if we are the unicast destination */
        if uc_repr.destination_position_vector.address.mac_addr()
            == self.gn_core.address().mac_addr()
        {
            self.receive_unicast(timestamp, bh_repr, ch_repr, uc_repr, uc.payload(), src_addr);
            None
        } else {
            self.forward_unicast(timestamp, bh_repr, ch_repr, uc_repr, uc.payload(), src_addr)
        }
    }

    /// Forwards a unicast packet.
    fn forward_unicast<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        uc_repr: UnicastRepr,
        payload: &'packet [u8],
        src_addr: HardwareAddress,
        //dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        /* Step 3: duplicate packet detection */
        let dup_opt = self.location_table.duplicate_packet_detection(
            uc_repr.source_position_vector.address,
            uc_repr.sequence_number,
        );

        /* Ignore result only if we are using CBF algorithm */
        if GN_NON_AREA_FORWARDING_ALGORITHM != GnNonAreaForwardingAlgorithm::Cbf
            && dup_opt.is_some_and(|x| x)
        {
            return None;
        }

        /* Step 7-8: destination position vector. */
        /* We do this step earlier and in a closure to avoid the borrow checker complaining about
        borrowing twice the location_table since we need mutable (exclusive) access to a value. */
        let uc_repr = {
            let destination = self.location_table.update_if(
                timestamp,
                &uc_repr.destination_position_vector.into(),
                |e| !e.is_neighbour,
            );

            // Apply the algorithm defined in ETSI 103 836-4-1 V2.1.1 clause C.3.
            if bh_repr.next_header != BHNextHeader::SecuredHeader
                && destination.is_neighbour
                && compare_position_vector_freshness(
                    &destination.position_vector,
                    &uc_repr.destination_position_vector.into(),
                )
            {
                UnicastRepr {
                    sequence_number: uc_repr.sequence_number,
                    source_position_vector: uc_repr.source_position_vector,
                    destination_position_vector: destination.position_vector.into(),
                }
            } else {
                uc_repr
            }
        };

        /* Step 3: perform duplicate address detection. */
        self.gn_core
            .duplicate_address_detection(src_addr, uc_repr.source_position_vector.address);

        /* Step 4: update Location table */
        let entry = self
            .location_table
            .update_mut(timestamp, &uc_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(uc_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + uc_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, timestamp);

        /* Step 9: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming Unicast packet. */
        if entry.ls_pending {
            self.ls_buffer.flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == uc_repr.source_position_vector.address
            });

            entry.ls_pending = false;
        }

        self.uc_forwarding_buffer
            .flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == uc_repr.source_position_vector.address
            });

        /* Step 10: Build packet and decrement RHL. */
        if bh_repr.remaining_hop_limit == 0 {
            /* Remaining Hop Limit is reached, discard packet. */
            return None;
        }

        let fwd_bh_repr = BasicHeaderRepr {
            version: bh_repr.version,
            next_header: bh_repr.next_header,
            lifetime: bh_repr.lifetime,
            remaining_hop_limit: bh_repr.remaining_hop_limit - 1,
        };

        /* Step 11: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && ch_repr.traffic_class.store_carry_forward() {
            /* Buffer the packet into the unicast buffer */
            let metadata = PacketMetadata::new_unicast(fwd_bh_repr, ch_repr, uc_repr);
            self.uc_forwarding_buffer
                .enqueue(metadata, payload, timestamp)
                .ok();

            return None;
        }

        let packet =
            GeonetPacket::new_unicast(fwd_bh_repr, ch_repr, uc_repr, GeonetPayload::Raw(payload));

        /* Step 12-13: TODO: execute forwarding algorithm. */
        /* Step 14: TODO: execute media dependent procedures */
        /* Step 15: return packet */
        Some(packet)
    }

    /// Receiver (destination) operations for a unicast packet.
    fn receive_unicast<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        uc_repr: UnicastRepr,
        payload: &'packet [u8],
        src_addr: HardwareAddress,
        //dst_addr: HardwareAddress,
    ) {
        /* Step 3: duplicate packet detection */
        let dup_opt = self.location_table.duplicate_packet_detection(
            uc_repr.source_position_vector.address,
            uc_repr.sequence_number,
        );

        if dup_opt.is_some_and(|x| x) {
            return;
        }

        /* Step 4: perform duplicate address detection */
        self.gn_core
            .duplicate_address_detection(src_addr, uc_repr.source_position_vector.address);

        /* Step 5-6: update Location table */
        let entry = self
            .location_table
            .update_mut(timestamp, &uc_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(uc_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + uc_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, timestamp);

        /* Step 7: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming Unicast packet. */
        if entry.ls_pending {
            self.ls_buffer.flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == uc_repr.source_position_vector.address
            });

            entry.ls_pending = false;
        }

        self.uc_forwarding_buffer
            .flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == uc_repr.source_position_vector.address
            });

        /* Step 8: TODO: pass payload to upper protocol. */
    }

    /// Process a Geo Broadcast packet.
    pub(super) fn process_geo_broadcast<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        //dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let gbc = check!(GeoBroadcastHeader::new_checked(ch_payload));
        let gbc_repr = check!(GeoBroadcastRepr::parse(&gbc));

        /* Step 3: determine function F(x,y) */
        let dst_area = Area::from_gbc(&ch_repr.header_type, &gbc_repr);
        let inside = dst_area.inside_or_at_border(self.gn_core.position());

        /* Step 3a-3b: duplicate packet detection */
        let dup_opt = self.location_table.duplicate_packet_detection(
            gbc_repr.source_position_vector.address,
            gbc_repr.sequence_number,
        );

        /* Ignore result only if we are using CBF algorithm */
        if ((!inside && GN_NON_AREA_FORWARDING_ALGORITHM != GnNonAreaForwardingAlgorithm::Cbf)
            || (inside && GN_AREA_FORWARDING_ALGORITHM != GnAreaForwardingAlgorithm::Cbf))
            && dup_opt.is_some_and(|x| x)
        {
            return None;
        }

        /* Step 4: perform duplicate address detection. */
        self.gn_core
            .duplicate_address_detection(src_addr, gbc_repr.source_position_vector.address);

        /* Step 5-6: update Location table */
        let entry = self
            .location_table
            .update_mut(timestamp, &gbc_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(gbc_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + gbc_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, timestamp);

        /* Step 7: TODO: pass payload to upper protocol if we are inside the destination area */
        if inside {}

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming GBC packet. */
        if entry.ls_pending {
            self.ls_buffer.flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == gbc_repr.source_position_vector.address
            });

            entry.ls_pending = false;
        }

        self.uc_forwarding_buffer
            .flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == gbc_repr.source_position_vector.address
            });

        /* Step 9: decrement Remaining Hop limit */
        if bh_repr.remaining_hop_limit == 0 {
            /* Remaining Hop Limit is reached, discard packet. */
            return None;
        }

        let fwd_bh_repr = BasicHeaderRepr {
            version: bh_repr.version,
            next_header: bh_repr.next_header,
            lifetime: bh_repr.lifetime,
            remaining_hop_limit: bh_repr.remaining_hop_limit - 1,
        };

        /* Step 10: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && ch_repr.traffic_class.store_carry_forward() {
            /* Buffer the packet into the broadcast buffer */
            let metadata = PacketMetadata::new_broadcast(fwd_bh_repr, ch_repr, gbc_repr);
            self.bc_forwarding_buffer
                .enqueue(metadata, gbc.payload(), timestamp)
                .ok();

            return None;
        }

        /* Step 11-12: TODO: forwarding algorithm */

        // Packet is sent with a the link layer destination address returned by the forwarding algorithm.
        let packet = GeonetPacket::new_broadcast(
            fwd_bh_repr,
            ch_repr,
            gbc_repr,
            GeonetPayload::Raw(gbc.payload()),
        );

        /* Step 13: TODO: execute media dependent procedures */
        /* Step 14: return packet */
        Some(packet)
    }

    /// Process a Geo Anycast packet.
    pub(super) fn process_geo_anycast<'packet>(
        &mut self,
        timestamp: Instant,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        src_addr: HardwareAddress,
        //dst_addr: HardwareAddress,
    ) -> Option<GeonetPacket<'packet>> {
        let gac = check!(GeoAnycastHeader::new_checked(ch_payload));
        let gac_repr = check!(GeoAnycastRepr::parse(&gac));

        /* Step 3: duplicate packet detection */
        let dup_opt = self.location_table.duplicate_packet_detection(
            gac_repr.source_position_vector.address,
            gac_repr.sequence_number,
        );

        if dup_opt.is_some_and(|x| x) {
            return None;
        }

        /* Step 4: perform duplicate address detection. */
        self.gn_core
            .duplicate_address_detection(src_addr, gac_repr.source_position_vector.address);

        /* Step 5-6: update Location table */
        let entry = self
            .location_table
            .update_mut(timestamp, &gac_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(gac_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + gac_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, timestamp);

        /* Step 7: determine function F(x,y) */
        let dst_area = Area::from_gac(&ch_repr.header_type, &gac_repr);
        let inside = dst_area.inside_or_at_border(self.gn_core.position());

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming GBC packet. */
        if entry.ls_pending {
            self.ls_buffer.flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == gac_repr.source_position_vector.address
            });

            entry.ls_pending = false;
        }

        self.uc_forwarding_buffer
            .flush_with(timestamp, |packet_node| {
                packet_node.metadata().source_address() == gac_repr.source_position_vector.address
            });

        /* Step 9: TODO: pass payload to upper protocol if we are inside the destination area */
        if inside {
            return None;
        }

        /* Step 10a: decrement Remaining Hop limit */
        if bh_repr.remaining_hop_limit == 0 {
            /* Remaining Hop Limit is reached, discard packet. */
            return None;
        }

        let fwd_bh_repr = BasicHeaderRepr {
            version: bh_repr.version,
            next_header: bh_repr.next_header,
            lifetime: bh_repr.lifetime,
            remaining_hop_limit: bh_repr.remaining_hop_limit - 1,
        };

        /* Step 10b: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && ch_repr.traffic_class.store_carry_forward() {
            /* Buffer the packet into the broadcast buffer */
            let metadata = PacketMetadata::new_anycast(fwd_bh_repr, ch_repr, gac_repr);
            self.bc_forwarding_buffer
                .enqueue(metadata, gac.payload(), timestamp)
                .ok();

            return None;
        }

        /* Step 11: TODO: forwarding algorithm */

        // Packet is sent with a the link layer destination address returned by the forwarding algorithm.
        let packet = GeonetPacket::new_broadcast(
            fwd_bh_repr,
            ch_repr,
            gac_repr,
            GeonetPayload::Raw(gac.payload()),
        );

        /* Step 12: TODO: execute media dependent procedures */
        /* Step 13: return packet */
        Some(packet)
    }
}
