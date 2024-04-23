use uom::si::angle::{degree, radian};
use uom::si::f32::{Angle, Length};
use uom::si::length::meter;

use crate::common::CbfIdentifier;
use crate::config::{
    GN_BROADCAST_CBF_DEF_SECTOR_ANGLE, GN_CBF_MAX_TIME, GN_CBF_MIN_TIME,
    GN_DEFAULT_MAX_COMMUNICATION_RANGE, VELOCE_CBF_MAX_RETRANSMIT,
};
use crate::iface::location_service::LocationServiceRequest;
use crate::iface::location_table::LocationTableG5Extension;
use crate::iface::{Congestion, SocketSet};
use crate::network::{
    GeoAnycastReqMeta, GeoBroadcastReqMeta, GnCore, Indication, SingleHopReqMeta,
    TopoScopedReqMeta, UnicastReqMeta, UpperProtocol,
};
use crate::phy::{Medium, PacketMeta};
use crate::wire::G5Extension;
use crate::{
    common::geo_area::{DistanceAB, GeoArea, Shape},
    config::{
        GnAreaForwardingAlgorithm, GnNonAreaForwardingAlgorithm, GN_AREA_FORWARDING_ALGORITHM,
        GN_BEACON_SERVICE_MAX_JITTER, GN_BEACON_SERVICE_RETRANSMIT_TIMER, GN_DEFAULT_HOP_LIMIT,
        GN_DEFAULT_PACKET_LIFETIME, GN_DEFAULT_TRAFFIC_CLASS, GN_IS_MOBILE,
        GN_LOCATION_SERVICE_MAX_RETRANS, GN_LOCATION_SERVICE_RETRANSMIT_TIMER,
        GN_NON_AREA_FORWARDING_ALGORITHM, GN_PROTOCOL_VERSION,
    },
    iface::{
        location_service::{LocationServiceFailedRequest, LocationServiceState},
        location_table::compare_position_vector_freshness,
        GeonetPacket, GeonetPayload,
    },
    time::Duration,
    wire::{
        BHNextHeader, BasicHeader, BasicHeaderRepr, BeaconHeader, BeaconHeaderRepr, CommonHeader,
        CommonHeaderRepr, EthernetAddress, EthernetRepr, GeoAnycastHeader, GeoAnycastRepr,
        GeoBroadcastHeader, GeoBroadcastRepr, GeonetPacketType, GeonetRepr, GeonetUnicast,
        GnProtocol, LocationServiceReplyHeader, LocationServiceReplyRepr,
        LocationServiceRequestHeader, LocationServiceRequestRepr,
        LongPositionVectorRepr as LongPositionVector, SingleHopHeader, SingleHopHeaderRepr,
        TopoBroadcastHeader, TopoBroadcastRepr, UnicastHeader, UnicastRepr,
    },
};

use super::{check, next_sequence_number, InterfaceInner, InterfaceServices};

impl InterfaceInner {
    /// Defer the beaconing retransmission if the packet source address is ours.
    pub(super) fn defer_beacon(&mut self, core: &mut GnCore, gn_repr: &GeonetRepr) -> bool {
        let deferred =
            gn_repr.source_position_vector().address.mac_addr() == core.address().mac_addr();
        if deferred {
            let rand_jitter = Duration::from_millis(
                core.rand
                    .rand_range(0..=GN_BEACON_SERVICE_MAX_JITTER.millis() as u32)
                    .into(),
            );

            self.retransmit_beacon_at = core.now + GN_BEACON_SERVICE_RETRANSMIT_TIMER + rand_jitter;
        }

        deferred
    }

    /// Processes a Geonetworking packet.
    pub(crate) fn process_geonet_packet<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        gn_packet: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        self.process_basic_header(svcs, sockets, meta, gn_packet, link_layer)
    }

    /// Processes the Basic Header of a Geonetworking packet.
    fn process_basic_header<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        gn_packet: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let bh = check!(BasicHeader::new_checked(gn_packet));
        let bh_repr = check!(BasicHeaderRepr::parse(&bh));

        // Check Geonetworking protocol version.
        if bh_repr.version != GN_PROTOCOL_VERSION {
            net_trace!(
                "network: {}",
                stringify!(bh_repr.version != GN_PROTOCOL_VERSION)
            );
            return None;
        }

        match bh_repr.next_header {
            BHNextHeader::Any | BHNextHeader::CommonHeader => {
                self.process_common_header(svcs, sockets, meta, bh_repr, bh.payload(), link_layer)
            }
            BHNextHeader::SecuredHeader => todo!(),
            BHNextHeader::Unknown(_) => {
                net_trace!("network: unknown basic header next header field value");
                return None;
            }
        }
    }

    /// Processes the Common Header of a Geonetworking packet.
    fn process_common_header<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        bh_repr: BasicHeaderRepr,
        bh_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let ch = check!(CommonHeader::new_checked(bh_payload));
        let ch_repr = check!(CommonHeaderRepr::parse(&ch));

        // Step 1: check the MHL field.
        if ch_repr.max_hop_limit < bh_repr.remaining_hop_limit {
            net_trace!(
                "network: malformed {}",
                stringify!(ch_repr.max_hop_limit < bh_repr.remaining_hop_limit)
            );
            return None;
        }

        // Step 2: TODO: process the BC forwarding packet buffer

        // TODO: Process the BC forwarding packet buffer and the forwarding algorithm having caused the buffering needs to be re-executed.
        let ch_payload = ch.payload();
        match ch_repr.header_type {
            GeonetPacketType::Any => {
                net_trace!("network: discard 'Any' packet type");
                return None;
            }
            GeonetPacketType::Beacon => {
                self.process_beacon(svcs, bh_repr, ch_repr, ch_payload, link_layer)
            }
            GeonetPacketType::GeoUnicast => self.process_unicast(
                svcs, sockets, meta, bh_repr, ch_repr, ch_payload, link_layer,
            ),
            GeonetPacketType::GeoAnycastCircle
            | GeonetPacketType::GeoAnycastRect
            | GeonetPacketType::GeoAnycastElip => self.process_geo_anycast(
                svcs, sockets, meta, bh_repr, ch_repr, ch_payload, link_layer,
            ),
            GeonetPacketType::GeoBroadcastCircle
            | GeonetPacketType::GeoBroadcastRect
            | GeonetPacketType::GeoBroadcastElip => self.process_geo_broadcast(
                svcs, sockets, meta, bh_repr, ch_repr, ch_payload, link_layer,
            ),
            GeonetPacketType::TsbSingleHop => self.process_single_hop_broadcast(
                svcs, sockets, meta, bh_repr, ch_repr, ch_payload, link_layer,
            ),
            GeonetPacketType::TsbMultiHop => self.process_topo_scoped_broadcast(
                svcs, sockets, meta, bh_repr, ch_repr, ch_payload, link_layer,
            ),
            GeonetPacketType::LsRequest => {
                self.process_ls_request(svcs, bh_repr, ch_repr, ch_payload, link_layer)
            }
            GeonetPacketType::LsReply => {
                self.process_ls_reply(svcs, bh_repr, ch_repr, ch_payload, link_layer)
            }
            GeonetPacketType::Unknown(u) => {
                net_trace!("network: discard 'Unknown={}' packet type", u);
                return None;
            }
        }
    }

    /// Processes a Beaconing packet.
    fn process_beacon<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let beacon = check!(BeaconHeader::new_checked(ch_payload));
        let beacon_repr = check!(BeaconHeaderRepr::parse(&beacon));

        // TODO: check if payload length is 0.

        /* Step 3: perform duplicate address detection. */
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, beacon_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        /* Step 4: update Location table */
        let entry = self
            .location_table
            .update_mut(svcs.core.now, &beacon_repr.source_position_vector);

        /* Step 5: update PDR in Location table */
        let packet_size = bh_repr.buffer_len() + ch_repr.buffer_len() + beacon_repr.buffer_len();
        entry.update_pdr(packet_size, svcs.core.now);

        /* Step 6: set `is_neighbour` flag in Location table */
        entry.is_neighbour = true;

        /* Step 7: Do nothing */

        /* Step 8: flush location service and unicast buffers for this packet source address */
        if let Some(handle) = entry.ls_pending {
            svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == beacon_repr.src_addr().mac_addr()
            });

            svcs.ls.cancel_request(handle);
        }

        svcs.uc_forwarding_buffer
            .mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == beacon_repr.src_addr().mac_addr()
            });

        None
    }

    /// Processes a Location Service request packet.
    fn process_ls_request<'packet, 'svcs>(
        &mut self,
        mut svcs: InterfaceServices<'svcs>,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
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
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, ls_req_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        /* Step 5-6: add/update location table */
        let entry = self
            .location_table
            .update_mut(svcs.core.now, &ls_req_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(ls_req_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len() + ch_repr.buffer_len() + ls_req_repr.buffer_len();
        entry.update_pdr(packet_size, svcs.core.now);

        /* Determine if we are the location service destination */
        if ls_req_repr.request_address.mac_addr() == svcs.core.address().mac_addr() {
            /* We are the destination */
            /* Step 8: create LS reply packet */
            let reply_bh_repr = BasicHeaderRepr {
                version: GN_PROTOCOL_VERSION,
                next_header: BHNextHeader::CommonHeader,
                lifetime: GN_DEFAULT_PACKET_LIFETIME,
                remaining_hop_limit: GN_DEFAULT_HOP_LIMIT,
            };

            let reply_ch_repr = CommonHeaderRepr {
                next_header: GnProtocol::Any,
                header_type: GeonetPacketType::LsReply,
                traffic_class: GN_DEFAULT_TRAFFIC_CLASS,
                mobile: GN_IS_MOBILE,
                payload_len: 0,
                max_hop_limit: GN_DEFAULT_HOP_LIMIT,
            };

            let reply_ls_repr = LocationServiceReplyRepr {
                sequence_number: next_sequence_number!(self),
                source_position_vector: svcs.core.ego_position_vector(),
                destination_position_vector: entry.position_vector.into(),
            };

            let packet = GeonetPacket::new_location_service_reply(
                reply_bh_repr,
                reply_ch_repr,
                reply_ls_repr,
            );

            /* Step 9: Forwarding algorithm. */
            let addr_opt = if GN_NON_AREA_FORWARDING_ALGORITHM == GnNonAreaForwardingAlgorithm::Cbf
            {
                Some(EthernetAddress::BROADCAST)
            } else {
                self.non_area_greedy_forwarding(&mut svcs, &packet)
            };

            let Some(addr) = addr_opt else {
                return None;
            };

            /* Step 10: TODO: Security sign packet. */

            /* Step 11: TODO: Media dependent procedures. */

            /* Step 12: Return packet. */
            Some((svcs, addr, packet))
        } else {
            /* We are a forwarder */
            /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
            that are destined to the source of the incoming Location Service Request packet. */
            /* Step 8a */
            if let Some(handle) = entry.ls_pending {
                svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                    packet_node.metadata().extended_header.dst_addr().mac_addr()
                        == ls_req_repr.src_addr().mac_addr()
                });

                svcs.ls.cancel_request(handle);
            }

            /* Step 8b */
            svcs.uc_forwarding_buffer
                .mark_flush(svcs.core.now, |packet_node| {
                    packet_node.metadata().extended_header.dst_addr().mac_addr()
                        == ls_req_repr.src_addr().mac_addr()
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
            Some((svcs, EthernetAddress::BROADCAST, packet))
        }
    }

    /// Processes a Location Service reply packet.
    fn process_ls_reply<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let ls_rep = check!(LocationServiceReplyHeader::new_checked(ch_payload));
        let ls_rep_repr = check!(LocationServiceReplyRepr::parse(&ls_rep));

        // TODO: check if there are no bytes following the LS Reply header.

        /* Determine if we are the location service reply destination */
        if ls_rep_repr.destination_position_vector.address.mac_addr()
            == svcs.core.address().mac_addr()
        {
            /* We are the destination. */
            /* Step 3: duplicate packet detection */
            let dup_opt = self
                .location_table
                .duplicate_packet_detection(ls_rep_repr.src_addr(), ls_rep_repr.sequence_number);

            if dup_opt.is_some_and(|x| x) {
                return None;
            }

            /* Step 3: perform duplicate address detection. */
            svcs.core
                .duplicate_address_detection(link_layer.src_addr, ls_rep_repr.src_addr())
                .and_then(|addr| {
                    self.hardware_addr = addr.into();
                    Some(addr)
                });

            /* Step 4: update Location table */
            let entry = self
                .location_table
                .update_mut(svcs.core.now, &ls_rep_repr.source_position_vector);

            /* Add received packet sequence number to the duplicate packet list */
            if dup_opt.is_none() {
                entry.dup_packet_list.write(ls_rep_repr.sequence_number);
            }

            /* Step 5: update PDR in Location table */
            let packet_size =
                bh_repr.buffer_len() + ch_repr.buffer_len() + ls_rep_repr.buffer_len();
            entry.update_pdr(packet_size, svcs.core.now);

            /* Step 6-7-8: Flush packets inside Location Service and Unicast forwarding buffers
            that are destined to the source of the incoming Location Service Reply packet. */
            if let Some(handle) = entry.ls_pending {
                svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                    packet_node.metadata().extended_header.dst_addr().mac_addr()
                        == ls_rep_repr.src_addr().mac_addr()
                });

                svcs.ls.cancel_request(handle);
            }

            svcs.uc_forwarding_buffer
                .mark_flush(svcs.core.now, |packet_node| {
                    packet_node.metadata().extended_header.dst_addr().mac_addr()
                        == ls_rep_repr.src_addr().mac_addr()
                });

            None
        } else {
            /* We are forwarder. */
            self.forward_unicast(
                svcs,
                bh_repr,
                ch_repr,
                ls_rep_repr,
                ls_rep.payload(),
                link_layer,
            )
        }
    }

    /// Processes a Single-Hop Broadcast packet.
    fn process_single_hop_broadcast<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let shb = check!(SingleHopHeader::new_checked(ch_payload));
        let shb_repr = check!(SingleHopHeaderRepr::parse(&shb));

        /* Step 3: perform duplicate address detection. */
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, shb_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        let ls_pending = {
            /* Step 4: update Location table */
            let entry = self
                .location_table
                .update_mut(svcs.core.now, &shb_repr.source_position_vector);

            /* Step 5: update PDR in Location table */
            let packet_size = bh_repr.buffer_len()
                + ch_repr.buffer_len()
                + shb_repr.buffer_len()
                + ch_repr.payload_len;
            entry.update_pdr(packet_size, svcs.core.now);

            /* Step 6: set ìs_neighbour` flag in Location table */
            entry.is_neighbour = true;

            /*  Update media dependent data in Location Table */
            #[cfg(feature = "medium-ieee80211p")]
            if self.caps.medium == Medium::Ieee80211p {
                let g5_ext = G5Extension::from_bytes(shb_repr.extension());
                let extension = LocationTableG5Extension {
                    local_update_tst: svcs.core.now,
                    station_pv_tst: shb_repr.source_position_vector.timestamp.into(),
                    local_cbr: g5_ext.cbr_l0_hop(),
                    one_hop_cbr: g5_ext.cbr_l1_hop(),
                    tx_power: g5_ext.tx_power(),
                    rx_power: meta.power,
                };

                entry.extensions = Some(extension.into());
            }

            entry.ls_pending
        };

        /* Step 7: Go to upper layer */
        let gn_repr = GeonetRepr::new_single_hop_broadcast(bh_repr, ch_repr, shb_repr);
        self.pass_up(&svcs, sockets, meta, &gn_repr, shb.payload());

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming SHB packet. */
        if let Some(handle) = ls_pending {
            svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == shb_repr.src_addr().mac_addr()
            });

            svcs.ls.cancel_request(handle);
        }

        svcs.uc_forwarding_buffer
            .mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == shb_repr.src_addr().mac_addr()
            });

        None
    }

    /// Processes a Topologically Scoped Broadcast packet.
    fn process_topo_scoped_broadcast<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let tsb = check!(TopoBroadcastHeader::new_checked(ch_payload));
        let tsb_repr = check!(TopoBroadcastRepr::parse(&tsb));

        /* Step 3: duplicate packet detection */
        let dup_opt = self
            .location_table
            .duplicate_packet_detection(tsb_repr.src_addr(), tsb_repr.sequence_number);

        if dup_opt.is_some_and(|x| x) {
            return None;
        }

        /* Step 4: perform duplicate address detection. */
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, tsb_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        let ls_pending = {
            /* Step 5-6: update Location table */
            let entry = self
                .location_table
                .update_mut(svcs.core.now, &tsb_repr.source_position_vector);

            /* Add received packet sequence number to the duplicate packet list */
            if dup_opt.is_none() {
                entry.dup_packet_list.write(tsb_repr.sequence_number);
            }

            /* Step 5-6: update PDR in Location table */
            let packet_size = bh_repr.buffer_len()
                + ch_repr.buffer_len()
                + tsb_repr.buffer_len()
                + ch_repr.payload_len;
            entry.update_pdr(packet_size, svcs.core.now);

            entry.ls_pending
        };

        /* Step 7: Go to upper layer */
        let gn_repr = GeonetRepr::new_topo_scoped_broadcast(bh_repr, ch_repr, tsb_repr);
        self.pass_up(&svcs, sockets, meta, &gn_repr, tsb.payload());

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming TSB packet. */
        if let Some(handle) = ls_pending {
            svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == tsb_repr.src_addr().mac_addr()
            });

            svcs.ls.cancel_request(handle);
        }

        svcs.uc_forwarding_buffer
            .mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == tsb_repr.src_addr().mac_addr()
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
            let metadata = GeonetRepr::new_topo_scoped_broadcast(fwd_bh_repr, ch_repr, tsb_repr);
            svcs.bc_forwarding_buffer
                .enqueue(metadata, tsb.payload(), svcs.core.now)
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
        Some((svcs, EthernetAddress::BROADCAST, packet))
    }

    /// Process a unicast packet.
    fn process_unicast<'packet, 'svcs>(
        &mut self,
        svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let uc = check!(UnicastHeader::new_checked(ch_payload));
        let uc_repr = check!(UnicastRepr::parse(&uc));

        /* Determine if we are the unicast destination */
        if uc_repr.destination_position_vector.address.mac_addr() == svcs.core.address().mac_addr()
        {
            self.receive_unicast(
                svcs,
                sockets,
                meta,
                bh_repr,
                ch_repr,
                uc_repr,
                uc.payload(),
                link_layer,
            );
            None
        } else {
            self.forward_unicast(svcs, bh_repr, ch_repr, uc_repr, uc.payload(), link_layer)
        }
    }

    /// Forwards a unicast packet.
    fn forward_unicast<'packet, 'svcs>(
        &mut self,
        mut svcs: InterfaceServices<'svcs>,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        uc_repr: UnicastRepr,
        payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        /* Step 3: duplicate packet detection */
        let dup_opt = self
            .location_table
            .duplicate_packet_detection(uc_repr.src_addr(), uc_repr.sequence_number);

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
                svcs.core.now,
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
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, uc_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        /* Step 4: update Location table */
        let entry = self
            .location_table
            .update_mut(svcs.core.now, &uc_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(uc_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + uc_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, svcs.core.now);

        /* Step 9: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming Unicast packet. */
        if let Some(handle) = entry.ls_pending {
            svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == uc_repr.src_addr().mac_addr()
            });

            svcs.ls.cancel_request(handle);
        }

        svcs.uc_forwarding_buffer
            .mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == uc_repr.src_addr().mac_addr()
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
            let metadata = GeonetUnicast::new(fwd_bh_repr, ch_repr, uc_repr);
            svcs.uc_forwarding_buffer
                .enqueue(metadata, payload, svcs.core.now)
                .ok();

            return None;
        }

        let packet = if let GeonetPacketType::LsReply = ch_repr.header_type {
            GeonetPacket::new_location_service_reply(fwd_bh_repr, ch_repr, uc_repr)
        } else {
            GeonetPacket::new_unicast(fwd_bh_repr, ch_repr, uc_repr, GeonetPayload::Raw(payload))
        };

        /* Step 12: execute forwarding algorithm. */
        let addr_opt = if GN_NON_AREA_FORWARDING_ALGORITHM == GnNonAreaForwardingAlgorithm::Cbf {
            Some(EthernetAddress::BROADCAST)
        } else {
            self.non_area_greedy_forwarding(&mut svcs, &packet)
        };

        /* Step 13: Check forwarding algorithm result. */
        let Some(addr) = addr_opt else {
            return None;
        };

        /* Step 14: TODO: execute media dependent procedures */
        /* Step 15: return packet */
        Some((svcs, addr, packet))
    }

    /// Receiver (destination) operations for a unicast packet.
    fn receive_unicast<'packet>(
        &mut self,
        svcs: InterfaceServices,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        uc_repr: UnicastRepr,
        payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) {
        /* Step 3: duplicate packet detection */
        let dup_opt = self
            .location_table
            .duplicate_packet_detection(uc_repr.src_addr(), uc_repr.sequence_number);

        if dup_opt.is_some_and(|x| x) {
            return;
        }

        /* Step 4: perform duplicate address detection */
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, uc_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        /* Step 5-6: update Location table */
        let entry = self
            .location_table
            .update_mut(svcs.core.now, &uc_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(uc_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + uc_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, svcs.core.now);

        /* Step 7: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming Unicast packet. */
        if let Some(handle) = entry.ls_pending {
            svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == uc_repr.src_addr().mac_addr()
            });

            svcs.ls.cancel_request(handle);
        }

        svcs.uc_forwarding_buffer
            .mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == uc_repr.src_addr().mac_addr()
            });

        /* Step 8: pass payload to upper protocol. */
        let gn_repr: GeonetRepr = GeonetRepr::new_unicast(bh_repr, ch_repr, uc_repr);
        self.pass_up(&svcs, sockets, meta, &gn_repr, payload);
    }

    /// Process a Geo Broadcast packet.
    fn process_geo_broadcast<'packet, 'svcs>(
        &mut self,
        mut svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let gbc = check!(GeoBroadcastHeader::new_checked(ch_payload));
        let gbc_repr = check!(GeoBroadcastRepr::parse(&gbc));

        /* Step 3: determine function F(x,y) */
        let dst_area = GeoArea::from_gbc(&ch_repr.header_type, &gbc_repr);
        let inside = dst_area.inside_or_at_border(svcs.core.geo_position());

        /* Step 3a-3b: duplicate packet detection */
        let dup_opt = self
            .location_table
            .duplicate_packet_detection(gbc_repr.src_addr(), gbc_repr.sequence_number);

        /* Ignore result only if we are using CBF algorithm */
        if ((!inside && GN_NON_AREA_FORWARDING_ALGORITHM != GnNonAreaForwardingAlgorithm::Cbf)
            || (inside && GN_AREA_FORWARDING_ALGORITHM != GnAreaForwardingAlgorithm::Cbf))
            && dup_opt.is_some_and(|x| x)
        {
            return None;
        }

        /* Step 4: perform duplicate address detection. */
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, gbc_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        let ls_pending = {
            /* Step 5-6: update Location table */
            let entry = self
                .location_table
                .update_mut(svcs.core.now, &gbc_repr.source_position_vector);

            /* Add received packet sequence number to the duplicate packet list */
            if dup_opt.is_none() {
                entry.dup_packet_list.write(gbc_repr.sequence_number);
            }

            /* Step 5-6: update PDR in Location table */
            let packet_size = bh_repr.buffer_len()
                + ch_repr.buffer_len()
                + gbc_repr.buffer_len()
                + ch_repr.payload_len;
            entry.update_pdr(packet_size, svcs.core.now);

            entry.ls_pending
        };

        /* Step 7: pass payload to upper protocol if we are inside the destination area */
        if inside {
            let gn_repr = GeonetRepr::new_broadcast(bh_repr, ch_repr, gbc_repr);
            self.pass_up(&svcs, sockets, meta, &gn_repr, gbc.payload());
        }

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming GBC packet. */
        if let Some(handle) = ls_pending {
            svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == gbc_repr.src_addr().mac_addr()
            });

            svcs.ls.cancel_request(handle);
        }

        svcs.uc_forwarding_buffer
            .mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == gbc_repr.src_addr().mac_addr()
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
            let metadata = GeonetRepr::new_broadcast(fwd_bh_repr, ch_repr, gbc_repr);
            svcs.bc_forwarding_buffer
                .enqueue(metadata, gbc.payload(), svcs.core.now)
                .ok();

            return None;
        }

        // Packet is sent with a the link layer destination address returned by the forwarding algorithm.
        let packet = GeonetPacket::new_broadcast(
            fwd_bh_repr,
            ch_repr,
            gbc_repr,
            GeonetPayload::Raw(gbc.payload()),
        );

        /* Step 11: forwarding algorithm */
        let dst_ll_addr_opt = self.forwarding_algorithm(&mut svcs, &packet, Some(link_layer));

        /* Step 12: check if packet has been buffered or dropped */
        let Some(dst_addr) = dst_ll_addr_opt else {
            return None;
        };

        /* Step 13: TODO: execute media dependent procedures */
        /* Step 14: return packet */
        Some((svcs, dst_addr, packet))
    }

    /// Process a Geo Anycast packet.
    pub(super) fn process_geo_anycast<'packet, 'svcs>(
        &mut self,
        mut svcs: InterfaceServices<'svcs>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        bh_repr: BasicHeaderRepr,
        ch_repr: CommonHeaderRepr,
        ch_payload: &'packet [u8],
        link_layer: EthernetRepr,
    ) -> Option<(
        InterfaceServices<'svcs>,
        EthernetAddress,
        GeonetPacket<'packet>,
    )> {
        let gac = check!(GeoAnycastHeader::new_checked(ch_payload));
        let gac_repr = check!(GeoAnycastRepr::parse(&gac));

        /* Step 3: duplicate packet detection */
        let dup_opt = self
            .location_table
            .duplicate_packet_detection(gac_repr.src_addr(), gac_repr.sequence_number);

        if dup_opt.is_some_and(|x| x) {
            return None;
        }

        /* Step 4: perform duplicate address detection. */
        svcs.core
            .duplicate_address_detection(link_layer.src_addr, gac_repr.src_addr())
            .and_then(|addr| {
                self.hardware_addr = addr.into();
                Some(addr)
            });

        /* Step 5-6: update Location table */
        let entry = self
            .location_table
            .update_mut(svcs.core.now, &gac_repr.source_position_vector);

        /* Add received packet sequence number to the duplicate packet list */
        if dup_opt.is_none() {
            entry.dup_packet_list.write(gac_repr.sequence_number);
        }

        /* Step 5-6: update PDR in Location table */
        let packet_size = bh_repr.buffer_len()
            + ch_repr.buffer_len()
            + gac_repr.buffer_len()
            + ch_repr.payload_len;
        entry.update_pdr(packet_size, svcs.core.now);

        /* Step 7: determine function F(x,y) */
        let dst_area = GeoArea::from_gac(&ch_repr.header_type, &gac_repr);
        let inside = dst_area.inside_or_at_border(svcs.core.geo_position());

        /* Step 8: Flush packets inside Location Service and Unicast forwarding buffers
        that are destined to the source of the incoming GBC packet. */
        if let Some(handle) = entry.ls_pending {
            svcs.ls_buffer.mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == gac_repr.src_addr().mac_addr()
            });

            svcs.ls.cancel_request(handle);
        }

        svcs.uc_forwarding_buffer
            .mark_flush(svcs.core.now, |packet_node| {
                packet_node.metadata().extended_header.dst_addr().mac_addr()
                    == gac_repr.src_addr().mac_addr()
            });

        /* Step 9: pass payload to upper protocol if we are inside the destination area */
        if inside {
            let gn_repr = GeonetRepr::new_anycast(bh_repr, ch_repr, gac_repr);
            self.pass_up(&svcs, sockets, meta, &gn_repr, gac.payload());
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
            let metadata = GeonetRepr::new_anycast(fwd_bh_repr, ch_repr, gac_repr);
            svcs.bc_forwarding_buffer
                .enqueue(metadata, gac.payload(), svcs.core.now)
                .ok();

            return None;
        }

        // Packet is sent with a the link layer destination address returned by the forwarding algorithm.
        let packet = GeonetPacket::new_anycast(
            fwd_bh_repr,
            ch_repr,
            gac_repr,
            GeonetPayload::Raw(gac.payload()),
        );

        /* Step 11: forwarding algorithm */
        let dst_ll_addr_opt = self.forwarding_algorithm(&mut svcs, &packet, Some(link_layer));

        /* Step 12: check if packet has been buffered or dropped */
        let Some(dst_addr) = dst_ll_addr_opt else {
            return None;
        };

        /* Step 12: TODO: execute media dependent procedures */
        /* Step 13: return packet */
        Some((svcs, dst_addr, packet))
    }

    /// Dispatch beacons packets.
    pub(super) fn dispatch_beacon<F, E>(
        &mut self,
        svcs: InterfaceServices,
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                BeaconHeaderRepr,
            ),
        ) -> Result<(), E>,
    {
        if self.retransmit_beacon_at > svcs.core.now {
            return Ok(());
        }

        /* Step 1a: set the fields of the basic header */
        let bh_repr = BasicHeaderRepr {
            version: GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: GN_DEFAULT_PACKET_LIFETIME,
            remaining_hop_limit: 1,
        };

        /* Step 1b: set the fields of the common header */
        let ch_repr = CommonHeaderRepr {
            next_header: GnProtocol::Any,
            header_type: GeonetPacketType::Beacon,
            traffic_class: GN_DEFAULT_TRAFFIC_CLASS,
            mobile: GN_IS_MOBILE,
            payload_len: 0,
            max_hop_limit: 1,
        };

        /* Step 1c: set the fields of the beacon header */
        let beacon_repr = BeaconHeaderRepr {
            source_position_vector: svcs.core.ego_position_vector(),
        };

        /* Step 2: TODO: security sign packet */
        /* Step 3: TODO: media dependent procedures */

        /* Step 4: pass packet to access payload */
        emit(
            self,
            svcs.core,
            svcs.congestion_control,
            (EthernetAddress::BROADCAST, bh_repr, ch_repr, beacon_repr),
        )?;

        Ok(())
    }

    /// Dispatch location service pending requests packets.
    pub(crate) fn dispatch_ls_request<F, E>(
        &mut self,
        svcs: InterfaceServices,
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                LocationServiceRequestRepr,
            ),
        ) -> Result<(), E>,
    {
        for r in svcs.ls.ls_requests.iter_mut() {
            if let Some(LocationServiceRequest { state, .. }) = r {
                match state {
                    LocationServiceState::Pending(pr) => {
                        // Max attempts reached. Query failed.
                        if pr.attempts >= GN_LOCATION_SERVICE_MAX_RETRANS {
                            *state = LocationServiceState::Failure(LocationServiceFailedRequest {
                                address: pr.address,
                            });
                            continue;
                        }

                        // Transmission timeout.
                        if pr.retransmit_at > svcs.core.now {
                            continue;
                        }

                        let bh_repr = BasicHeaderRepr {
                            version: GN_PROTOCOL_VERSION,
                            next_header: BHNextHeader::CommonHeader,
                            lifetime: GN_DEFAULT_PACKET_LIFETIME,
                            remaining_hop_limit: GN_DEFAULT_HOP_LIMIT,
                        };

                        let ch_repr = CommonHeaderRepr {
                            next_header: GnProtocol::Any,
                            header_type: GeonetPacketType::LsRequest,
                            traffic_class: GN_DEFAULT_TRAFFIC_CLASS,
                            mobile: GN_IS_MOBILE,
                            payload_len: 0,
                            max_hop_limit: GN_DEFAULT_HOP_LIMIT,
                        };

                        let ls_req_repr = LocationServiceRequestRepr {
                            sequence_number: next_sequence_number!(self),
                            source_position_vector: svcs.core.ego_position_vector(),
                            request_address: pr.address,
                        };

                        emit(
                            self,
                            svcs.core,
                            svcs.congestion_control,
                            (EthernetAddress::BROADCAST, bh_repr, ch_repr, ls_req_repr),
                        )?;

                        pr.retransmit_at = svcs.core.now + GN_LOCATION_SERVICE_RETRANSMIT_TIMER;
                        pr.attempts += 1;

                        break;
                    }
                    LocationServiceState::Failure(fr) => {
                        // Query has failed, remove elements inside the ls buffer.
                        svcs.ls_buffer.drop_with(|packet_node| {
                            packet_node.metadata().extended_header.dst_addr().mac_addr()
                                == fr.address.mac_addr()
                        });

                        // Remove location table entry.
                        self.location_table.remove(&fr.address.mac_addr());
                        r.take();
                    }
                };
            }
        }

        // Nothing to dispatch.
        Ok(())
    }

    /// Dispatch a unicast transmission request.
    pub(crate) fn dispatch_unicast<F, E>(
        &mut self,
        mut svcs: InterfaceServices,
        metadata: UnicastReqMeta,
        payload: &[u8],
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                UnicastRepr,
                &[u8],
            ),
        ) -> Result<(), E>,
    {
        /* Step 1a: set the fields of the basic header */
        let bh_repr = BasicHeaderRepr {
            version: GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: metadata.max_lifetime,
            remaining_hop_limit: metadata.max_hop_limit,
        };

        /* Step 1b: set the fields of the common header */
        let ch_repr = CommonHeaderRepr {
            next_header: metadata.upper_proto.into(),
            header_type: GeonetPacketType::GeoUnicast,
            traffic_class: metadata.traffic_class,
            mobile: GN_IS_MOBILE,
            payload_len: payload.len(),
            max_hop_limit: metadata.max_hop_limit,
        };

        /* Step 2: location table lookup */
        if let Some(entry) = self.location_table.find(&metadata.destination.mac_addr()) {
            /* Step 1b: set the fields of the unicast header */
            let uc_repr = UnicastRepr {
                sequence_number: next_sequence_number!(self),
                source_position_vector: svcs.core.ego_position_vector(),
                destination_position_vector: entry.position_vector.into(),
            };

            /* Check Location Service state */
            if entry.ls_pending.is_some() {
                /* Location Service request pending for destination: buffer the packet into LS buffer */
                let packet_meta = GeonetUnicast::new(bh_repr, ch_repr, uc_repr);
                svcs.ls_buffer
                    .enqueue(packet_meta, payload, svcs.core.now)
                    .ok();

                return Ok(());
            }

            /* Step 3: check if we should buffer the packet */
            if !self.location_table.has_neighbour() && metadata.traffic_class.store_carry_forward()
            {
                /* Buffer the packet into the unicast buffer */
                let packet_meta = GeonetUnicast::new(bh_repr, ch_repr, uc_repr);
                svcs.uc_forwarding_buffer
                    .enqueue(packet_meta, payload, svcs.core.now)
                    .ok();

                return Ok(());
            }

            /* Step 4: forwarding algorithm */
            let nh_ll_addr =
                if GN_NON_AREA_FORWARDING_ALGORITHM == GnNonAreaForwardingAlgorithm::Cbf {
                    EthernetAddress::BROADCAST
                } else {
                    let packet = GeonetPacket::new_unicast(
                        bh_repr.clone(),
                        ch_repr.clone(),
                        uc_repr.clone(),
                        GeonetPayload::Raw(payload),
                    );

                    /* Step 5: check if packet is buffered */
                    let Some(addr) = self.non_area_greedy_forwarding(&mut svcs, &packet) else {
                        return Ok(());
                    };

                    addr
                };

            /* Step 6: TODO: security encapsulation */
            /* Step 7: TODO: repetition */
            /* Step 8: TODO: media dependent procedures */
            /* Step 9: pass packet to access layer */
            emit(
                self,
                svcs.core,
                svcs.congestion_control,
                (nh_ll_addr, bh_repr, ch_repr, uc_repr, payload),
            )?;
        } else {
            /* Step 2a: invoke location service for this destination */
            let Ok(handle) = svcs.ls.request(metadata.destination, svcs.core.now) else {
                /* Error invoking Location Service. */
                net_trace!("Error invoking Location Service");
                // TODO: we should return an error.
                return Ok(());
            };

            /* Add a LocTE entry for the station */
            let mut pv = LongPositionVector::default();
            pv.address = metadata.destination;
            let entry = self.location_table.update_mut(svcs.core.now, &pv);
            entry.ls_pending = Some(handle);

            /* Set the fields of the unicast header */
            /* We set a default destination_position_vector, even it's content are wrong. */
            /* It does not matter because we update the headers with correct data when flushing buffers. */
            let uc_repr = UnicastRepr {
                sequence_number: next_sequence_number!(self),
                source_position_vector: svcs.core.ego_position_vector(),
                destination_position_vector: entry.position_vector.into(),
            };

            /* Add packet into the LS buffer */
            let packet_meta = GeonetUnicast::new(bh_repr, ch_repr, uc_repr);

            svcs.ls_buffer
                .enqueue(packet_meta, payload, svcs.core.now)
                .ok();
        }

        return Ok(());
    }

    /// Dispatch a Topologically Scoped Broadcast packet.
    pub(crate) fn dispatch_topo_scoped_broadcast<F, E>(
        &mut self,
        svcs: InterfaceServices,
        metadata: TopoScopedReqMeta,
        payload: &[u8],
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                TopoBroadcastRepr,
                &[u8],
            ),
        ) -> Result<(), E>,
    {
        /* Step 1a: set the fields of the basic header */
        let bh_repr = BasicHeaderRepr {
            version: GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: metadata.max_lifetime,
            remaining_hop_limit: metadata.max_hop_limit,
        };

        /* Step 1b: set the fields of the common header */
        let ch_repr = CommonHeaderRepr {
            next_header: metadata.upper_proto.into(),
            header_type: GeonetPacketType::TsbMultiHop,
            traffic_class: metadata.traffic_class,
            mobile: GN_IS_MOBILE,
            payload_len: payload.len(),
            max_hop_limit: metadata.max_hop_limit,
        };

        /* Step 1c: set the fields of the tsb header */
        let tsb_repr = TopoBroadcastRepr {
            sequence_number: next_sequence_number!(self),
            source_position_vector: svcs.core.ego_position_vector(),
        };

        /* Step 2: TODO: security sign packet */

        /* Step 3: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && metadata.traffic_class.store_carry_forward() {
            /* Buffer the packet into the broadcast buffer */
            let packet_meta = GeonetRepr::new_topo_scoped_broadcast(bh_repr, ch_repr, tsb_repr);
            svcs.bc_forwarding_buffer
                .enqueue(packet_meta, payload, svcs.core.now)
                .ok();

            return Ok(());
        }

        /* Step 4: TODO: packet repetition */
        /* Step 5: TODO: media dependent procedures */
        /* Step 6: pass packet to access layer */
        emit(
            self,
            svcs.core,
            svcs.congestion_control,
            (
                EthernetAddress::BROADCAST,
                bh_repr,
                ch_repr,
                tsb_repr,
                payload,
            ),
        )?;

        Ok(())
    }

    /// Dispatch a Single Hop Broadcast packet.
    pub(crate) fn dispatch_single_hop_broadcast<F, E>(
        &mut self,
        svcs: InterfaceServices,
        metadata: SingleHopReqMeta,
        payload: &[u8],
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                SingleHopHeaderRepr,
                &[u8],
            ),
        ) -> Result<(), E>,
    {
        /* Step 1a: set the fields of the basic header */
        let bh_repr = BasicHeaderRepr {
            version: GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: metadata.max_lifetime,
            remaining_hop_limit: 1,
        };

        /* Step 1b: set the fields of the common header */
        let ch_repr = CommonHeaderRepr {
            next_header: metadata.upper_proto.into(),
            header_type: GeonetPacketType::TsbSingleHop,
            traffic_class: metadata.traffic_class,
            mobile: GN_IS_MOBILE,
            payload_len: payload.len(),
            max_hop_limit: 1,
        };

        /* Step 1c: set the fields of the shb header */
        let mut shb_repr = SingleHopHeaderRepr {
            source_position_vector: svcs.core.ego_position_vector(),
            extension: [0; SingleHopHeaderRepr::extension_len()],
        };

        #[cfg(feature = "medium-ieee80211p")]
        if self.caps.medium == Medium::Ieee80211p {
            let congestion_ctrl = &svcs.congestion_control;
            let g5_ext = G5Extension::new(
                congestion_ctrl.local_cbr(),
                congestion_ctrl.global_cbr(),
                self.caps.radio.tx_power,
            );

            shb_repr.extension.copy_from_slice(g5_ext.as_bytes());
        }

        /* Step 2: TODO: security sign packet */

        /* Step 3: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && metadata.traffic_class.store_carry_forward() {
            /* Buffer the packet into the broadcast buffer */
            let packet_meta = GeonetRepr::new_single_hop_broadcast(bh_repr, ch_repr, shb_repr);
            svcs.bc_forwarding_buffer
                .enqueue(packet_meta, payload, svcs.core.now)
                .ok();

            return Ok(());
        }

        /* Step 4: TODO: packet repetition */
        /* Step 5: TODO: media dependent procedures */
        /* Step 6: pass packet to access layer */
        emit(
            self,
            svcs.core,
            svcs.congestion_control,
            (
                EthernetAddress::BROADCAST,
                bh_repr,
                ch_repr,
                shb_repr,
                payload,
            ),
        )?;

        Ok(())
    }

    /// Dispatch a Geo Broadcast packet.
    pub(crate) fn dispatch_geo_broadcast<F, E>(
        &mut self,
        mut svcs: InterfaceServices,
        metadata: GeoBroadcastReqMeta,
        payload: &[u8],
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                GeoBroadcastRepr,
                &[u8],
            ),
        ) -> Result<(), E>,
    {
        /* Step 1a: set the fields of the basic header */
        let bh_repr = BasicHeaderRepr {
            version: GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: metadata.max_lifetime,
            remaining_hop_limit: metadata.max_hop_limit,
        };

        /* Step 1b: set the fields of the common header */
        let ch_repr = CommonHeaderRepr {
            next_header: metadata.upper_proto.into(),
            header_type: (|| match metadata.destination.shape {
                Shape::Circle(_) => GeonetPacketType::GeoBroadcastCircle,
                Shape::Rectangle(_) => GeonetPacketType::GeoBroadcastRect,
                Shape::Ellipse(_) => GeonetPacketType::GeoBroadcastElip,
            })(),
            traffic_class: metadata.traffic_class,
            mobile: GN_IS_MOBILE,
            payload_len: payload.len(),
            max_hop_limit: metadata.max_hop_limit,
        };

        /* Step 1c: set the fields of the geo broadcast header */
        let gbc_repr = GeoBroadcastRepr {
            source_position_vector: svcs.core.ego_position_vector(),
            sequence_number: next_sequence_number!(self),
            latitude: metadata.destination.position.latitude,
            longitude: metadata.destination.position.longitude,
            distance_a: metadata.destination.shape.distance_a(),
            distance_b: metadata.destination.shape.distance_b(),
            angle: metadata.destination.angle,
        };

        /* Step 2: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && metadata.traffic_class.store_carry_forward() {
            /* Buffer the packet into the broadcast buffer */
            let packet_meta = GeonetRepr::new_broadcast(bh_repr, ch_repr, gbc_repr);
            svcs.bc_forwarding_buffer
                .enqueue(packet_meta, payload, svcs.core.now)
                .ok();

            return Ok(());
        }

        /* Step 3: forwarding algorithm */
        let packet_meta =
            GeonetPacket::new_broadcast(bh_repr, ch_repr, gbc_repr, GeonetPayload::Raw(payload));
        let nh_ll_addr_opt = self.forwarding_algorithm(&mut svcs, &packet_meta, None);

        /* Step 4: check if packet has been buffered or dropped */
        let Some(dst_addr) = nh_ll_addr_opt else {
            return Ok(());
        };

        /* Step 5: TODO: security sign packet */
        /* Step 6: TODO: packet repetition */
        /* Step 7: TODO: media dependent procedures */

        /* Step 8: pass packet to access layer */
        emit(
            self,
            svcs.core,
            svcs.congestion_control,
            (dst_addr, bh_repr, ch_repr, gbc_repr, payload),
        )?;

        Ok(())
    }

    /// Dispatch a Geo Anycast packet.
    pub(crate) fn dispatch_geo_anycast<F, E>(
        &mut self,
        mut svcs: InterfaceServices,
        metadata: GeoAnycastReqMeta,
        payload: &[u8],
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                GeoAnycastRepr,
                &[u8],
            ),
        ) -> Result<(), E>,
    {
        /* Step 1a: set the fields of the basic header */
        let bh_repr = BasicHeaderRepr {
            version: GN_PROTOCOL_VERSION,
            next_header: BHNextHeader::CommonHeader,
            lifetime: metadata.max_lifetime,
            remaining_hop_limit: metadata.max_hop_limit,
        };

        /* Step 1b: set the fields of the common header */
        let ch_repr = CommonHeaderRepr {
            next_header: metadata.upper_proto.into(),
            header_type: (|| match metadata.destination.shape {
                Shape::Circle(_) => GeonetPacketType::GeoAnycastCircle,
                Shape::Rectangle(_) => GeonetPacketType::GeoAnycastRect,
                Shape::Ellipse(_) => GeonetPacketType::GeoAnycastElip,
            })(),
            traffic_class: metadata.traffic_class,
            mobile: GN_IS_MOBILE,
            payload_len: payload.len(),
            max_hop_limit: metadata.max_hop_limit,
        };

        /* Step 1c: set the fields of the geo anycast header */
        let gbc_repr = GeoAnycastRepr {
            source_position_vector: svcs.core.ego_position_vector(),
            sequence_number: next_sequence_number!(self),
            latitude: metadata.destination.position.latitude,
            longitude: metadata.destination.position.longitude,
            distance_a: metadata.destination.shape.distance_a(),
            distance_b: metadata.destination.shape.distance_b(),
            angle: metadata.destination.angle,
        };

        /* Step 2: check if we should buffer the packet */
        if !self.location_table.has_neighbour() && metadata.traffic_class.store_carry_forward() {
            /* Buffer the packet into the broadcast buffer */
            let packet_meta = GeonetRepr::new_anycast(bh_repr, ch_repr, gbc_repr);
            svcs.bc_forwarding_buffer
                .enqueue(packet_meta, payload, svcs.core.now)
                .ok();

            return Ok(());
        }

        /* Step 3: forwarding algorithm */
        let packet_meta =
            GeonetPacket::new_anycast(bh_repr, ch_repr, gbc_repr, GeonetPayload::Raw(payload));
        let nh_ll_addr_opt = self.forwarding_algorithm(&mut svcs, &packet_meta, None);

        /* Step 4: check if packet has been buffered or dropped */
        let Some(dst_addr) = nh_ll_addr_opt else {
            return Ok(());
        };

        /* Step 5: TODO: security sign packet */
        /* Step 6: TODO: packet repetition */
        /* Step 7: TODO: media dependent procedures */

        /* Step 8: pass packet to access layer */
        emit(
            self,
            svcs.core,
            svcs.congestion_control,
            (dst_addr, bh_repr, ch_repr, gbc_repr, payload),
        )?;

        Ok(())
    }

    /// Dequeue one packet marked as flushable from the ls buffer.
    /// Returns `None` when no packets are available.
    pub(crate) fn dispatch_ls_buffer<F, E>(
        &mut self,
        svcs: InterfaceServices,
        emit: F,
    ) -> Option<Result<(), E>>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                UnicastRepr,
                &[u8],
            ),
        ) -> Result<(), E>,
    {
        svcs.ls_buffer.flush_one(|packet| {
            let expiry = packet.expires_at();
            let meta = packet.metadata();
            let dest_addr = meta
                .extended_header
                .destination_position_vector
                .address
                .mac_addr();

            // Update the packet lifetime.
            meta.basic_header.lifetime = expiry - svcs.core.now;
            // Update ego position in packet.
            meta.extended_header.source_position_vector = svcs.core.ego_position_vector();

            // Update destination position vector in stored packet.
            if let Some(dst_entry) = self.location_table.find(&dest_addr) {
                meta.extended_header.destination_position_vector = dst_entry.position_vector.into();
            }

            emit(
                self,
                svcs.core,
                svcs.congestion_control,
                (
                    dest_addr,
                    meta.basic_header.to_owned(),
                    meta.common_header.to_owned(),
                    meta.extended_header.to_owned(),
                    packet.payload(),
                ),
            )
        })
    }

    /// Dequeue one packet marked as flushable from the unicast buffer.
    /// Returns `None` when no packets are available.
    pub(crate) fn dispatch_unicast_buffer<F, E>(
        &mut self,
        svcs: InterfaceServices,
        emit: F,
    ) -> Option<Result<(), E>>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (
                EthernetAddress,
                BasicHeaderRepr,
                CommonHeaderRepr,
                UnicastRepr,
                &[u8],
            ),
        ) -> Result<(), E>,
    {
        svcs.uc_forwarding_buffer.flush_one(|packet| {
            let expiry = packet.expires_at();
            let meta = packet.metadata();
            let dest_addr = meta
                .extended_header
                .destination_position_vector
                .address
                .mac_addr();

            // Update the packet lifetime.
            meta.basic_header.lifetime = expiry - svcs.core.now;
            // Update position in packet only if we are the origin.
            if meta.extended_header.src_addr().mac_addr() == svcs.core.address().mac_addr() {
                meta.extended_header.source_position_vector = svcs.core.ego_position_vector();
            }

            emit(
                self,
                svcs.core,
                svcs.congestion_control,
                (
                    dest_addr,
                    meta.basic_header.to_owned(),
                    meta.common_header.to_owned(),
                    meta.extended_header.to_owned(),
                    packet.payload(),
                ),
            )
        })
    }

    /// Dequeue one packet marked as flushable from the unicast buffer.
    /// Returns `None` when no packets are available.
    pub(crate) fn dispatch_broadcast_buffer<F, E>(
        &mut self,
        svcs: InterfaceServices,
        emit: F,
    ) -> Option<Result<(), E>>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (EthernetAddress, GeonetRepr, &[u8]),
        ) -> Result<(), E>,
    {
        svcs.bc_forwarding_buffer.flush_one(|packet| {
            let expiry = packet.expires_at();
            let meta = packet.metadata();

            // Update the packet lifetime.
            meta.set_lifetime(expiry - svcs.core.now);
            // Update position in packet only if we are the origin.
            if meta.source_position_vector().address.mac_addr() == svcs.core.address().mac_addr() {
                meta.set_source_position_vector(svcs.core.ego_position_vector());
            }

            emit(
                self,
                svcs.core,
                svcs.congestion_control,
                (
                    EthernetAddress::BROADCAST,
                    meta.to_owned(),
                    packet.payload(),
                ),
            )
        })
    }

    /// Dequeue one expired packet from the contention buffer.
    /// Returns `None` when no packets are available.
    pub(crate) fn dispatch_contention_buffer<F, E>(
        &mut self,
        svcs: InterfaceServices,
        emit: F,
    ) -> Option<Result<(), E>>
    where
        F: FnOnce(
            &mut InterfaceInner,
            &mut GnCore,
            &mut Congestion,
            (EthernetAddress, GeonetRepr, &[u8]),
        ) -> Result<(), E>,
    {
        svcs.cb_forwarding_buffer
            .dequeue_expired(svcs.core.now, |packet| {
                let expiry = packet.expires_at();
                let meta = packet.metadata();

                // Update the packet lifetime.
                meta.set_lifetime(expiry - svcs.core.now);
                // Update position in packet only if we are the origin.
                if meta.source_position_vector().address.mac_addr()
                    == svcs.core.address().mac_addr()
                {
                    meta.set_source_position_vector(svcs.core.ego_position_vector());
                }

                emit(
                    self,
                    svcs.core,
                    svcs.congestion_control,
                    (
                        EthernetAddress::BROADCAST,
                        meta.to_owned(),
                        packet.payload(),
                    ),
                )
            })
    }

    /// Executes the forwarding algorithm selection procedure
    /// as described in ETSI TS 103 836-4-1 V2.1.1 clause D.
    ///
    /// # Panics
    ///
    /// This method panics if `packet` is neither of Anycast nor Broadcast type.
    fn forwarding_algorithm(
        &mut self,
        svcs: &mut InterfaceServices,
        packet: &GeonetPacket,
        link_layer: Option<EthernetRepr>,
    ) -> Option<EthernetAddress> {
        let area = packet.geo_area();
        let f_ego = area.inside_or_at_border(svcs.core.geo_position());

        let ret = if f_ego {
            match GN_AREA_FORWARDING_ALGORITHM {
                GnAreaForwardingAlgorithm::Unspecified | GnAreaForwardingAlgorithm::Simple => {
                    self.area_simple_forwarding()
                }
                GnAreaForwardingAlgorithm::Cbf => {
                    self.area_contention_based_forwarding(svcs, packet, link_layer)
                }
                GnAreaForwardingAlgorithm::Advanced => {
                    self.area_advanced_forwarding(svcs, packet, link_layer)
                }
            }
        } else {
            let inside = link_layer
                .and_then(|ll| self.location_table.find(&ll.src_addr))
                .is_some_and(|neigh| {
                    neigh.position_vector.is_accurate
                        && area.inside_or_at_border(neigh.geo_position())
                });

            match (inside, GN_NON_AREA_FORWARDING_ALGORITHM) {
                (
                    true,
                    GnNonAreaForwardingAlgorithm::Unspecified
                    | GnNonAreaForwardingAlgorithm::Greedy,
                ) => self.non_area_greedy_forwarding(svcs, packet),
                (true, GnNonAreaForwardingAlgorithm::Cbf) => {
                    self.non_area_contention_based_forwarding(svcs, packet, link_layer)
                }
                _ => None,
            }
        };

        ret
    }

    /// Executes the non area greedy forwarding algorithm as
    /// described in ETSI TS 103 836-4-1 V2.1.1 clause E.2.
    ///
    /// # Panics
    ///
    /// This method panics if `packet` does not contain a destination nor a payload.
    fn non_area_greedy_forwarding(
        &mut self,
        svcs: &mut InterfaceServices,
        packet: &GeonetPacket,
    ) -> Option<EthernetAddress> {
        let dest = packet.geo_destination();
        let dist_ego_dest = svcs.core.geo_position().distance_to(&dest);
        let mut mfr = dist_ego_dest;

        let mut next_hop = None;
        for neighbor in self.location_table.neighbour_list().into_iter() {
            let dist = packet
                .geo_destination()
                .distance_to(&neighbor.geo_position());
            if mfr < dist {
                next_hop = Some(neighbor.position_vector.address.mac_addr().into());
                mfr = dist;
            }
        }

        let ll_addr = if mfr < dist_ego_dest {
            next_hop
        } else {
            if packet.common_header().traffic_class.store_carry_forward() {
                match (packet, packet.payload().into_option()) {
                    (GeonetPacket::Unicast(u), Some(payload)) => {
                        svcs.uc_forwarding_buffer
                            .enqueue(u.geonet_variant(), payload, svcs.core.now)
                            .ok();
                    }
                    (GeonetPacket::Anycast(_) | GeonetPacket::Broadcast(_), Some(payload)) => {
                        let metadata = packet.geonet_repr();
                        svcs.bc_forwarding_buffer
                            .enqueue(metadata, payload, svcs.core.now)
                            .ok();
                    }
                    _ => unreachable!(),
                };

                None
            } else {
                Some(EthernetAddress::BROADCAST.into())
            }
        };

        ll_addr
    }

    /// Executes the non area contention algorithm as
    /// described in ETSI TS 103 836-4-1 V2.1.1 clause E.3.
    ///
    /// # Panics
    ///
    /// This method panics if `packet` does not contain a destination nor a payload.
    fn non_area_contention_based_forwarding(
        &mut self,
        svcs: &mut InterfaceServices,
        packet: &GeonetPacket,
        link_layer: Option<EthernetRepr>,
    ) -> Option<EthernetAddress> {
        let Some(EthernetRepr { src_addr, .. }) = link_layer else {
            return Some(EthernetAddress::BROADCAST.into());
        };

        let cbf_id = CbfIdentifier(packet.source_address(), packet.sequence_number());
        if svcs.cb_forwarding_buffer.remove(cbf_id) {
            return None;
        }

        let entry_opt = self.location_table.find(&src_addr);
        let pai_ego = svcs.core.ego_position_vector.is_accurate;
        let payload = packet.payload().into_option().unwrap();

        match (entry_opt, pai_ego) {
            (Some(entry), true) if entry.position_vector.is_accurate => {
                let destination = packet.geo_destination();
                let dist_p_se = destination.distance_to(&entry.geo_position());
                let dist_p_ego = destination.distance_to(&svcs.core.geo_position());
                let progress = dist_p_se - dist_p_ego;

                if progress > Length::new::<meter>(0.0) {
                    let cbf_timer = Self::cbf_timeout_equation(progress);
                    let meta = packet.geonet_repr();
                    svcs.cb_forwarding_buffer
                        .enqueue(meta, payload, cbf_id, cbf_timer, svcs.core.now, src_addr)
                        .ok();
                }
            }
            _ => {
                let meta = packet.geonet_repr();
                svcs.cb_forwarding_buffer
                    .enqueue(
                        meta,
                        payload,
                        cbf_id,
                        GN_CBF_MAX_TIME,
                        svcs.core.now,
                        src_addr,
                    )
                    .ok();
            }
        };

        None
    }

    /// Executes the simple GeoBroadcast forwarding algorithm as
    /// described in ETSI TS 103 836-4-1 V2.1.1 clause F.2.
    ///
    /// Always return the link layer broadcast address.
    fn area_simple_forwarding(&self) -> Option<EthernetAddress> {
        Some(EthernetAddress::BROADCAST.into())
    }

    /// Executes the non area contention algorithm as
    /// described in ETSI TS 103 836-4-1 V2.1.1 clause F.3.
    ///
    /// # Panics
    ///
    /// This method panics if `packet` does not contain a destination nor a payload.
    fn area_contention_based_forwarding(
        &mut self,
        svcs: &mut InterfaceServices,
        packet: &GeonetPacket,
        link_layer: Option<EthernetRepr>,
    ) -> Option<EthernetAddress> {
        let Some(EthernetRepr { src_addr, .. }) = link_layer else {
            return Some(EthernetAddress::BROADCAST.into());
        };

        let cbf_id = CbfIdentifier(packet.source_address(), packet.sequence_number());
        if svcs.cb_forwarding_buffer.remove(cbf_id) {
            return None;
        }

        let entry_opt = self.location_table.find(&src_addr);
        let pai_ego = svcs.core.ego_position_vector.is_accurate;
        let payload = packet.payload().into_option().unwrap();

        let cbf_timer = match (entry_opt, pai_ego) {
            (Some(entry), true) if entry.position_vector.is_accurate => {
                let dist_se_ego = entry.geo_position().distance_to(&svcs.core.geo_position());
                Self::cbf_timeout_equation(dist_se_ego)
            }
            _ => GN_CBF_MAX_TIME,
        };

        let meta = packet.geonet_repr();
        svcs.cb_forwarding_buffer
            .enqueue(meta, payload, cbf_id, cbf_timer, svcs.core.now, src_addr)
            .ok();

        None
    }

    /// Executes the non area contention algorithm as
    /// described in ETSI TS 103 836-4-1 V2.1.1 clause F.4.
    ///
    /// # Panics
    ///
    /// This method panics if `packet` does not contain a destination nor a payload.
    fn area_advanced_forwarding(
        &mut self,
        svcs: &mut InterfaceServices,
        packet: &GeonetPacket,
        link_layer: Option<EthernetRepr>,
    ) -> Option<EthernetAddress> {
        let Some(EthernetRepr {
            src_addr, dst_addr, ..
        }) = link_layer
        else {
            return Some(EthernetAddress::BROADCAST.into());
        };

        let cbf_id = CbfIdentifier(packet.source_address(), packet.sequence_number());

        let payload = packet.payload().into_option().unwrap();
        let meta = packet.geonet_repr();

        let rc = if let Some(_popped) = svcs.cb_forwarding_buffer.pop_if(cbf_id, |e| {
            if e.cbf_counter >= VELOCE_CBF_MAX_RETRANSMIT {
                true
            } else {
                let entry_sndr_opt = self.location_table.find(&e.sender());
                let entry_fwdr_opt = self.location_table.find(&src_addr);
                let inside = match (entry_sndr_opt, entry_fwdr_opt) {
                    (Some(entry_sndr), Some(entry_fwdr)) => {
                        let dist_r = entry_sndr
                            .geo_position()
                            .distance_to(&svcs.core.geo_position());
                        let dist_f = entry_fwdr
                            .geo_position()
                            .distance_to(&svcs.core.geo_position());
                        let dist_rf = entry_sndr
                            .geo_position()
                            .distance_to(&entry_fwdr.geo_position());
                        let mut angle_fsr = Angle::new::<radian>(0.0);
                        if dist_r > Length::new::<meter>(0.0) && dist_f > Length::new::<meter>(0.0)
                        {
                            let cos_fsr = (dist_rf * dist_rf - dist_r * dist_r - dist_f * dist_f)
                                / (-2.0 * dist_r * dist_f);
                            angle_fsr = cos_fsr.acos();
                        }

                        dist_r < dist_f
                            && dist_f < Length::new::<meter>(GN_DEFAULT_MAX_COMMUNICATION_RANGE)
                            && angle_fsr < Angle::new::<degree>(GN_BROADCAST_CBF_DEF_SECTOR_ANGLE)
                    }
                    _ => false,
                };
                if inside {
                    true
                } else {
                    let pai_ego = svcs.core.ego_position_vector.is_accurate;

                    let cbf_timer = match (entry_fwdr_opt, pai_ego) {
                        (Some(entry), true) if entry.position_vector.is_accurate => {
                            let dist_se_ego =
                                entry.geo_position().distance_to(&svcs.core.geo_position());
                            Self::cbf_timeout_equation(dist_se_ego)
                        }
                        _ => GN_CBF_MAX_TIME,
                    };

                    e.cbf_counter += 1;
                    e.cbf_expires_at = svcs.core.now + cbf_timer;

                    false
                }
            }
        }) {
            None
        } else {
            if dst_addr == svcs.core.address().mac_addr() {
                let nh = self.non_area_greedy_forwarding(svcs, packet);
                svcs.cb_forwarding_buffer
                    .enqueue(
                        meta,
                        payload,
                        cbf_id,
                        GN_CBF_MAX_TIME,
                        svcs.core.now,
                        src_addr,
                    )
                    .ok();
                nh
            } else {
                /* Contention buffering. There is a modification in our implementation since the condition
                ((PV_SE EXISTS) OR (PV_SE = EPV)) AND (PAI_SE = TRUE)) is weird and does not make sense.
                PV_SE cannot be EPV since SE is deduced from the link layer sender mac address, the OR condition
                seems to be a mistake. On ETSI EN 302 636-4-1 V1.2.1, this condition does not exists, our
                implementation follows that version.
                */
                let entry_opt = self.location_table.find(&src_addr);
                let pai_ego = svcs.core.ego_position_vector.is_accurate;

                let cbf_timer = match (entry_opt, pai_ego) {
                    (Some(entry), true) if entry.position_vector.is_accurate => {
                        let dist_se_ego =
                            entry.geo_position().distance_to(&svcs.core.geo_position());
                        Self::cbf_timeout_equation(dist_se_ego)
                    }
                    _ => GN_CBF_MAX_TIME,
                };
                svcs.cb_forwarding_buffer
                    .enqueue(meta, payload, cbf_id, cbf_timer, svcs.core.now, src_addr)
                    .ok();

                None
            }
        };

        rc
    }

    /// Computes the Non Area Contention Based Forwarding algorithm equation.
    /// This equation is defined in ETSI 103 836-4-1 V2.1.1 clauses E.3 and F3.
    fn cbf_timeout_equation(progress: Length) -> Duration {
        let max_range = Length::new::<meter>(GN_DEFAULT_MAX_COMMUNICATION_RANGE);
        if progress > max_range {
            GN_CBF_MIN_TIME
        } else if progress > Length::new::<meter>(0.0) {
            let eq = GN_CBF_MAX_TIME.millis()
                + (GN_CBF_MIN_TIME.millis() - GN_CBF_MAX_TIME.millis())
                    / GN_DEFAULT_MAX_COMMUNICATION_RANGE as u64
                    * progress.get::<meter>() as u64;
            Duration::from_millis(eq)
        } else {
            GN_CBF_MAX_TIME
        }
    }

    /// Pass received Geonetworking payload to upper layer.
    fn pass_up(
        &mut self,
        svcs: &InterfaceServices,
        sockets: &mut SocketSet,
        _meta: PacketMeta,
        repr: &GeonetRepr,
        payload: &[u8],
    ) {
        let ind = Indication {
            upper_proto: repr.next_header().into(),
            transport: repr.transport(),
            ali_id: (),
            its_aid: (),
            cert_id: (),
            rem_lifetime: repr.lifetime(),
            rem_hop_limit: repr.hop_limit(),
            traffic_class: repr.traffic_class(),
        };

        #[cfg(feature = "socket-geonet")]
        let handled_by_geonet_socket = self.geonet_socket_filter(sockets, ind, payload);
        #[cfg(not(feature = "socket-geonet"))]
        let handled_by_geonet_socket = false;

        match ind.upper_proto {
            UpperProtocol::BtpA => {
                self.process_btp_a(svcs, sockets, ind, handled_by_geonet_socket, repr, payload)
            }
            UpperProtocol::BtpB => {
                self.process_btp_b(svcs, sockets, ind, handled_by_geonet_socket, payload)
            }
            UpperProtocol::Any => {}
            UpperProtocol::Ipv6 => {} // _ if handled_by_geonet_socket => None,
        };
    }
}
