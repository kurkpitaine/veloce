use rasn::de;

use crate::{
    iface::{Interface, SocketHandle, SocketSet},
    network::{GnCore, Request, Transport},
    socket,
    time::{Instant, TAI2004},
    wire::{
        GnAddress, UtChangePosition, UtGnTriggerGeoUnicast, UtInitialize, UtMessageType, UtPacket,
        UtResult,UtGnTriggerGeoAnycast, UtGnTriggerGeoBroadcast, UtGnTriggerShb, UtGnTriggerTsb,
    },
};

pub type Result = core::result::Result<(), ()>;

pub struct State {
    /// Initially configured Geonetworking address.
    initial_address: GnAddress,
    /// Geonetworking socket handle.
    gn_socket_handle: SocketHandle,
}

impl State {
    /// Constructs a new State.
    pub fn new(addr: GnAddress, sock_handle: SocketHandle) -> Self {
        State {
            initial_address: addr,
            gn_socket_handle: sock_handle,
        }
    }

    /// Dispatch an Uppertester request.
    pub fn ut_dispatcher(
        &self,
        timestamp: Instant,
        iface: &mut Interface,
        router: &mut GnCore,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Option<[u8; 2]> {
        let mut res = [0u8; 2];
        let mut res_packet = UtPacket::new(&mut res);

        let ut_packet = UtPacket::new(buffer);

        let rc = match ut_packet.message_type() {
            UtMessageType::UtInitialize => {
                res_packet.set_message_type(UtMessageType::UtInitializeResult);
                self.ut_initialize(timestamp, iface, router, ut_packet.payload())
            }
            UtMessageType::UtChangePosition => {
                res_packet.set_message_type(UtMessageType::UtChangePositionResult);
                self.ut_change_position(timestamp, iface, router, buffer)
            }
            UtMessageType::UtChangePseudonym => {
                res_packet.set_message_type(UtMessageType::UtChangePseudonymResult);
                self.ut_change_pseudonym(timestamp, iface, router, buffer)
            }
            UtMessageType::UtGnTriggerGeoUnicast => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_geo_unicast(timestamp, sockets, buffer)
            }
            UtMessageType::UtGnTriggerGeoBroadcast => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_geo_broadcast(timestamp, sockets, buffer)
            }
            UtMessageType::UtGnTriggerGeoAnycast => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_geo_anycast(timestamp, sockets, buffer)
            }
            UtMessageType::UtGnTriggerShb => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_shb(timestamp, sockets, buffer)
            }
            UtMessageType::UtGnTriggerTsb => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_tsb(timestamp, sockets, buffer)
            }
            UtMessageType::UtBtpTriggerA => {
                res_packet.set_message_type(UtMessageType::UtBtpTriggerResult);
                Err(())
            }
            UtMessageType::UtBtpTriggerB => {
                res_packet.set_message_type(UtMessageType::UtBtpTriggerResult);
                Err(())
            }
            _ => {
                return None;
            }
        };

        if rc.is_ok() {
            res_packet.set_result(UtResult::Success)
        } else {
            res_packet.set_result(UtResult::Failure)
        }

        Some(res)
    }

    fn ut_initialize(
        &self,
        _timestamp: Instant,
        iface: &mut Interface,
        router: &mut GnCore,
        buffer: &[u8],
    ) -> Result {
        let ut_init = UtInitialize::new(buffer);

        // TODO: set correct certificate if testing with security.
        // return an error since we don't support security yet.
        if ut_init.hashed_id8() != UtInitialize::<&[u8]>::ZERO_HASHEDID8 {
            return Err(());
        }

        // Reset buffers
        iface.ls_buffer.clear();
        iface.uc_forwarding_buffer.clear();
        iface.bc_forwarding_buffer.clear();
        iface.cb_forwarding_buffer.clear();

        // Reset location table
        iface.inner.clear_location_table();

        // Reset sequence number
        iface.inner.reset_sequence_number();

        // Reset geonetworking address
        router.set_address(self.initial_address);

        Ok(())
    }

    fn ut_change_position(
        &self,
        timestamp: Instant,
        iface: &mut Interface,
        router: &mut GnCore,
        buffer: &[u8],
    ) -> Result {
        let ut_ch_pos = UtChangePosition::new(buffer);
        router.ego_position_vector.latitude += ut_ch_pos.delta_latitude();
        router.ego_position_vector.longitude += ut_ch_pos.delta_longitude();
        router.ego_position_vector.timestamp = TAI2004::from_unix_instant(timestamp).into();

        Ok(())
    }

    fn ut_change_pseudonym(
        &self,
        _timestamp: Instant,
        _iface: &mut Interface,
        _router: &mut GnCore,
        _buffer: &[u8],
    ) -> Result {
        // TODO: we don't support changing pseudonym yet.
        // This has to be made on the upper layers.
        Err(())
    }

    fn ut_trigger_geo_unicast(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result {
        let socket = sockets.get_mut::<socket::geonet::Socket>(self.gn_socket_handle);

        let ut_guc_pkt = UtGnTriggerGeoUnicast::new(buffer);
        let req_meta = Request {
            transport: Transport::Unicast(ut_guc_pkt.dst_addr()),
            max_lifetime: ut_guc_pkt.lifetime(),
            traffic_class: ut_guc_pkt.traffic_class(),
            ..Default::default()
        };
        socket
            .send_slice(&ut_guc_pkt.payload()[..ut_guc_pkt.payload_len()], req_meta)
            .map_err(|_| ())
    }

    fn ut_trigger_shb(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result {
        let socket = sockets.get_mut::<socket::geonet::Socket>(self.gn_socket_handle);

        let ut_shb_pkt = UtGnTriggerShb::new(buffer);
        let req_meta = Request {
            transport: Transport::SingleHopBroadcast,
            traffic_class: ut_shb_pkt.traffic_class(),
            ..Default::default()
        };
        socket
            .send_slice(&ut_shb_pkt.payload()[..ut_shb_pkt.payload_len()], req_meta)
            .map_err(|_| ())
    }

    fn ut_trigger_tsb(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result {
        let socket = sockets.get_mut::<socket::geonet::Socket>(self.gn_socket_handle);

        let ut_tsb_pkt = UtGnTriggerTsb::new(buffer);
        let req_meta = Request {
            transport: Transport::TopoBroadcast,
            max_hop_limit: ut_tsb_pkt.hops(),
            max_lifetime: ut_tsb_pkt.lifetime(),
            traffic_class: ut_tsb_pkt.traffic_class(),
            ..Default::default()
        };
        socket
            .send_slice(&ut_tsb_pkt.payload()[..ut_tsb_pkt.payload_len()], req_meta)
            .map_err(|_| ())
    }

    fn ut_trigger_geo_broadcast(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result {
        let socket = sockets.get_mut::<socket::geonet::Socket>(self.gn_socket_handle);

        let ut_gbc_pkt = UtGnTriggerGeoBroadcast::new(buffer);
        let req_meta = Request {
            transport: Transport::Broadcast(ut_gbc_pkt.area()),
            max_lifetime: ut_gbc_pkt.lifetime(),
            traffic_class: ut_gbc_pkt.traffic_class(),
            ..Default::default()
        };
        socket
            .send_slice(&ut_gbc_pkt.payload()[..ut_gbc_pkt.payload_len()], req_meta)
            .map_err(|_| ())
    }

    fn ut_trigger_geo_anycast(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result {
        let socket = sockets.get_mut::<socket::geonet::Socket>(self.gn_socket_handle);

        let ut_gbc_pkt = UtGnTriggerGeoAnycast::new(buffer);
        let req_meta = Request {
            transport: Transport::Anycast(ut_gbc_pkt.area()),
            max_lifetime: ut_gbc_pkt.lifetime(),
            traffic_class: ut_gbc_pkt.traffic_class(),
            ..Default::default()
        };
        socket
            .send_slice(&ut_gbc_pkt.payload()[..ut_gbc_pkt.payload_len()], req_meta)
            .map_err(|_| ())
    }
}
