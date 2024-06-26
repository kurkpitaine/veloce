use std::net::SocketAddr;

use crate::{
    iface::{Interface, SocketHandle, SocketSet},
    network::{GnCore, Indication, Request, Transport, UpperProtocol},
    socket,
    time::{Instant, TAI2004},
    wire::{
        GnAddress, UtChangePosition, UtGnEventInd, UtGnTriggerGeoAnycast, UtGnTriggerGeoBroadcast,
        UtGnTriggerGeoUnicast, UtGnTriggerShb, UtGnTriggerTsb, UtInitialize, UtMessageType,
        UtPacket, UtResult,
    },
};

use log::{debug, error};

pub type Result = core::result::Result<(), ()>;

pub struct State {
    /// Initially configured Geonetworking address.
    initial_address: GnAddress,
    /// Geonetworking socket handle.
    gn_socket_handle: SocketHandle,
    /// UT server address.
    ut_server: Option<SocketAddr>,
}

impl State {
    /// Constructs a new State.
    pub fn new(addr: GnAddress, sock_handle: SocketHandle) -> Self {
        State {
            initial_address: addr,
            gn_socket_handle: sock_handle,
            ut_server: None,
        }
    }

    /// Dispatch an Uppertester request.
    pub fn ut_dispatcher(
        &mut self,
        timestamp: Instant,
        iface: &mut Interface,
        router: &mut GnCore,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
        source: SocketAddr,
    ) -> Option<[u8; 2]> {
        let mut res = [0u8; 2];
        let mut res_packet = UtPacket::new(&mut res);

        let ut_packet = UtPacket::new(buffer);

        let rc = match ut_packet.message_type() {
            UtMessageType::UtInitialize => {
                res_packet.set_message_type(UtMessageType::UtInitializeResult);
                self.ut_initialize(timestamp, iface, router, ut_packet.payload(), source)
            }
            UtMessageType::UtChangePosition if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtChangePositionResult);
                self.ut_change_position(timestamp, iface, router, ut_packet.payload())
            }
            UtMessageType::UtChangePseudonym if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtChangePseudonymResult);
                self.ut_change_pseudonym(timestamp, iface, router, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerGeoUnicast if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_geo_unicast(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerGeoBroadcast if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_geo_broadcast(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerGeoAnycast if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_geo_anycast(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerShb if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_shb(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerTsb if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtGnTriggerResult);
                self.ut_trigger_tsb(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtBtpTriggerA if self.ut_server == Some(source) => {
                res_packet.set_message_type(UtMessageType::UtBtpTriggerResult);
                Err(())
            }
            UtMessageType::UtBtpTriggerB if self.ut_server == Some(source) => {
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

    /// Notify to the Uppertester a received Geonetworking packet.
    pub fn ut_gn_event(
        &mut self,
        meta: Indication,
        buffer: &[u8],
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let (ut_server, msg_type) = match (self.ut_server, meta.upper_proto) {
            (Some(s), UpperProtocol::Any) => (s, UtMessageType::UtGnEventInd),
            _ => return None,
        };

        let mut res_buf = vec![0u8; 3 + buffer.len()];
        let mut res_pkt = UtPacket::new(&mut res_buf);
        res_pkt.set_message_type(msg_type);

        let mut ind_pkt = UtGnEventInd::new(res_pkt.payload_mut());
        ind_pkt.set_payload_len(buffer.len());
        ind_pkt.payload_mut().copy_from_slice(buffer);

        Some((ut_server, res_buf))
    }

    fn ut_initialize(
        &mut self,
        _timestamp: Instant,
        iface: &mut Interface,
        router: &mut GnCore,
        buffer: &[u8],
        source: SocketAddr,
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

        // Set server address
        self.ut_server = Some(source);

        Ok(())
    }

    fn ut_change_position(
        &self,
        timestamp: Instant,
        _iface: &mut Interface,
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
        debug!("GUC meta: {:?}", req_meta);
        socket
            .send_slice(&ut_guc_pkt.payload()[..ut_guc_pkt.payload_len()], req_meta)
            .map_err(|e| {
                error!("Failed to send GUC packet: {}", e);
                ()
            })
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
        debug!("SHB meta: {:?}", req_meta);
        socket
            .send_slice(&ut_shb_pkt.payload()[..ut_shb_pkt.payload_len()], req_meta)
            .map_err(|e| {
                error!("Failed to send SHB packet: {}", e);
                ()
            })
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
        debug!("TSB meta: {:?}", req_meta);
        socket
            .send_slice(&ut_tsb_pkt.payload()[..ut_tsb_pkt.payload_len()], req_meta)
            .map_err(|e| {
                error!("Failed to send TSB packet: {}", e);
                ()
            })
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
        debug!("GBC meta: {:?}", req_meta);
        socket
            .send_slice(&ut_gbc_pkt.payload()[..ut_gbc_pkt.payload_len()], req_meta)
            .map_err(|e| {
                error!("Failed to send GBC packet: {}", e);
                ()
            })
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
        debug!("GAC meta: {:?}", req_meta);
        socket
            .send_slice(&ut_gbc_pkt.payload()[..ut_gbc_pkt.payload_len()], req_meta)
            .map_err(|e| {
                error!("Failed to send GAC packet: {}", e);
                ()
            })
    }
}
