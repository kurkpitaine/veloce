use std::{collections::HashMap, net::SocketAddr};

use crate::{
    common::geo_area::{Circle, GeoArea, Shape},
    iface::{Interface, SocketHandle, SocketSet},
    network::{GnCore, Indication, Request, Transport, UpperProtocol},
    rand::Rand,
    socket::{
        self,
        denm::{ActionId, EventHandle, EventParameters},
    },
    time::{Duration, Instant, TAI2004},
    types::{tenth_of_microdegree, Distance, Pseudonym},
    wire::{
        uppertester::{
            btp::{UtBtpTriggerA, UtBtpTriggerB},
            denm::{
                UtDenmEventInd, UtDenmTermination, UtDenmTrigger, UtDenmTriggerResult,
                UtDenmUpdate, UtDenmUpdateResult,
            },
            UtResultPacket,
        },
        BtpAHeader, BtpARepr, BtpBHeader, BtpBRepr, GnAddress, GnTrafficClass, UtChangePosition,
        UtGnEventInd, UtGnTriggerGeoAnycast, UtGnTriggerGeoBroadcast, UtGnTriggerGeoUnicast,
        UtGnTriggerShb, UtGnTriggerTsb, UtInitialize, UtMessageType, UtPacket, UtResult,
    },
};

use log::{debug, error, trace};
use uom::si::{angle::degree, f64::Angle, length::meter};
use veloce_asn1::{
    defs::etsi_messages_r2::{denm__pdu__descriptions as denm, etsi__its__cdd as cdd},
    prelude::rasn,
};

pub type Result<T> = core::result::Result<T, ()>;

pub struct State {
    /// Initially configured Geonetworking address.
    initial_address: GnAddress,
    /// Geonetworking socket handle.
    gn_socket_handle: SocketHandle,
    /// DENM socket handle.
    denm_socket_handle: SocketHandle,
    /// UT server address.
    ut_server: Option<SocketAddr>,
    /// DENM handles.
    denm_handles: HashMap<EventHandle, EventParameters>,
}

impl State {
    /// Constructs a new State.
    pub fn new(addr: GnAddress, gn_handle: SocketHandle, denm_handle: SocketHandle) -> Self {
        State {
            initial_address: addr,
            gn_socket_handle: gn_handle,
            denm_socket_handle: denm_handle,
            ut_server: None,
            denm_handles: HashMap::new(),
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
    ) -> Option<Vec<u8>> {
        let mut res_len = 1024;
        let mut res: Vec<u8> = vec![0u8; res_len];
        let mut res_packet = UtResultPacket::new(&mut res);

        let ut_packet = UtPacket::new(buffer);

        let rc = match ut_packet.message_type() {
            UtMessageType::UtInitialize => {
                res_packet.set_result_message_type(UtMessageType::UtInitializeResult);
                res_len = 2;
                self.ut_initialize(
                    timestamp,
                    sockets,
                    iface,
                    router,
                    ut_packet.payload(),
                    source,
                )
            }
            UtMessageType::UtChangePosition if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtChangePositionResult);
                res_len = 2;
                self.ut_change_position(timestamp, iface, router, ut_packet.payload())
            }
            UtMessageType::UtChangePseudonym if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtChangePseudonymResult);
                res_len = 2;
                self.ut_change_pseudonym(timestamp, iface, router, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerGeoUnicast if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtGnTriggerResult);
                res_len = 2;
                self.ut_trigger_geo_unicast(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerGeoBroadcast if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtGnTriggerResult);
                res_len = 2;
                self.ut_trigger_geo_broadcast(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerGeoAnycast if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtGnTriggerResult);
                res_len = 2;
                self.ut_trigger_geo_anycast(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerShb if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtGnTriggerResult);
                res_len = 2;
                self.ut_trigger_shb(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtGnTriggerTsb if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtGnTriggerResult);
                res_len = 2;
                self.ut_trigger_tsb(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtBtpTriggerA if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtBtpTriggerResult);
                res_len = 2;
                self.ut_btp_trigger_a(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtBtpTriggerB if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtBtpTriggerResult);
                res_len = 2;
                self.ut_btp_trigger_b(timestamp, sockets, ut_packet.payload())
            }
            UtMessageType::UtDenmTrigger if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtDenmTriggerResult);
                res_len = 8;
                self.ut_denm_trigger(timestamp, sockets, router, ut_packet.payload())
                    .map(|h| {
                        let mut denm_res = UtDenmTriggerResult::new(res_packet.payload_mut());
                        denm_res.set_station_id(h.action_id().station_id);
                        denm_res.set_sequence_number(h.action_id().seq_num);
                    })
            }
            UtMessageType::UtDenmUpdate if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtDenmUpdateResult);
                res_len = 8;
                self.ut_denm_update(timestamp, sockets, router, ut_packet.payload())
                    .map(|h| {
                        let mut denm_res = UtDenmUpdateResult::new(res_packet.payload_mut());
                        denm_res.set_station_id(h.action_id().station_id);
                        denm_res.set_sequence_number(h.action_id().seq_num);
                    })
            }
            UtMessageType::UtDenmTermination if self.ut_server == Some(source) => {
                res_packet.set_result_message_type(UtMessageType::UtDenmTerminationResult);
                res_len = 2;
                self.ut_denm_terminate(timestamp, sockets, router, ut_packet.payload())
            }
            _ => {
                return None;
            }
        };

        if rc.is_ok() {
            res_packet.set_result_code(UtResult::Success);
        } else {
            res_packet.set_result_code(UtResult::Failure);
        }

        res.truncate(res_len);
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
        sockets: &mut SocketSet<'_>,
        iface: &mut Interface,
        router: &mut GnCore,
        buffer: &[u8],
        source: SocketAddr,
    ) -> Result<()> {
        let ut_init = UtInitialize::new(buffer);

        // TODO: set correct certificate if testing with security.
        // return an error since we don't support security yet.
        if ut_init.hashed_id8() != UtInitialize::<&[u8]>::ZERO_HASHEDID8 {
            return Err(());
        }

        // Reset denm socket and local handles.
        let denm_socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);
        denm_socket.reset();
        self.denm_handles.clear();

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
    ) -> Result<()> {
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
        router: &mut GnCore,
        _buffer: &[u8],
    ) -> Result<()> {
        let mut random = Rand::new(router.pseudonym.0.into());
        router.pseudonym = Pseudonym(random.rand_u32());
        Ok(())
    }

    fn ut_trigger_geo_unicast(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result<()> {
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
    ) -> Result<()> {
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
    ) -> Result<()> {
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
    ) -> Result<()> {
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
    ) -> Result<()> {
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

    fn ut_btp_trigger_a(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result<()> {
        let socket = sockets.get_mut::<socket::geonet::Socket>(self.gn_socket_handle);
        let ut_btp_a_pkt = UtBtpTriggerA::new(buffer);

        let mut btp_buf = [0u8; 4];
        let btp_repr = BtpARepr {
            dst_port: ut_btp_a_pkt.dst_port(),
            src_port: ut_btp_a_pkt.src_port(),
        };

        btp_repr.emit(&mut BtpAHeader::new_unchecked(&mut btp_buf));

        socket
            .send_slice(&btp_buf, Default::default())
            .map_err(|e| {
                error!("Failed to send BTP-A packet: {}", e);
                ()
            })
    }

    fn ut_btp_trigger_b(
        &self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        buffer: &[u8],
    ) -> Result<()> {
        let socket = sockets.get_mut::<socket::geonet::Socket>(self.gn_socket_handle);
        let ut_btp_b_pkt = UtBtpTriggerB::new(buffer);

        let mut btp_buf = [0u8; 4];
        let btp_repr = BtpBRepr {
            dst_port: ut_btp_b_pkt.dst_port(),
            dst_port_info: ut_btp_b_pkt.dst_port_info(),
        };

        btp_repr.emit(&mut BtpBHeader::new_unchecked(&mut btp_buf));

        socket
            .send_slice(&btp_buf, Default::default())
            .map_err(|e| {
                error!("Failed to send BTP-B packet: {}", e);
                ()
            })
    }

    // Notify to the Uppertester a received DENM.
    pub fn ut_denm_event(&mut self, evt: socket::denm::PollEvent) -> Option<(SocketAddr, Vec<u8>)> {
        let (ut_server, rx_evt) = match (self.ut_server, evt.poll_in_evt()) {
            (Some(s), Some(e)) => (s, e),
            _ => return None,
        };

        let info = match rx_evt {
            socket::denm::PollProcessEvent::RecvNew(info) => info,
            socket::denm::PollProcessEvent::RecvUpdate(info) => info,
            socket::denm::PollProcessEvent::RecvCancel(info) => info,
            socket::denm::PollProcessEvent::RecvNegation(info) => info,
        };

        let encoded = rasn::uper::encode(&info.msg).unwrap();

        let mut res_buf = vec![0u8; 3 + encoded.len()];
        let mut res_pkt = UtPacket::new(&mut res_buf);
        res_pkt.set_message_type(UtMessageType::UtDenmEventInd);

        let mut ind_pkt = UtDenmEventInd::new(res_pkt.payload_mut());
        ind_pkt.set_payload_len(encoded.len());
        ind_pkt.payload_mut().copy_from_slice(&encoded);

        Some((ut_server, res_buf))
    }

    fn ut_denm_trigger(
        &mut self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        router: &mut GnCore,
        buffer: &[u8],
    ) -> Result<EventHandle> {
        let socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);
        let ut_denm_trig = UtDenmTrigger::new(buffer);
        let pos = router.geo_position();

        let pp = cdd::PathPoint::new(
            cdd::DeltaReferencePosition::new(
                cdd::DeltaLatitude(0),
                cdd::DeltaLongitude(0),
                cdd::DeltaAltitude(0),
            ),
            None,
        );
        let traces = cdd::Traces(vec![cdd::Path(vec![pp])]);

        let event = socket::denm::EventParameters {
            detection_time: ut_denm_trig.detection_time(),
            validity_duration: ut_denm_trig
                .has_validity_duration()
                .then(|| ut_denm_trig.validity_duration()),
            position: cdd::ReferencePosition {
                latitude: cdd::Latitude(pos.latitude.get::<tenth_of_microdegree>() as i32),
                longitude: cdd::Longitude(pos.longitude.get::<tenth_of_microdegree>() as i32),
                position_confidence_ellipse: cdd::PosConfidenceEllipse {
                    semi_major_confidence: cdd::SemiAxisLength(4095),
                    semi_minor_confidence: cdd::SemiAxisLength(4095),
                    semi_major_orientation: cdd::HeadingValue(3601),
                },
                altitude: cdd::Altitude {
                    altitude_value: cdd::AltitudeValue(800001),
                    altitude_confidence: cdd::AltitudeConfidence::unavailable,
                },
            },
            awareness: socket::denm::EventAwareness {
                distance: Some(
                    raw_relevance_distance_to_enum_variant(ut_denm_trig.relevance_distance())
                        .map_err(|_| {
                            error!("Unsupported relevance distance value");
                        })?,
                ),
                traffic_direction: {
                    if ut_denm_trig.has_relevance_traffic_direction() {
                        Some(
                            raw_relevance_traffic_direction_to_enum_variant(
                                ut_denm_trig.relevance_traffic_direction(),
                            )
                            .map_err(|_| {
                                error!("Unsupported relevance traffic direction value");
                            })?,
                        )
                    } else {
                        None
                    }
                },
            },
            geo_area: GeoArea {
                shape: Shape::Circle(Circle {
                    radius: Distance::new::<meter>(100.0),
                }),
                position: pos,
                angle: Angle::new::<degree>(0.0),
            },
            repetition: {
                if ut_denm_trig.has_repetition_interval() || ut_denm_trig.has_repetition_duration()
                {
                    Some(socket::denm::RepetitionParameters {
                        duration: if ut_denm_trig.has_repetition_duration() {
                            ut_denm_trig.repetition_duration()
                        } else {
                            Duration::ZERO
                        },
                        interval: if ut_denm_trig.has_repetition_interval() {
                            ut_denm_trig.repetition_interval()
                        } else {
                            Duration::ZERO
                        },
                    })
                } else {
                    None
                }
            },
            keep_alive: ut_denm_trig
                .has_transmission_interval()
                .then(|| ut_denm_trig.transmission_interval()),
            traffic_class: GnTrafficClass(1),
            situation_container: {
                Some(denm::SituationContainer::new(
                    cdd::InformationQuality(ut_denm_trig.information_quality()),
                    cdd::CauseCodeV2::new(raw_cc_and_scc_to_enum_variant(
                        ut_denm_trig.cause_code(),
                        ut_denm_trig.sub_cause_code(),
                    )),
                    None,
                    None,
                    None,
                ))
            },
            location_container: Some(denm::LocationContainer::new(None, None, traces, None, None)),
            alacarte_container: None, // Ignore alacarte container as the test spec is not clear about it.
        };

        socket
            .trigger(router, event.clone())
            .map(|h| {
                self.denm_handles.insert(h, event);
                h
            })
            .map_err(|e| {
                error!("Failed to trigger DENM: {}", e);
                ()
            })
    }

    fn ut_denm_update(
        &mut self,
        _timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        router: &mut GnCore,
        buffer: &[u8],
    ) -> Result<EventHandle> {
        let socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);
        let ut_denm_upd = UtDenmUpdate::new(buffer);

        // Look for the DENM handle.
        let (evt_hdl, evt_params) = self
            .denm_handles
            .iter_mut()
            .find(|(h, _)| {
                h.action_id().station_id == ut_denm_upd.station_id()
                    && h.action_id().seq_num == ut_denm_upd.sequence_number()
            })
            .ok_or_else(|| {
                error!(
                    "Cannot find DENM {}-{} handle",
                    ut_denm_upd.station_id(),
                    ut_denm_upd.sequence_number()
                );
            })?;

        let mut event = socket::denm::EventParameters {
            detection_time: ut_denm_upd.detection_time(),
            ..evt_params.clone()
        };

        if ut_denm_upd.has_validity_duration() {
            event.validity_duration = Some(ut_denm_upd.validity_duration());
        }

        if ut_denm_upd.has_info_quality_cause_code_sub_cause_code() {
            event.situation_container = event.situation_container.map_or_else(
                || {
                    Some(denm::SituationContainer::new(
                        cdd::InformationQuality(ut_denm_upd.information_quality()),
                        cdd::CauseCodeV2::new(raw_cc_and_scc_to_enum_variant(
                            ut_denm_upd.cause_code(),
                            ut_denm_upd.sub_cause_code(),
                        )),
                        None,
                        None,
                        None,
                    ))
                },
                |mut sc| {
                    sc.information_quality =
                        cdd::InformationQuality(ut_denm_upd.information_quality());
                    sc.event_type = cdd::CauseCodeV2::new(raw_cc_and_scc_to_enum_variant(
                        ut_denm_upd.cause_code(),
                        ut_denm_upd.sub_cause_code(),
                    ));

                    Some(sc)
                },
            );
        }

        if ut_denm_upd.has_relevance_distance() {
            event.awareness.distance = Some(
                raw_relevance_distance_to_enum_variant(ut_denm_upd.relevance_distance()).map_err(
                    |_| {
                        error!("Unsupported relevance distance value");
                    },
                )?,
            );
        }

        if ut_denm_upd.has_relevance_traffic_direction() {
            event.awareness.traffic_direction = Some(
                raw_relevance_traffic_direction_to_enum_variant(
                    ut_denm_upd.relevance_traffic_direction(),
                )
                .map_err(|_| {
                    error!("Unsupported relevance traffic direction value");
                })?,
            );
        }

        if ut_denm_upd.has_traffic_class() {
            debug!("Traffic class flag is set but value does not exists in UT packet");
        }

        if ut_denm_upd.has_transmission_interval() {
            event.keep_alive = Some(ut_denm_upd.transmission_interval());
        }

        if ut_denm_upd.has_repetition_interval() {
            event.repetition = Some(socket::denm::RepetitionParameters {
                duration: ut_denm_upd.repetition_interval(),
                interval: ut_denm_upd.repetition_interval(),
            });
        }

        socket
            .update(router, *evt_hdl, event.clone())
            .map(|h| {
                *evt_params = event;
                h
            })
            .map_err(|e| {
                error!("Failed to update DENM: {}", e);
                ()
            })
    }

    fn ut_denm_terminate(
        &mut self,
        timestamp: Instant,
        sockets: &mut SocketSet<'_>,
        router: &mut GnCore,
        buffer: &[u8],
    ) -> Result<()> {
        let socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);

        let ut_denm_upd = UtDenmTermination::new(buffer);

        // Look for the DENM handle.
        let evt_opt = self
            .denm_handles
            .iter()
            .find(|(h, _)| {
                h.action_id().station_id == ut_denm_upd.station_id()
                    && h.action_id().seq_num == ut_denm_upd.sequence_number()
            })
            .map(|(h, p)| (*h, p.clone()));

        if let Some((evt_hdl, evt_params)) = evt_opt {
            trace!(
                "Cancelling DENM {}-{}",
                evt_hdl.action_id().station_id,
                evt_hdl.action_id().seq_num
            );

            socket
                .cancel(router, evt_hdl, evt_params.clone())
                .map(|_| {
                    self.denm_handles.remove(&evt_hdl);
                    ()
                })
                .map_err(|e| {
                    error!("Failed to cancel DENM: {}", e);
                    ()
                })
        } else {
            trace!(
                "Negating DENM {}-{}",
                ut_denm_upd.station_id(),
                ut_denm_upd.sequence_number()
            );

            let pos = router.geo_position();

            let action_id = ActionId {
                station_id: ut_denm_upd.station_id(),
                seq_num: ut_denm_upd.sequence_number(),
            };

            let event = EventParameters {
                detection_time: TAI2004::from_unix_instant(timestamp),
                validity_duration: None,
                position: cdd::ReferencePosition {
                    latitude: cdd::Latitude(pos.latitude.get::<tenth_of_microdegree>() as i32),
                    longitude: cdd::Longitude(pos.longitude.get::<tenth_of_microdegree>() as i32),
                    position_confidence_ellipse: cdd::PosConfidenceEllipse {
                        semi_major_confidence: cdd::SemiAxisLength(4095),
                        semi_minor_confidence: cdd::SemiAxisLength(4095),
                        semi_major_orientation: cdd::HeadingValue(3601),
                    },
                    altitude: cdd::Altitude {
                        altitude_value: cdd::AltitudeValue(800001),
                        altitude_confidence: cdd::AltitudeConfidence::unavailable,
                    },
                },
                awareness: socket::denm::EventAwareness {
                    distance: None,
                    traffic_direction: None,
                },
                geo_area: GeoArea {
                    shape: Shape::Circle(Circle {
                        radius: Distance::new::<meter>(100.0),
                    }),
                    position: pos,
                    angle: Angle::new::<degree>(0.0),
                },
                repetition: None,
                keep_alive: None,
                traffic_class: GnTrafficClass(1),
                situation_container: None,
                location_container: None,
                alacarte_container: None,
            };

            socket
                .negate(router, action_id, event)
                .map(|_| ())
                .map_err(|e| {
                    error!("Failed to negate DENM: {}", e);
                    ()
                })
        }
    }
}

fn raw_relevance_distance_to_enum_variant(rd: u8) -> Result<cdd::StandardLength3b> {
    match rd {
        0 => Ok(cdd::StandardLength3b::lessThan50m),
        1 => Ok(cdd::StandardLength3b::lessThan100m),
        2 => Ok(cdd::StandardLength3b::lessThan200m),
        3 => Ok(cdd::StandardLength3b::lessThan500m),
        4 => Ok(cdd::StandardLength3b::lessThan1000m),
        5 => Ok(cdd::StandardLength3b::lessThan5km),
        6 => Ok(cdd::StandardLength3b::lessThan10km),
        7 => Ok(cdd::StandardLength3b::over10km),
        _ => Err(()),
    }
}

fn raw_relevance_traffic_direction_to_enum_variant(rd: u8) -> Result<cdd::TrafficDirection> {
    match rd {
        0 => Ok(cdd::TrafficDirection::allTrafficDirections),
        1 => Ok(cdd::TrafficDirection::sameAsReferenceDirection_upstreamOfReferencePosition),
        2 => Ok(cdd::TrafficDirection::sameAsReferenceDirection_downstreamOfReferencePosition),
        3 => Ok(cdd::TrafficDirection::oppositeToReferenceDirection),
        _ => Err(()),
    }
}

fn raw_cc_and_scc_to_enum_variant(cc: u8, scc: u8) -> cdd::CauseCodeChoice {
    match cc {
        0 => cdd::CauseCodeChoice::reserved0(cdd::SubCauseCodeType(scc)),
        1 => cdd::CauseCodeChoice::trafficCondition1(cdd::TrafficConditionSubCauseCode(scc)),
        2 => cdd::CauseCodeChoice::accident2(cdd::AccidentSubCauseCode(scc)),
        3 => cdd::CauseCodeChoice::roadworks3(cdd::RoadworksSubCauseCode(scc)),
        4 => cdd::CauseCodeChoice::reserved4(cdd::SubCauseCodeType(scc)),
        5 => cdd::CauseCodeChoice::impassability5(cdd::ImpassabilitySubCauseCode(scc)),
        6 => cdd::CauseCodeChoice::adverseWeatherCondition_Adhesion6(
            cdd::AdverseWeatherConditionAdhesionSubCauseCode(scc),
        ),
        7 => cdd::CauseCodeChoice::aquaplaning7(cdd::SubCauseCodeType(scc)),
        8 => cdd::CauseCodeChoice::reserved8(cdd::SubCauseCodeType(scc)),
        9 => cdd::CauseCodeChoice::hazardousLocation_SurfaceCondition9(
            cdd::HazardousLocationSurfaceConditionSubCauseCode(scc),
        ),
        10 => cdd::CauseCodeChoice::hazardousLocation_ObstacleOnTheRoad10(
            cdd::HazardousLocationObstacleOnTheRoadSubCauseCode(scc),
        ),
        11 => cdd::CauseCodeChoice::hazardousLocation_AnimalOnTheRoad11(
            cdd::HazardousLocationAnimalOnTheRoadSubCauseCode(scc),
        ),
        12 => cdd::CauseCodeChoice::humanPresenceOnTheRoad12(
            cdd::HumanPresenceOnTheRoadSubCauseCode(scc),
        ),
        13 => cdd::CauseCodeChoice::reserved13(cdd::SubCauseCodeType(scc)),
        14 => cdd::CauseCodeChoice::wrongWayDriving14(cdd::WrongWayDrivingSubCauseCode(scc)),
        15 => cdd::CauseCodeChoice::rescueAndRecoveryWorkInProgress15(
            cdd::RescueAndRecoveryWorkInProgressSubCauseCode(scc),
        ),
        16 => cdd::CauseCodeChoice::reserved16(cdd::SubCauseCodeType(scc)),
        17 => cdd::CauseCodeChoice::adverseWeatherCondition_ExtremeWeatherCondition17(
            cdd::AdverseWeatherConditionExtremeWeatherConditionSubCauseCode(scc),
        ),
        18 => cdd::CauseCodeChoice::adverseWeatherCondition_Visibility18(
            cdd::AdverseWeatherConditionVisibilitySubCauseCode(scc),
        ),
        19 => cdd::CauseCodeChoice::adverseWeatherCondition_Precipitation19(
            cdd::AdverseWeatherConditionPrecipitationSubCauseCode(scc),
        ),
        20 => cdd::CauseCodeChoice::violence20(cdd::SubCauseCodeType(scc)),
        21 => cdd::CauseCodeChoice::reserved21(cdd::SubCauseCodeType(scc)),
        22 => cdd::CauseCodeChoice::reserved22(cdd::SubCauseCodeType(scc)),
        23 => cdd::CauseCodeChoice::reserved23(cdd::SubCauseCodeType(scc)),
        24 => cdd::CauseCodeChoice::reserved24(cdd::SubCauseCodeType(scc)),
        25 => cdd::CauseCodeChoice::reserved25(cdd::SubCauseCodeType(scc)),
        26 => cdd::CauseCodeChoice::slowVehicle26(cdd::SlowVehicleSubCauseCode(scc)),
        27 => {
            cdd::CauseCodeChoice::dangerousEndOfQueue27(cdd::DangerousEndOfQueueSubCauseCode(scc))
        }
        28 => cdd::CauseCodeChoice::publicTransportVehicleApproaching28(cdd::SubCauseCodeType(scc)),
        29 => cdd::CauseCodeChoice::reserved29(cdd::SubCauseCodeType(scc)),
        30 => cdd::CauseCodeChoice::reserved30(cdd::SubCauseCodeType(scc)),
        31 => cdd::CauseCodeChoice::reserved31(cdd::SubCauseCodeType(scc)),
        32 => cdd::CauseCodeChoice::reserved32(cdd::SubCauseCodeType(scc)),
        33 => cdd::CauseCodeChoice::reserved33(cdd::SubCauseCodeType(scc)),
        34 => cdd::CauseCodeChoice::reserved34(cdd::SubCauseCodeType(scc)),
        35 => cdd::CauseCodeChoice::reserved35(cdd::SubCauseCodeType(scc)),
        36 => cdd::CauseCodeChoice::reserved36(cdd::SubCauseCodeType(scc)),
        37 => cdd::CauseCodeChoice::reserved37(cdd::SubCauseCodeType(scc)),
        38 => cdd::CauseCodeChoice::reserved38(cdd::SubCauseCodeType(scc)),
        39 => cdd::CauseCodeChoice::reserved39(cdd::SubCauseCodeType(scc)),
        40 => cdd::CauseCodeChoice::reserved40(cdd::SubCauseCodeType(scc)),
        41 => cdd::CauseCodeChoice::reserved41(cdd::SubCauseCodeType(scc)),
        42 => cdd::CauseCodeChoice::reserved42(cdd::SubCauseCodeType(scc)),
        43 => cdd::CauseCodeChoice::reserved43(cdd::SubCauseCodeType(scc)),
        44 => cdd::CauseCodeChoice::reserved44(cdd::SubCauseCodeType(scc)),
        45 => cdd::CauseCodeChoice::reserved45(cdd::SubCauseCodeType(scc)),
        46 => cdd::CauseCodeChoice::reserved46(cdd::SubCauseCodeType(scc)),
        47 => cdd::CauseCodeChoice::reserved47(cdd::SubCauseCodeType(scc)),
        48 => cdd::CauseCodeChoice::reserved48(cdd::SubCauseCodeType(scc)),
        49 => cdd::CauseCodeChoice::reserved49(cdd::SubCauseCodeType(scc)),
        50 => cdd::CauseCodeChoice::reserved50(cdd::SubCauseCodeType(scc)),
        51 => cdd::CauseCodeChoice::reserved51(cdd::SubCauseCodeType(scc)),
        52 => cdd::CauseCodeChoice::reserved52(cdd::SubCauseCodeType(scc)),
        53 => cdd::CauseCodeChoice::reserved53(cdd::SubCauseCodeType(scc)),
        54 => cdd::CauseCodeChoice::reserved54(cdd::SubCauseCodeType(scc)),
        55 => cdd::CauseCodeChoice::reserved55(cdd::SubCauseCodeType(scc)),
        56 => cdd::CauseCodeChoice::reserved56(cdd::SubCauseCodeType(scc)),
        57 => cdd::CauseCodeChoice::reserved57(cdd::SubCauseCodeType(scc)),
        58 => cdd::CauseCodeChoice::reserved58(cdd::SubCauseCodeType(scc)),
        59 => cdd::CauseCodeChoice::reserved59(cdd::SubCauseCodeType(scc)),
        60 => cdd::CauseCodeChoice::reserved60(cdd::SubCauseCodeType(scc)),
        61 => cdd::CauseCodeChoice::reserved61(cdd::SubCauseCodeType(scc)),
        62 => cdd::CauseCodeChoice::reserved62(cdd::SubCauseCodeType(scc)),
        63 => cdd::CauseCodeChoice::reserved63(cdd::SubCauseCodeType(scc)),
        64 => cdd::CauseCodeChoice::reserved64(cdd::SubCauseCodeType(scc)),
        65 => cdd::CauseCodeChoice::reserved65(cdd::SubCauseCodeType(scc)),
        66 => cdd::CauseCodeChoice::reserved66(cdd::SubCauseCodeType(scc)),
        67 => cdd::CauseCodeChoice::reserved67(cdd::SubCauseCodeType(scc)),
        68 => cdd::CauseCodeChoice::reserved68(cdd::SubCauseCodeType(scc)),
        69 => cdd::CauseCodeChoice::reserved69(cdd::SubCauseCodeType(scc)),
        70 => cdd::CauseCodeChoice::reserved70(cdd::SubCauseCodeType(scc)),
        71 => cdd::CauseCodeChoice::reserved71(cdd::SubCauseCodeType(scc)),
        72 => cdd::CauseCodeChoice::reserved72(cdd::SubCauseCodeType(scc)),
        73 => cdd::CauseCodeChoice::reserved73(cdd::SubCauseCodeType(scc)),
        74 => cdd::CauseCodeChoice::reserved74(cdd::SubCauseCodeType(scc)),
        75 => cdd::CauseCodeChoice::reserved75(cdd::SubCauseCodeType(scc)),
        76 => cdd::CauseCodeChoice::reserved76(cdd::SubCauseCodeType(scc)),
        77 => cdd::CauseCodeChoice::reserved77(cdd::SubCauseCodeType(scc)),
        78 => cdd::CauseCodeChoice::reserved78(cdd::SubCauseCodeType(scc)),
        79 => cdd::CauseCodeChoice::reserved79(cdd::SubCauseCodeType(scc)),
        80 => cdd::CauseCodeChoice::reserved80(cdd::SubCauseCodeType(scc)),
        81 => cdd::CauseCodeChoice::reserved81(cdd::SubCauseCodeType(scc)),
        82 => cdd::CauseCodeChoice::reserved82(cdd::SubCauseCodeType(scc)),
        83 => cdd::CauseCodeChoice::reserved83(cdd::SubCauseCodeType(scc)),
        84 => cdd::CauseCodeChoice::reserved84(cdd::SubCauseCodeType(scc)),
        85 => cdd::CauseCodeChoice::reserved85(cdd::SubCauseCodeType(scc)),
        86 => cdd::CauseCodeChoice::reserved86(cdd::SubCauseCodeType(scc)),
        87 => cdd::CauseCodeChoice::reserved87(cdd::SubCauseCodeType(scc)),
        88 => cdd::CauseCodeChoice::reserved88(cdd::SubCauseCodeType(scc)),
        89 => cdd::CauseCodeChoice::reserved89(cdd::SubCauseCodeType(scc)),
        90 => cdd::CauseCodeChoice::reserved90(cdd::SubCauseCodeType(scc)),
        91 => cdd::CauseCodeChoice::vehicleBreakdown91(cdd::VehicleBreakdownSubCauseCode(scc)),
        92 => cdd::CauseCodeChoice::postCrash92(cdd::PostCrashSubCauseCode(scc)),
        93 => cdd::CauseCodeChoice::humanProblem93(cdd::HumanProblemSubCauseCode(scc)),
        94 => cdd::CauseCodeChoice::stationaryVehicle94(cdd::StationaryVehicleSubCauseCode(scc)),
        95 => cdd::CauseCodeChoice::emergencyVehicleApproaching95(
            cdd::EmergencyVehicleApproachingSubCauseCode(scc),
        ),
        96 => cdd::CauseCodeChoice::hazardousLocation_DangerousCurve96(
            cdd::HazardousLocationDangerousCurveSubCauseCode(scc),
        ),
        97 => cdd::CauseCodeChoice::collisionRisk97(cdd::CollisionRiskSubCauseCode(scc)),
        98 => cdd::CauseCodeChoice::signalViolation98(cdd::SignalViolationSubCauseCode(scc)),
        99 => cdd::CauseCodeChoice::dangerousSituation99(cdd::DangerousSituationSubCauseCode(scc)),
        100 => cdd::CauseCodeChoice::railwayLevelCrossing100(
            cdd::RailwayLevelCrossingSubCauseCode(scc),
        ),
        101 => cdd::CauseCodeChoice::reserved101(cdd::SubCauseCodeType(scc)),
        102 => cdd::CauseCodeChoice::reserved102(cdd::SubCauseCodeType(scc)),
        103 => cdd::CauseCodeChoice::reserved103(cdd::SubCauseCodeType(scc)),
        104 => cdd::CauseCodeChoice::reserved104(cdd::SubCauseCodeType(scc)),
        105 => cdd::CauseCodeChoice::reserved105(cdd::SubCauseCodeType(scc)),
        106 => cdd::CauseCodeChoice::reserved106(cdd::SubCauseCodeType(scc)),
        107 => cdd::CauseCodeChoice::reserved107(cdd::SubCauseCodeType(scc)),
        108 => cdd::CauseCodeChoice::reserved108(cdd::SubCauseCodeType(scc)),
        109 => cdd::CauseCodeChoice::reserved109(cdd::SubCauseCodeType(scc)),
        110 => cdd::CauseCodeChoice::reserved110(cdd::SubCauseCodeType(scc)),
        111 => cdd::CauseCodeChoice::reserved111(cdd::SubCauseCodeType(scc)),
        112 => cdd::CauseCodeChoice::reserved112(cdd::SubCauseCodeType(scc)),
        113 => cdd::CauseCodeChoice::reserved113(cdd::SubCauseCodeType(scc)),
        114 => cdd::CauseCodeChoice::reserved114(cdd::SubCauseCodeType(scc)),
        115 => cdd::CauseCodeChoice::reserved115(cdd::SubCauseCodeType(scc)),
        116 => cdd::CauseCodeChoice::reserved116(cdd::SubCauseCodeType(scc)),
        117 => cdd::CauseCodeChoice::reserved117(cdd::SubCauseCodeType(scc)),
        118 => cdd::CauseCodeChoice::reserved118(cdd::SubCauseCodeType(scc)),
        119 => cdd::CauseCodeChoice::reserved119(cdd::SubCauseCodeType(scc)),
        120 => cdd::CauseCodeChoice::reserved120(cdd::SubCauseCodeType(scc)),
        121 => cdd::CauseCodeChoice::reserved121(cdd::SubCauseCodeType(scc)),
        122 => cdd::CauseCodeChoice::reserved122(cdd::SubCauseCodeType(scc)),
        123 => cdd::CauseCodeChoice::reserved123(cdd::SubCauseCodeType(scc)),
        124 => cdd::CauseCodeChoice::reserved124(cdd::SubCauseCodeType(scc)),
        125 => cdd::CauseCodeChoice::reserved125(cdd::SubCauseCodeType(scc)),
        126 => cdd::CauseCodeChoice::reserved126(cdd::SubCauseCodeType(scc)),
        127 => cdd::CauseCodeChoice::reserved127(cdd::SubCauseCodeType(scc)),
        128 => cdd::CauseCodeChoice::reserved128(cdd::SubCauseCodeType(scc)),
        129 => cdd::CauseCodeChoice::reserved129(cdd::SubCauseCodeType(scc)),
        130 => cdd::CauseCodeChoice::reserved130(cdd::SubCauseCodeType(scc)),
        131 => cdd::CauseCodeChoice::reserved131(cdd::SubCauseCodeType(scc)),
        132 => cdd::CauseCodeChoice::reserved132(cdd::SubCauseCodeType(scc)),
        133 => cdd::CauseCodeChoice::reserved133(cdd::SubCauseCodeType(scc)),
        134 => cdd::CauseCodeChoice::reserved134(cdd::SubCauseCodeType(scc)),
        135 => cdd::CauseCodeChoice::reserved135(cdd::SubCauseCodeType(scc)),
        136 => cdd::CauseCodeChoice::reserved136(cdd::SubCauseCodeType(scc)),
        137 => cdd::CauseCodeChoice::reserved137(cdd::SubCauseCodeType(scc)),
        138 => cdd::CauseCodeChoice::reserved138(cdd::SubCauseCodeType(scc)),
        139 => cdd::CauseCodeChoice::reserved139(cdd::SubCauseCodeType(scc)),
        140 => cdd::CauseCodeChoice::reserved140(cdd::SubCauseCodeType(scc)),
        141 => cdd::CauseCodeChoice::reserved141(cdd::SubCauseCodeType(scc)),
        142 => cdd::CauseCodeChoice::reserved142(cdd::SubCauseCodeType(scc)),
        143 => cdd::CauseCodeChoice::reserved143(cdd::SubCauseCodeType(scc)),
        144 => cdd::CauseCodeChoice::reserved144(cdd::SubCauseCodeType(scc)),
        145 => cdd::CauseCodeChoice::reserved145(cdd::SubCauseCodeType(scc)),
        146 => cdd::CauseCodeChoice::reserved146(cdd::SubCauseCodeType(scc)),
        147 => cdd::CauseCodeChoice::reserved147(cdd::SubCauseCodeType(scc)),
        148 => cdd::CauseCodeChoice::reserved148(cdd::SubCauseCodeType(scc)),
        149 => cdd::CauseCodeChoice::reserved149(cdd::SubCauseCodeType(scc)),
        150 => cdd::CauseCodeChoice::reserved150(cdd::SubCauseCodeType(scc)),
        151 => cdd::CauseCodeChoice::reserved151(cdd::SubCauseCodeType(scc)),
        152 => cdd::CauseCodeChoice::reserved152(cdd::SubCauseCodeType(scc)),
        153 => cdd::CauseCodeChoice::reserved153(cdd::SubCauseCodeType(scc)),
        154 => cdd::CauseCodeChoice::reserved154(cdd::SubCauseCodeType(scc)),
        155 => cdd::CauseCodeChoice::reserved155(cdd::SubCauseCodeType(scc)),
        156 => cdd::CauseCodeChoice::reserved156(cdd::SubCauseCodeType(scc)),
        157 => cdd::CauseCodeChoice::reserved157(cdd::SubCauseCodeType(scc)),
        158 => cdd::CauseCodeChoice::reserved158(cdd::SubCauseCodeType(scc)),
        159 => cdd::CauseCodeChoice::reserved159(cdd::SubCauseCodeType(scc)),
        160 => cdd::CauseCodeChoice::reserved160(cdd::SubCauseCodeType(scc)),
        161 => cdd::CauseCodeChoice::reserved161(cdd::SubCauseCodeType(scc)),
        162 => cdd::CauseCodeChoice::reserved162(cdd::SubCauseCodeType(scc)),
        163 => cdd::CauseCodeChoice::reserved163(cdd::SubCauseCodeType(scc)),
        164 => cdd::CauseCodeChoice::reserved164(cdd::SubCauseCodeType(scc)),
        165 => cdd::CauseCodeChoice::reserved165(cdd::SubCauseCodeType(scc)),
        166 => cdd::CauseCodeChoice::reserved166(cdd::SubCauseCodeType(scc)),
        167 => cdd::CauseCodeChoice::reserved167(cdd::SubCauseCodeType(scc)),
        168 => cdd::CauseCodeChoice::reserved168(cdd::SubCauseCodeType(scc)),
        169 => cdd::CauseCodeChoice::reserved169(cdd::SubCauseCodeType(scc)),
        170 => cdd::CauseCodeChoice::reserved170(cdd::SubCauseCodeType(scc)),
        171 => cdd::CauseCodeChoice::reserved171(cdd::SubCauseCodeType(scc)),
        172 => cdd::CauseCodeChoice::reserved172(cdd::SubCauseCodeType(scc)),
        173 => cdd::CauseCodeChoice::reserved173(cdd::SubCauseCodeType(scc)),
        174 => cdd::CauseCodeChoice::reserved174(cdd::SubCauseCodeType(scc)),
        175 => cdd::CauseCodeChoice::reserved175(cdd::SubCauseCodeType(scc)),
        176 => cdd::CauseCodeChoice::reserved176(cdd::SubCauseCodeType(scc)),
        177 => cdd::CauseCodeChoice::reserved177(cdd::SubCauseCodeType(scc)),
        178 => cdd::CauseCodeChoice::reserved178(cdd::SubCauseCodeType(scc)),
        179 => cdd::CauseCodeChoice::reserved179(cdd::SubCauseCodeType(scc)),
        180 => cdd::CauseCodeChoice::reserved180(cdd::SubCauseCodeType(scc)),
        181 => cdd::CauseCodeChoice::reserved181(cdd::SubCauseCodeType(scc)),
        182 => cdd::CauseCodeChoice::reserved182(cdd::SubCauseCodeType(scc)),
        183 => cdd::CauseCodeChoice::reserved183(cdd::SubCauseCodeType(scc)),
        184 => cdd::CauseCodeChoice::reserved184(cdd::SubCauseCodeType(scc)),
        185 => cdd::CauseCodeChoice::reserved185(cdd::SubCauseCodeType(scc)),
        186 => cdd::CauseCodeChoice::reserved186(cdd::SubCauseCodeType(scc)),
        187 => cdd::CauseCodeChoice::reserved187(cdd::SubCauseCodeType(scc)),
        188 => cdd::CauseCodeChoice::reserved188(cdd::SubCauseCodeType(scc)),
        189 => cdd::CauseCodeChoice::reserved189(cdd::SubCauseCodeType(scc)),
        190 => cdd::CauseCodeChoice::reserved190(cdd::SubCauseCodeType(scc)),
        191 => cdd::CauseCodeChoice::reserved191(cdd::SubCauseCodeType(scc)),
        192 => cdd::CauseCodeChoice::reserved192(cdd::SubCauseCodeType(scc)),
        193 => cdd::CauseCodeChoice::reserved193(cdd::SubCauseCodeType(scc)),
        194 => cdd::CauseCodeChoice::reserved194(cdd::SubCauseCodeType(scc)),
        195 => cdd::CauseCodeChoice::reserved195(cdd::SubCauseCodeType(scc)),
        196 => cdd::CauseCodeChoice::reserved196(cdd::SubCauseCodeType(scc)),
        197 => cdd::CauseCodeChoice::reserved197(cdd::SubCauseCodeType(scc)),
        198 => cdd::CauseCodeChoice::reserved198(cdd::SubCauseCodeType(scc)),
        199 => cdd::CauseCodeChoice::reserved199(cdd::SubCauseCodeType(scc)),
        200 => cdd::CauseCodeChoice::reserved200(cdd::SubCauseCodeType(scc)),
        201 => cdd::CauseCodeChoice::reserved201(cdd::SubCauseCodeType(scc)),
        202 => cdd::CauseCodeChoice::reserved202(cdd::SubCauseCodeType(scc)),
        203 => cdd::CauseCodeChoice::reserved203(cdd::SubCauseCodeType(scc)),
        204 => cdd::CauseCodeChoice::reserved204(cdd::SubCauseCodeType(scc)),
        205 => cdd::CauseCodeChoice::reserved205(cdd::SubCauseCodeType(scc)),
        206 => cdd::CauseCodeChoice::reserved206(cdd::SubCauseCodeType(scc)),
        207 => cdd::CauseCodeChoice::reserved207(cdd::SubCauseCodeType(scc)),
        208 => cdd::CauseCodeChoice::reserved208(cdd::SubCauseCodeType(scc)),
        209 => cdd::CauseCodeChoice::reserved209(cdd::SubCauseCodeType(scc)),
        210 => cdd::CauseCodeChoice::reserved210(cdd::SubCauseCodeType(scc)),
        211 => cdd::CauseCodeChoice::reserved211(cdd::SubCauseCodeType(scc)),
        212 => cdd::CauseCodeChoice::reserved212(cdd::SubCauseCodeType(scc)),
        213 => cdd::CauseCodeChoice::reserved213(cdd::SubCauseCodeType(scc)),
        214 => cdd::CauseCodeChoice::reserved214(cdd::SubCauseCodeType(scc)),
        215 => cdd::CauseCodeChoice::reserved215(cdd::SubCauseCodeType(scc)),
        216 => cdd::CauseCodeChoice::reserved216(cdd::SubCauseCodeType(scc)),
        217 => cdd::CauseCodeChoice::reserved217(cdd::SubCauseCodeType(scc)),
        218 => cdd::CauseCodeChoice::reserved218(cdd::SubCauseCodeType(scc)),
        219 => cdd::CauseCodeChoice::reserved219(cdd::SubCauseCodeType(scc)),
        220 => cdd::CauseCodeChoice::reserved220(cdd::SubCauseCodeType(scc)),
        221 => cdd::CauseCodeChoice::reserved221(cdd::SubCauseCodeType(scc)),
        222 => cdd::CauseCodeChoice::reserved222(cdd::SubCauseCodeType(scc)),
        223 => cdd::CauseCodeChoice::reserved223(cdd::SubCauseCodeType(scc)),
        224 => cdd::CauseCodeChoice::reserved224(cdd::SubCauseCodeType(scc)),
        225 => cdd::CauseCodeChoice::reserved225(cdd::SubCauseCodeType(scc)),
        226 => cdd::CauseCodeChoice::reserved226(cdd::SubCauseCodeType(scc)),
        227 => cdd::CauseCodeChoice::reserved227(cdd::SubCauseCodeType(scc)),
        228 => cdd::CauseCodeChoice::reserved228(cdd::SubCauseCodeType(scc)),
        229 => cdd::CauseCodeChoice::reserved229(cdd::SubCauseCodeType(scc)),
        230 => cdd::CauseCodeChoice::reserved230(cdd::SubCauseCodeType(scc)),
        231 => cdd::CauseCodeChoice::reserved231(cdd::SubCauseCodeType(scc)),
        232 => cdd::CauseCodeChoice::reserved232(cdd::SubCauseCodeType(scc)),
        233 => cdd::CauseCodeChoice::reserved233(cdd::SubCauseCodeType(scc)),
        234 => cdd::CauseCodeChoice::reserved234(cdd::SubCauseCodeType(scc)),
        235 => cdd::CauseCodeChoice::reserved235(cdd::SubCauseCodeType(scc)),
        236 => cdd::CauseCodeChoice::reserved236(cdd::SubCauseCodeType(scc)),
        237 => cdd::CauseCodeChoice::reserved237(cdd::SubCauseCodeType(scc)),
        238 => cdd::CauseCodeChoice::reserved238(cdd::SubCauseCodeType(scc)),
        239 => cdd::CauseCodeChoice::reserved239(cdd::SubCauseCodeType(scc)),
        240 => cdd::CauseCodeChoice::reserved240(cdd::SubCauseCodeType(scc)),
        241 => cdd::CauseCodeChoice::reserved241(cdd::SubCauseCodeType(scc)),
        242 => cdd::CauseCodeChoice::reserved242(cdd::SubCauseCodeType(scc)),
        243 => cdd::CauseCodeChoice::reserved243(cdd::SubCauseCodeType(scc)),
        244 => cdd::CauseCodeChoice::reserved244(cdd::SubCauseCodeType(scc)),
        245 => cdd::CauseCodeChoice::reserved245(cdd::SubCauseCodeType(scc)),
        246 => cdd::CauseCodeChoice::reserved246(cdd::SubCauseCodeType(scc)),
        247 => cdd::CauseCodeChoice::reserved247(cdd::SubCauseCodeType(scc)),
        248 => cdd::CauseCodeChoice::reserved248(cdd::SubCauseCodeType(scc)),
        249 => cdd::CauseCodeChoice::reserved249(cdd::SubCauseCodeType(scc)),
        250 => cdd::CauseCodeChoice::reserved250(cdd::SubCauseCodeType(scc)),
        251 => cdd::CauseCodeChoice::reserved251(cdd::SubCauseCodeType(scc)),
        252 => cdd::CauseCodeChoice::reserved252(cdd::SubCauseCodeType(scc)),
        253 => cdd::CauseCodeChoice::reserved253(cdd::SubCauseCodeType(scc)),
        254 => cdd::CauseCodeChoice::reserved254(cdd::SubCauseCodeType(scc)),
        255 => cdd::CauseCodeChoice::reserved255(cdd::SubCauseCodeType(scc)),
    }
}
