use std::io;
use std::os::fd::AsRawFd;
use std::rc::Rc;

use clap::Parser;
use log::{/* debug,*/ error, info, trace};

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use veloce::iface::{Config, CongestionControl, Interface, SocketSet};
use veloce::network::{GnAddrConfigMode, GnCore, GnCoreGonfig};
use veloce::phy::{Medium, RawSocket as VeloceRawSocket};
use veloce::socket;
use veloce::socket::denm::EventParameters;
use veloce::time::Instant;
use veloce::types::Pseudonym;
use veloce::utils;
use veloce::wire::{EthernetAddress, StationType};
use veloce_gnss::Gpsd;
use veloce_ipc::denm::{ApiResult, ApiResultCode, Handle as ApiHandle};
use veloce_ipc::prelude::zmq;
use veloce_ipc::{IpcEvent, IpcEventType};
use veloce_ipc::{ZmqPublisher, ZmqReplier};

#[derive(Parser, Default, Debug)]
struct Arguments {
    dev: String,
    log_level: String,
}

const DEV_TOKEN: Token = Token(0);
const GPSD_TOKEN: Token = Token(1);
const IPC_REP_TOKEN: Token = Token(2);

fn main() {
    let args = Arguments::parse();
    utils::setup_logging(args.log_level.as_str());

    // Configure IPC
    let ipc_pub = Rc::new(ZmqPublisher::new("127.0.0.1:45556".to_string()).unwrap());
    let ipc_rep = Rc::new(ZmqReplier::new("127.0.0.1:45557".to_string()).unwrap());

    let ipc_rep_fd = ipc_rep.raw_fd().unwrap();
    let mut ipc_rep_src = SourceFd(&ipc_rep_fd);

    // Mio setup
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);

    let ll_addr = EthernetAddress([0x04, 0xe5, 0x48, 0xfa, 0xde, 0xca]);

    // Configure Raw socket device
    let mut device = RawSocket::new(args.dev.as_str(), Medium::Ethernet).unwrap();

    // Register it into the polling registry
    poll.registry()
        .register(&mut device, DEV_TOKEN, Interest::READABLE)
        .unwrap();

    // Register IPC rep.
    poll.registry()
        .register(&mut ipc_rep_src, IPC_REP_TOKEN, Interest::READABLE)
        .unwrap();

    // Build GnCore
    let mut router_config = GnCoreGonfig::new(StationType::PassengerCar, Pseudonym(0xabcd));
    router_config.random_seed = 0xfadecafedeadbeef;
    router_config.addr_config_mode = GnAddrConfigMode::Managed(ll_addr);
    let mut router = GnCore::new(router_config, Instant::now());

    // Configure interface
    let config = Config::new(ll_addr.into());
    let mut iface = Interface::new(config, device.inner_mut());
    iface.set_congestion_control(CongestionControl::LimericDualAlpha);

    let mut sockets = SocketSet::new(vec![]);

    // Create CAM socket
    let mut cam_socket = socket::cam::Socket::new();

    // Register the tx callback.
    let ipc_tx = ipc_pub.clone();
    cam_socket.register_send_callback(move |uper, _| {
        let evt = IpcEvent::new(IpcEventType::CamTx(uper.to_vec()));
        let bytes = evt.serialize_to_vec();
        ipc_tx.send(&bytes).unwrap();
    });

    // Register the rx callback.
    let ipc_rx = ipc_pub.clone();
    cam_socket.register_recv_callback(move |uper, _| {
        let evt = IpcEvent::new(IpcEventType::CamRx(uper.to_vec()));
        let bytes = evt.serialize_to_vec();
        ipc_rx.send(&bytes).unwrap();
    });

    // Add it to a SocketSet
    let _cam_handle: veloce::iface::SocketHandle = sockets.add(cam_socket);

    // Create DENM socket
    let denm_socket = socket::denm::Socket::new(vec![], vec![]);
    let denm_handle: veloce::iface::SocketHandle = sockets.add(denm_socket);

    // Create GPSD client
    let mut gpsd = Gpsd::new(
        "10.29.2.229:2947".to_string(),
        poll.registry().try_clone().unwrap(),
        GPSD_TOKEN,
    )
    .expect("malformed GPSD server address");

    loop {
        // Update timestamp.
        let now = Instant::now();
        router.set_timestamp(now);

        // For DENM IPC.
        let mut event_params = None;

        // Process each event.
        for event in events.iter() {
            match event.token() {
                GPSD_TOKEN => {
                    gpsd.ready(event);
                    gpsd.fetch_position()
                        .try_into()
                        .map(|fix| {
                            router.set_position(fix);
                        })
                        .ok();
                }
                DEV_TOKEN => {
                    //debug!("Rx available");
                }
                IPC_REP_TOKEN => {
                    info!("IPC_REP_TOKEN");
                    loop {
                        match ipc_rep.events() {
                            Ok(evts) if evts.contains(zmq::POLLIN) => {
                                info!("ZMQ readable");
                                match ipc_rep.recv() {
                                    Ok(data) => match IpcEvent::deserialize(&data) {
                                        Ok(evt) => {
                                            if let Some(evt_type) = evt.event_type {
                                                match evt_type {
                                                    IpcEventType::DenmTrigger(trigger) => {
                                                        if let Some(params) = trigger.parameters {
                                                            if let Ok(params) =
                                                                EventParameters::try_from(params)
                                                            {
                                                                event_params =
                                                                    Some((trigger.id, params));
                                                            } else {
                                                                error!(
                                                                    "EventParameters is malformed"
                                                                );
                                                            }
                                                        }
                                                    }
                                                    _ => error!("Unsupported"),
                                                }
                                            } else {
                                                error!("IPC data malformed.");
                                            }
                                        }
                                        Err(err) => error!("Cannot deserialize IPC event: {}", err),
                                    },
                                    Err(e) => error!("Cannot recv: {}", e),
                                }
                            }
                            Ok(_) => break,
                            Err(err) => error!("Cannot query ZMQ events: {}", err),
                        }
                    }
                }
                // We don't expect any events with tokens other than those we provided.
                _ => unreachable!(),
            }
        }

        //trace!("gpsd poll");
        let _ = gpsd.poll();

        // trace!("iface poll");
        iface.poll(&mut router, device.inner_mut(), &mut sockets);

        let denm_socket = sockets.get_mut::<socket::denm::Socket>(denm_handle);
        denm_socket.poll(now);

        if let Some((id_req, p)) = event_params {
            match denm_socket.trigger(&router, p) {
                Ok(handle) => {
                    info!("Triggered DENM: {:?}", handle);
                    let res = ApiResult {
                        id: id_req,
                        result: ApiResultCode::Ok.into(),
                        message: None,
                        handle: Some(handle.into()),
                    };
                    let evt = IpcEvent::new(IpcEventType::DenmResult(res));
                    let bytes = evt.serialize_to_vec();
                    ipc_rep.send(&bytes).unwrap();
                }
                Err(err) => {
                    error!("Cannot trigger DENM: {}", err);
                    let (result, message) = match err {
                        socket::denm::ApiError::NoFreeSlot => (ApiResultCode::NoFreeSlot, None),
                        socket::denm::ApiError::Expired => (ApiResultCode::Expired, None),
                        socket::denm::ApiError::InvalidDetectionTime => {
                            (ApiResultCode::InvalidDetectionTime, None)
                        }
                        socket::denm::ApiError::InvalidValidityDuration => {
                            (ApiResultCode::InvalidValidityDuration, None)
                        }
                        socket::denm::ApiError::InvalidRepetitionDuration => {
                            (ApiResultCode::InvalidRepetitionDuration, None)
                        }
                        socket::denm::ApiError::InvalidRepetitionInterval => {
                            (ApiResultCode::InvalidRepetitionInterval, None)
                        }
                        socket::denm::ApiError::InvalidKeepAliveTransmissionInterval => {
                            (ApiResultCode::InvalidKeepAliveTransmissionInterval, None)
                        }
                        socket::denm::ApiError::InvalidContent(s) => {
                            (ApiResultCode::InvalidContent, Some(s.to_string()))
                        }
                        socket::denm::ApiError::NotFound => (ApiResultCode::NotFound, None),
                        socket::denm::ApiError::ActionIdInOrigMsgtable => {
                            (ApiResultCode::ActionIdInOrigMsgtable, None)
                        }
                    };
                    let res = ApiResult {
                        id: id_req,
                        result: result.into(),
                        message,
                        handle: None,
                    };
                    let evt = IpcEvent::new(IpcEventType::DenmResult(res));
                    let bytes = evt.serialize_to_vec();
                    ipc_rep.send(&bytes).unwrap();
                }
            }
        }

        let iface_timeout = iface.poll_delay(now, &sockets);

        // Poll Mio for events, blocking until we get an event or a timeout.
        poll.poll(&mut events, iface_timeout.map(|t| t.into()))
            .unwrap();
    }
}

pub struct RawSocket {
    inner: VeloceRawSocket,
}

impl RawSocket {
    pub fn new(name: &str, medium: Medium) -> io::Result<RawSocket> {
        Ok(RawSocket {
            inner: VeloceRawSocket::new(name, medium)?,
        })
    }

    pub fn inner_mut(&mut self) -> &mut VeloceRawSocket {
        &mut self.inner
    }
}

impl Source for RawSocket {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        SourceFd(&self.inner.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        SourceFd(&self.inner.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        SourceFd(&self.inner.as_raw_fd()).deregister(registry)
    }
}
