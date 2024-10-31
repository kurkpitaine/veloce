use std::io;
use std::os::fd::AsRawFd;
use std::rc::Rc;

#[cfg(not(debug_assertions))]
use std::fs;
#[cfg(debug_assertions)]
use std::path::PathBuf;

use clap::Parser;
use log::error;

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use veloce::iface::{Config, CongestionControl, Interface, SocketSet};
use veloce::ipc::IpcDispatcher;
use veloce::network::core::SecurityConfig;
use veloce::network::{GnCore, GnCoreGonfig};
use veloce::phy::Device;
use veloce::security::{SecurityBackend, TrustChain};
use veloce::socket;
use veloce::time::Instant;
use veloce::types::{Power, Pseudonym};
use veloce::utils;
use veloce::wire::{EthernetAddress, StationType};
use veloce_gnss::Gpsd;
use veloce_ipc::prelude::zmq;
use veloce_ipc::{IpcEvent, IpcEventType};
use veloce_ipc::{ZmqPublisher, ZmqReplier};
use veloce_nxp_phy::{NxpChannel, NxpConfig, NxpLlcDevice, NxpRadio, NxpWirelessChannel};

use veloce_asn1::{defs::etsi_103097_v211::etsi_ts103097_module, prelude::rasn};

use veloce::security::{
    backend::openssl::{OpensslBackend, OpensslBackendConfig},
    certificate::{
        AuthorizationAuthorityCertificate, AuthorizationTicketCertificate, ExplicitCertificate,
        RootCertificate,
    },
};

#[derive(Parser, Default, Debug)]
struct Arguments {
    log_level: String,
}

const RX_TOKEN: Token = Token(0);
const GPSD_TOKEN: Token = Token(10);
const IPC_REP_TOKEN: Token = Token(11);

fn main() {
    let args = Arguments::parse();
    utils::setup_logging(args.log_level.as_str());

    // Configure IPC
    let ipc_pub = Rc::new(ZmqPublisher::new("0.0.0.0:45556".to_string()).unwrap());
    let ipc_rep = Rc::new(ZmqReplier::new("0.0.0.0:45557".to_string()).unwrap());

    let ipc_rep_fd = ipc_rep.raw_fd().unwrap();
    let mut ipc_rep_src = SourceFd(&ipc_rep_fd);

    // Mio setup
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);

    let ll_addr = EthernetAddress([0x04, 0xe5, 0x48, 0xfa, 0xde, 0xca]);

    let config = NxpConfig::new(
        NxpRadio::A,
        NxpChannel::Zero,
        NxpWirelessChannel::Chan180,
        Power::from_dbm_i32(23),
        ll_addr,
    );
    // Configure NXP device
    let mut device = RawSocket::new("cw-llc0", config).unwrap();
    device
        .inner_mut()
        .commit_config()
        .expect("Cannot configure device");

    // Register it into the polling registry
    poll.registry()
        .register(&mut device, RX_TOKEN, Interest::READABLE)
        .unwrap();

    // Register IPC rep.
    poll.registry()
        .register(&mut ipc_rep_src, IPC_REP_TOKEN, Interest::READABLE)
        .unwrap();

    // Load certificates.
    let backend = openssl_backend();
    let raw_root_cert = load_root_cert();
    let raw_aa_cert = load_aa_cert();
    let raw_at_cert = load_at_cert();

    let root_cert = RootCertificate::from_etsi_cert(raw_root_cert.0, &backend).unwrap();
    let aa_cert =
        AuthorizationAuthorityCertificate::from_etsi_cert(raw_aa_cert.0, &backend).unwrap();
    let at_cert = AuthorizationTicketCertificate::from_etsi_cert(raw_at_cert.0, &backend).unwrap();

    let mut own_chain = TrustChain::new(root_cert.into_with_hash_container(&backend).unwrap());
    own_chain.set_aa_cert(aa_cert.into_with_hash_container(&backend).unwrap());
    own_chain.set_at_cert(at_cert.into_with_hash_container(&backend).unwrap());

    let security_config = SecurityConfig {
        security_backend: SecurityBackend::Openssl(backend),
        own_trust_chain: own_chain,
    };

    // Build GnCore
    let mut router_config = GnCoreGonfig::new(StationType::PassengerCar, Pseudonym(0xabcd));
    router_config.random_seed = 0xfadecafedeadbeef;
    router_config.security = Some(security_config);
    let mut router = GnCore::new(router_config, Instant::now());
    let ll_addr = router.address().mac_addr();
    device.inner_mut().set_filter_addr(Some(ll_addr.into()));

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
        "127.0.0.1:2947".to_string(),
        poll.registry().try_clone().unwrap(),
        GPSD_TOKEN,
    )
    .expect("malformed GPSD server address");

    // IPC dispatcher.
    let ipc_dispatcher = IpcDispatcher {
        denm_socket_handle: denm_handle,
    };

    loop {
        // Update timestamp.
        let now = Instant::now();
        router.set_timestamp(now);

        // Process each event.
        for event in events.iter() {
            match event.token() {
                RX_TOKEN => {
                    iface.poll_ingress_single(&mut router, device.inner_mut(), &mut sockets);
                }
                GPSD_TOKEN => {
                    gpsd.ready(event).then(|| {
                        gpsd.fetch_position()
                            .try_into()
                            .map(|fix| {
                                router.set_position(fix).ok();
                            })
                            .ok();
                    });
                }
                IPC_REP_TOKEN => loop {
                    match ipc_rep.events() {
                        Ok(evts) if evts.contains(zmq::POLLIN) => match ipc_rep.recv() {
                            Ok(data) => match IpcEvent::deserialize(&data) {
                                Ok(evt) => {
                                    let Ok(resp) =
                                        ipc_dispatcher.dispatch(evt, &router, &mut sockets)
                                    else {
                                        error!("IPC data malformed.");
                                        continue;
                                    };

                                    if let Some(resp) = resp {
                                        let serialized = resp.serialize_to_vec();
                                        ipc_rep.send(&serialized).unwrap();
                                    }
                                }
                                Err(err) => error!("Cannot deserialize IPC event: {}", err),
                            },
                            Err(e) => error!("Cannot recv: {}", e),
                        },
                        Ok(_) => break,
                        Err(err) => error!("Cannot query ZMQ events: {}", err),
                    }
                },
                // We don't expect any events with tokens other than those we provided.
                _ => unreachable!(),
            }
        }

        // Poll the Gnss source.
        gpsd.poll().ok();

        // Poll the stack for egress or internal processing.
        iface.poll(&mut router, device.inner_mut(), &mut sockets);

        let denm_socket = sockets.get_mut::<socket::denm::Socket>(denm_handle);
        denm_socket.poll(now);

        let iface_timeout = iface.poll_delay(now, &sockets);

        // Poll Mio for events, blocking until we get an event or a timeout.
        loop {
            match poll.poll(&mut events, iface_timeout.map(|t| t.into())) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("Failed to poll: {}", e);
                    break;
                }
            }
        }
    }
}

pub struct RawSocket {
    inner: NxpLlcDevice,
}

impl RawSocket {
    pub fn new(name: &str, config: NxpConfig) -> io::Result<RawSocket> {
        Ok(RawSocket {
            inner: NxpLlcDevice::new(name, config)?,
        })
    }

    pub fn inner_mut(&mut self) -> &mut NxpLlcDevice {
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

pub fn openssl_backend() -> OpensslBackend {
    #[cfg(debug_assertions)]
    let key_path = {
        let mut key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        key_path.push("src/assets/AT.pem");
        std::fs::canonicalize(key_path)
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap()
    };

    #[cfg(not(debug_assertions))]
    let key_path = "assets/AT.pem".to_string();

    let config = OpensslBackendConfig {
        canonical_key_path: String::new(),
        canonical_key_passwd: String::new().into(),
        signing_cert_secret_key_path: Some(key_path),
        signing_cert_secret_key_passwd: Some("test1234".to_string().into()),
    };

    OpensslBackend::new(config).unwrap()
}

pub fn load_root_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    #[cfg(debug_assertions)]
    let input_root = include_bytes!("assets/RCA.cert");
    #[cfg(not(debug_assertions))]
    let input_root = &fs::read("assets/RCA.cert").unwrap();

    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_root).unwrap()
}

pub fn load_ea_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    #[cfg(debug_assertions)]
    let input_ea = include_bytes!("assets/EA.cert");
    #[cfg(not(debug_assertions))]
    let input_ea = &fs::read("assets/EA.cert").unwrap();

    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_ea).unwrap()
}

pub fn load_aa_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    #[cfg(debug_assertions)]
    let input_aa = include_bytes!("assets/AA.cert");
    #[cfg(not(debug_assertions))]
    let input_aa = &fs::read("assets/AA.cert").unwrap();

    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_aa).unwrap()
}

pub fn load_at_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    #[cfg(debug_assertions)]
    let input_at = include_bytes!("assets/AT.cert");
    #[cfg(not(debug_assertions))]
    let input_at = &fs::read("assets/AT.cert").unwrap();
    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_at).unwrap()
}

pub fn load_tlm_cert() -> etsi_ts103097_module::EtsiTs103097Certificate {
    #[cfg(debug_assertions)]
    let input_tlm = include_bytes!("assets/TLM.cert");
    #[cfg(not(debug_assertions))]
    let input_tlm = &fs::read("assets/TLM.cert").unwrap();
    rasn::coer::decode::<etsi_ts103097_module::EtsiTs103097Certificate>(input_tlm).unwrap()
}
