use core::fmt;
use std::{io, rc::Rc};

use log::{debug, error};
use mio::{Events, Interest, Poll, Registry, Token, event::Source};
use veloce::{
    iface::{Config as RouterIfaceConfig, CongestionControl, Interface, SocketHandle, SocketSet},
    ipc::IpcDispatcher,
    network::{
        GnAddrConfigMode, GnCore, GnCoreGonfig, GnCorePollEvent,
        core::SecurityConfig as RouterSecurityConfig,
    },
    phy::{Device, Medium},
    security::{
        DirectoryStorage, SecurityServicePollEvent, SecurityStorageMetadata, storage::StorageTrait,
    },
    socket,
    time::Instant,
    types::Pseudonym,
};
use veloce_ipc::{IpcEvent, IpcEventType, prelude::zmq};

use crate::{
    config::Config,
    device::AnyDevice,
    gnss::{GnssSource, GnssSourceError},
    ipc::Ipc,
};

const PHY_TOKEN: Token = Token(0);
const GNSS_TOKEN: Token = Token(1);
const IPC_REP_TOKEN: Token = Token(2);

pub type RouterResult<T> = core::result::Result<T, RouterError>;

/// Error returned by the router.
#[derive(Debug)]
pub enum RouterError {
    /// Error while creating the poll instance.
    PollCreate(io::Error),
    /// Error while cloning the poll registry.
    PollRegistryClone(io::Error),
    /// Error while setting up the interface.
    InterfaceSetup(io::Error),
    /// Error while creating the IPC sockets.
    IpcCreate(io::Error),
    /// Error getting the IPC interface as a mio [Source].
    IpcAsSource(io::Error),
    /// Error while registering up the IPC interface.
    IpcRegister(io::Error),
    /// GNSS setup error.
    GnssCreate(GnssSourceError),
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::PollCreate(e) => write!(f, "Failed to create poll instance: {e}"),
            RouterError::PollRegistryClone(e) => write!(f, "Failed to clone poll registry: {e}"),
            RouterError::InterfaceSetup(e) => write!(f, "Failed to setup interface: {e}"),
            RouterError::IpcCreate(e) => write!(f, "Failed to setup IPC sockets: {e}"),
            RouterError::IpcAsSource(e) => {
                write!(f, "Failed to get IPC interface as a mio source: {e}")
            }
            RouterError::IpcRegister(e) => write!(f, "Failed to register IPC interface: {e}"),
            RouterError::GnssCreate(e) => write!(f, "Failed to setup GNSS source: {e}"),
        }
    }
}

/// Geonetworking router.
#[derive(Debug)]
#[allow(unused)]
pub struct Router<'a> {
    /// Storage instance.
    storage_meta: Option<(Rc<DirectoryStorage>, SecurityStorageMetadata)>,
    /// Poll instance.
    poll: Poll,
    /// Device instance.
    device: AnyDevice,
    /// Interface instance.
    iface: Interface,
    /// Geonetworking router.
    router: GnCore,
    /// GNSS source.
    gnss: GnssSource,
    /// IPC instance.
    ipc: Ipc,
    /// IPC dispatcher.
    ipc_dispatcher: IpcDispatcher,
    /// High level sockets.
    sockets: SocketSet<'a>,
    /// CAM socket
    cam_socket_handle: SocketHandle,
    /// DENM socket
    denm_socket_handle: SocketHandle,
    /// Poll errors counter.
    poll_errors_num: u32,
    /// Max poll errors limit.
    max_poll_errors_num: u32,
}

impl<'a> Router<'a> {
    /// Constructs a new [Router] with parameters from the [Config].
    pub fn new(
        config: &Config,
        mut device: AnyDevice,
        security_config_storage: Option<(
            RouterSecurityConfig,
            Rc<DirectoryStorage>,
            SecurityStorageMetadata,
        )>,
    ) -> RouterResult<Router<'a>> {
        let poll = Poll::new().map_err(RouterError::PollCreate)?;
        let ipc = Ipc::new(config).map_err(RouterError::IpcCreate)?;

        let (security_config, storage_meta) =
            security_config_storage.map_or((None, None), |(c, s, m)| (Some(c), Some((s, m))));

        let mut router_config = GnCoreGonfig::new(config.station_type, Pseudonym(config.pseudonym));
        router_config.random_seed = rand::random();
        router_config.security = security_config;

        if let Some(addr) = config.ll_address {
            router_config.addr_config_mode = GnAddrConfigMode::Managed(addr);
        }

        let router = GnCore::new(router_config, Instant::now());
        let ll_addr = router.address().mac_addr();

        // Configure interface
        let ifconfig = RouterIfaceConfig::new(ll_addr.into());
        let iface = match &mut device {
            AnyDevice::NxpLlc(d) => {
                d.set_filter_addr(Some(ll_addr.into()));
                Self::setup_interface(d, ifconfig, poll.registry())
                    .map_err(RouterError::InterfaceSetup)?
            }
            AnyDevice::NxpUsb(d) => {
                d.set_filter_addr(Some(ll_addr.into()));
                Self::setup_interface(d, ifconfig, poll.registry())
                    .map_err(RouterError::InterfaceSetup)?
            }
            AnyDevice::RawEthernet(d) => Self::setup_interface(d, ifconfig, poll.registry())
                .map_err(RouterError::InterfaceSetup)?,
            AnyDevice::Udp(d) => Self::setup_interface(d, ifconfig, poll.registry())
                .map_err(RouterError::InterfaceSetup)?,
        };

        poll.registry()
            .register(
                &mut ipc.rep_as_source_fd().map_err(RouterError::IpcAsSource)?,
                IPC_REP_TOKEN,
                Interest::READABLE,
            )
            .map_err(RouterError::IpcRegister)?;

        // Configure sockets
        let mut sockets = SocketSet::new(vec![]);

        // Create CAM and DENM sockets
        let mut cam_socket = socket::cam::Socket::new();
        let mut denm_socket = socket::denm::Socket::new(vec![], vec![]);

        // Register the CAM tx callback.
        let ipc_cam_tx = ipc.publisher();
        cam_socket.register_send_callback(move |uper, _| {
            let evt = IpcEvent::new(IpcEventType::CamTx(uper.to_vec()));
            let bytes = evt.serialize_to_vec();
            ipc_cam_tx
                .send(&bytes)
                .inspect_err(|e| {
                    error!("Failed to send CAM Tx event on IPC publisher: {}", e);
                })
                .ok();
        });

        // Register the CAM rx callback.
        let ipc_cam_rx = ipc.publisher();
        cam_socket.register_recv_callback(move |uper, _| {
            let evt = IpcEvent::new(IpcEventType::CamRx(uper.to_vec()));
            let bytes = evt.serialize_to_vec();
            ipc_cam_rx
                .send(&bytes)
                .inspect_err(|e| {
                    error!("Failed to send CAM Rx event on IPC publisher: {}", e);
                })
                .ok();
        });

        // Register the DENM tx callback.
        let ipc_denm_tx = ipc.publisher();
        denm_socket.register_send_callback(move |uper, _| {
            let evt = IpcEvent::new(IpcEventType::DenmTx(uper.to_vec()));
            let bytes = evt.serialize_to_vec();
            ipc_denm_tx
                .send(&bytes)
                .inspect_err(|e| {
                    error!("Failed to send DENM Tx event on IPC publisher: {}", e);
                })
                .ok();
        });

        // Register the DENM rx callback.
        let ipc_denm_rx = ipc.publisher();
        denm_socket.register_recv_callback(move |uper, _| {
            let evt = IpcEvent::new(IpcEventType::DenmRx(uper.to_vec()));
            let bytes = evt.serialize_to_vec();
            ipc_denm_rx
                .send(&bytes)
                .inspect_err(|e| {
                    error!("Failed to send DENM Rx event on IPC publisher: {}", e);
                })
                .ok();
        });

        // Add them to a SocketSet
        let cam_socket_handle = sockets.add(cam_socket);
        let denm_socket_handle = sockets.add(denm_socket);

        // IPC dispatcher.
        let ipc_dispatcher = IpcDispatcher { denm_socket_handle };

        // GNSS source.
        let gnss_registry = poll
            .registry()
            .try_clone()
            .map_err(RouterError::PollRegistryClone)?;
        let gnss =
            GnssSource::new(config, gnss_registry, GNSS_TOKEN).map_err(RouterError::GnssCreate)?;

        Ok(Router {
            storage_meta,
            poll,
            device,
            iface,
            router,
            gnss,
            ipc,
            ipc_dispatcher,
            sockets,
            cam_socket_handle,
            denm_socket_handle,
            poll_errors_num: 0,
            max_poll_errors_num: 10000,
        })
    }

    pub fn run(&mut self) {
        let mut events = Events::with_capacity(128);
        debug!("running the geonetworking router");

        loop {
            self.check_for_poll_errors();

            // Update timestamp.
            let now = Instant::now();
            self.router.set_timestamp(now);

            // Process each event.
            for event in events.iter() {
                match event.token() {
                    PHY_TOKEN => {
                        match &mut self.device {
                            AnyDevice::NxpLlc(d) => self.iface.poll_ingress_single(
                                &mut self.router,
                                d,
                                &mut self.sockets,
                            ),
                            AnyDevice::NxpUsb(d) => self.iface.poll_ingress_single(
                                &mut self.router,
                                d,
                                &mut self.sockets,
                            ),
                            AnyDevice::RawEthernet(d) => self.iface.poll_ingress_single(
                                &mut self.router,
                                d,
                                &mut self.sockets,
                            ),
                            AnyDevice::Udp(d) => self.iface.poll_ingress_single(
                                &mut self.router,
                                d,
                                &mut self.sockets,
                            ),
                        };
                    }
                    GNSS_TOKEN => match &mut self.gnss {
                        GnssSource::Gpsd(gpsd) => {
                            gpsd.ready(event, now).then(|| {
                                gpsd.fetch_position()
                                    .try_into()
                                    .map(|fix| {
                                        self.router.set_position(fix, now).ok();
                                    })
                                    .ok();
                            });
                        }
                        _ => panic!("Unexpected GNSS source"),
                    },
                    IPC_REP_TOKEN => loop {
                        let rep = self.ipc.replier();
                        match rep.events() {
                            Ok(evts) if evts.contains(zmq::POLLIN) => match rep.recv() {
                                Ok(data) => match IpcEvent::deserialize(&data) {
                                    Ok(evt) => {
                                        let Ok(resp) = self.ipc_dispatcher.dispatch(
                                            evt,
                                            &self.router,
                                            &mut self.sockets,
                                        ) else {
                                            error!("IPC data malformed.");
                                            continue;
                                        };

                                        if let Some(resp) = resp {
                                            let serialized = resp.serialize_to_vec();
                                            rep.send(&serialized).inspect_err(|e|{
                                                error!("Failed to send IPC event response on IPC replier: {}", e);
                                            }).ok();
                                        }
                                    }
                                    Err(e) => error!("Cannot deserialize IPC event: {}", e),
                                },
                                Err(e) => error!("Cannot recv on IPC replier: {}", e),
                            },
                            Ok(_) => break,
                            Err(e) => error!("Cannot query ZMQ events on IPC replier: {}", e),
                        }
                    },
                    // We don't expect any events with tokens other than those we provided.
                    _ => unreachable!(),
                }
            }

            // Poll the Gnss source.
            match &mut self.gnss {
                GnssSource::Gpsd(gpsd) => {
                    gpsd.poll(now).ok();
                }
                GnssSource::Replay(replay) => {
                    if let Ok(true) = replay.poll(now) {
                        if let Ok(fix) = replay.fetch_position().try_into() {
                            self.router.set_position(fix, now).ok();
                        }
                    }
                }
                GnssSource::Fixed(fixed) => {
                    fixed
                        .fetch_position()
                        .try_into()
                        .map(|fix| {
                            self.router.set_position(fix, now).ok();
                        })
                        .ok();
                }
            }

            // Poll the router core for internal processing.
            match self.router.poll(&mut self.iface, now) {
                GnCorePollEvent::None => {}
                GnCorePollEvent::SecurityService(evt) => match evt {
                    SecurityServicePollEvent::PrivacyATCertificateRotation(i, _)
                    | SecurityServicePollEvent::ATCertificateExpiration(i, _) => {
                        self.storage_meta.as_mut().map(|(storage, meta)| {
                            meta.increment_elections_stats(i);
                            storage
                                .store_metadata(meta.to_owned())
                                .inspect_err(|e| {
                                    error!("Failed to store AT certificates metadata: {}", e);
                                })
                                .ok()
                        });
                    }
                },
            }

            // Poll the stack for egress or internal processing.
            match &mut self.device {
                AnyDevice::NxpLlc(d) => {
                    self.iface
                        .poll_egress(&mut self.router, d, &mut self.sockets)
                }
                AnyDevice::NxpUsb(d) => {
                    self.iface
                        .poll_egress(&mut self.router, d, &mut self.sockets)
                }
                AnyDevice::RawEthernet(d) => {
                    self.iface
                        .poll_egress(&mut self.router, d, &mut self.sockets)
                }
                AnyDevice::Udp(d) => self
                    .iface
                    .poll_egress(&mut self.router, d, &mut self.sockets),
            };

            let denm_socket = self
                .sockets
                .get_mut::<socket::denm::Socket>(self.denm_socket_handle);
            denm_socket.poll(now);

            // Poll Mio for events, blocking until we get an event or a timeout.
            let timeout = self.compute_timeout(now);
            loop {
                match self.poll.poll(&mut events, timeout) {
                    Ok(_) => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error!("Failed to poll events: {:?}", e);
                        self.poll_errors_num += 1;
                        continue;
                    }
                }
            }
        }
    }

    /// Compute the timeout to use for the next poll.
    fn compute_timeout(&self, now: Instant) -> Option<std::time::Duration> {
        let iface_timeout = self.iface.poll_delay(now, &self.sockets);
        let router_timeout = self.router.poll_delay(now);
        let gnss_timeout = if let GnssSource::Replay(replay) = &self.gnss {
            Some(replay.poll_delay(now))
        } else {
            None
        };

        [iface_timeout, router_timeout, gnss_timeout]
            .into_iter()
            .flatten()
            .min()
            .map(Into::into)
    }

    /// Check for polling errors.
    ///
    /// # Panics
    ///
    /// Panics if the number of polling errors exceeds the maximum number of
    /// errors allowed.
    fn check_for_poll_errors(&mut self) {
        if self.poll_errors_num >= self.max_poll_errors_num {
            error!(
                "Something is going very wrong. Last {} poll() calls failed, crashing..",
                self.poll_errors_num
            );
            panic!(
                "poll() calls failed {} times in a row",
                self.poll_errors_num
            );
        }
    }

    /// Setup the PHY device interface. Enables congestion control if the device
    /// is an IEEE 802.11p device.
    #[inline]
    fn setup_interface<D: Device + Source>(
        device: &mut D,
        ifconfig: RouterIfaceConfig,
        registry: &Registry,
    ) -> Result<Interface, io::Error> {
        let mut iface = Interface::new(ifconfig, device);

        if device.capabilities().medium == Medium::Ieee80211p {
            iface.set_congestion_control(CongestionControl::LimericDualAlpha);
        }

        registry.register(device, PHY_TOKEN, Interest::READABLE)?;

        Ok(iface)
    }
}
