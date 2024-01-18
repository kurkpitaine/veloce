#[cfg(test)]
mod tests;

#[cfg(feature = "proto-btp")]
mod btp;
#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "proto-geonet")]
mod geonet;
#[cfg(feature = "medium-ieee80211p")]
mod ieee80211p;

use super::location_service::LocationService;
use super::location_table::LocationTable;
use super::v2x_packet::*;

use super::socket_set::SocketSet;

use crate::common::{ContentionBuffer, PacketBuffer};
use crate::config::{
    GN_BC_FORWARDING_PACKET_BUFFER_ENTRY_COUNT as BC_BUF_ENTRY_NUM,
    GN_BC_FORWARDING_PACKET_BUFFER_SIZE as BC_BUF_SIZE,
    GN_CBF_PACKET_BUFFER_ENTRY_COUNT as CBF_BUF_ENTRY_NUM,
    GN_CBF_PACKET_BUFFER_SIZE as CBF_BUF_SIZE,
    GN_LOCATION_SERVICE_PACKET_BUFFER_ENTRY_COUNT as LS_BUF_ENTRY_NUM,
    GN_LOCATION_SERVICE_PACKET_BUFFER_SIZE as LS_BUF_SIZE,
    GN_UC_FORWARDING_PACKET_BUFFER_ENTRY_COUNT as UC_BUF_ENTRY_NUM,
    GN_UC_FORWARDING_PACKET_BUFFER_SIZE as UC_BUF_SIZE,
};
use crate::network::GnCore;
use crate::network::Indication;
use crate::phy::PacketMeta;
use crate::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};

use crate::socket::geonet::Socket as GeonetSocket;
use crate::socket::*;
use crate::time::{Duration, Instant};

use crate::wire::ieee80211::{FrameControl, QoSControl};
use crate::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, GeonetRepr, GeonetUnicast, HardwareAddress,
    Ieee80211Frame, Ieee80211Repr, LlcFrame, LlcRepr, SequenceNumber,
};

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed");
                return Default::default();
            }
        }
    };
}

macro_rules! sequence_number {
    ($handler:ident) => {
        (|| {
            let sn = $handler.sequence_number.clone();
            $handler.sequence_number += 1;
            sn
        })()
    };
}

use check;
use sequence_number;

type LsBuffer = PacketBuffer<GeonetUnicast, LS_BUF_ENTRY_NUM, LS_BUF_SIZE>;
type UcBuffer = PacketBuffer<GeonetUnicast, UC_BUF_ENTRY_NUM, UC_BUF_SIZE>;
type BcBuffer = PacketBuffer<GeonetRepr, BC_BUF_ENTRY_NUM, BC_BUF_SIZE>;
type CbfBuffer = ContentionBuffer<GeonetRepr, CBF_BUF_ENTRY_NUM, CBF_BUF_SIZE>;

/// A network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
#[derive(Debug)]
pub struct Interface {
    /// Interface inner description.
    pub(crate) inner: InterfaceInner,
    /// Location service of the interface.
    #[cfg(feature = "proto-geonet")]
    pub(crate) location_service: LocationService,
    /// Location Service packet buffer.
    #[cfg(feature = "proto-geonet")]
    pub(crate) ls_buffer: LsBuffer,
    /// Unicast forwarding packet buffer.
    #[cfg(feature = "proto-geonet")]
    pub(crate) uc_forwarding_buffer: UcBuffer,
    /// Broadcast forwarding packet buffer.
    #[cfg(feature = "proto-geonet")]
    pub(crate) bc_forwarding_buffer: BcBuffer,
    /// Contention Based forwarding packet buffer.
    #[cfg(feature = "proto-geonet")]
    pub(crate) cb_forwarding_buffer: CbfBuffer,
}

/// The device independent part of an access interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
#[derive(Debug)]
pub struct InterfaceInner {
    /// Access device capabilities.
    caps: DeviceCapabilities,
    /// Interface Hardware address.
    hardware_addr: HardwareAddress,
    /// Timestamp at which we need to retransmit a beacon packet.
    #[cfg(feature = "proto-geonet")]
    retransmit_beacon_at: Instant,
    /// Location Table of the Access Handler.
    #[cfg(feature = "proto-geonet")]
    location_table: LocationTable,
    /// Sequence Number of the Access Handler.
    #[cfg(feature = "proto-geonet")]
    sequence_number: SequenceNumber,
}

/// Configuration structure used for creating a network interface.
#[non_exhaustive]
pub struct Config {
    /// Random seed.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,

    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    pub hardware_addr: HardwareAddress,
}

impl Config {
    pub fn new(hardware_addr: HardwareAddress) -> Self {
        Config {
            random_seed: 0,
            hardware_addr,
        }
    }
}

/// Utility struct containing metadata for [InterfaceInner] processing.
#[cfg(feature = "proto-geonet")]
pub struct InterfaceServices<'a> {
    /// Reference on the Geonetworking core services.
    pub core: &'a mut GnCore,
    /// Reference on the Location Service.
    pub ls: &'a mut LocationService,
    /// Location Service packet buffer.
    pub ls_buffer: &'a mut LsBuffer,
    /// Unicast forwarding packet buffer.
    pub uc_forwarding_buffer: &'a mut UcBuffer,
    /// Broadcast forwarding packet buffer.
    pub bc_forwarding_buffer: &'a mut BcBuffer,
    /// Contention Based forwarding packet buffer.
    pub cb_forwarding_buffer: &'a mut CbfBuffer,
}

impl Interface {
    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// This function panics if the [`Config::hardware_address`] does not match
    /// the medium of the device.
    pub fn new<D>(config: Config, device: &mut D) -> Self
    where
        D: Device + ?Sized,
    {
        let caps = device.capabilities();

        match (caps.medium, config.hardware_addr) {
            #[cfg(feature = "medium-ethernet")]
            (Medium::Ethernet, HardwareAddress::Ethernet(_)) => {}
            #[cfg(feature = "medium-ieee80211p")]
            (Medium::Ieee80211p, HardwareAddress::Ethernet(_)) => {}
            #[cfg(feature = "medium-pc5")]
            (Medium::PC5, HardwareAddress::PC5(_)) => {}
            _ => panic!("The hardware address does not match the medium of the interface."),
        }

        Interface {
            location_service: LocationService::new(),
            ls_buffer: PacketBuffer::new(),
            uc_forwarding_buffer: PacketBuffer::new(),
            bc_forwarding_buffer: PacketBuffer::new(),
            cb_forwarding_buffer: ContentionBuffer::new(),
            inner: InterfaceInner {
                caps,
                hardware_addr: config.hardware_addr,
                retransmit_beacon_at: Instant::from_millis(0),
                location_table: LocationTable::new(),
                sequence_number: SequenceNumber(0),
            },
        }
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&mut self) -> &mut InterfaceInner {
        &mut self.inner
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    pub fn poll<D>(
        &mut self,
        core: &mut GnCore,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> bool
    where
        D: Device + ?Sized,
    {
        let mut readiness_may_have_changed = false;

        loop {
            let mut did_something = false;

            // net_trace!("socket_ingress");
            did_something |= self.socket_ingress(core, device, sockets);
            // net_trace!("socket_egress");
            did_something |= self.socket_egress(core, device, sockets);

            // Buffered packets inside different buffers are dequeued here after.
            // One call to xx_buffered_egress send ALL the packets marked for flush.
            // This could lead to some packets not being transmitted because of device exhaustion
            // if a large number of packets has to be sent.
            // net_trace!("ls_buffered_egress");
            did_something |= self.ls_buffered_egress(core, device);
            // net_trace!("uc_buffered_egress");
            did_something |= self.uc_buffered_egress(core, device);
            // net_trace!("bc_buffered_egress");
            did_something |= self.bc_buffered_egress(core, device);
            // net_trace!("cb_buffered_egress");
            did_something |= self.cb_buffered_egress(core, device);

            // net_trace!("location_service_egress");
            did_something |= self.location_service_egress(core, device);
            // net_trace!("beacon_service_egress");
            did_something |= self.beacon_service_egress(core, device);

            if did_something {
                readiness_may_have_changed = true;
            } else {
                break;
            }
        }

        readiness_may_have_changed
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&mut self, sockets: &SocketSet<'_>) -> Option<Instant> {
        let inner = &mut self.inner;

        let beacon_timeout = Some(inner.retransmit_beacon_at);
        let ls_timeout = self.location_service.poll_at();
        let cbf_timeout = self.cb_forwarding_buffer.poll_at();

        let sockets_timeout = sockets
            .items()
            .filter_map(move |item| {
                let socket_poll_at = item.socket.poll_at(inner);
                match socket_poll_at {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::ZERO),
                }
            })
            .min();

        let values = [beacon_timeout, ls_timeout, cbf_timeout, sockets_timeout];
        values.into_iter().flatten().min()
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Duration> {
        match self.poll_at(sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::ZERO),
            _ => None,
        }
    }

    fn socket_ingress<D>(
        &mut self,
        core: &mut GnCore,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> bool
    where
        D: Device + ?Sized,
    {
        let mut processed_any = false;

        while let Some((rx_token, tx_token)) = device.receive(core.now) {
            let rx_meta = rx_token.meta();
            let srv = InterfaceServices {
                core,
                ls: &mut self.location_service,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            };

            rx_token.consume(|frame| {
                match self.inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        if let Some((svcs, dst_addr, packet)) =
                            self.inner.process_ethernet(srv, sockets, rx_meta, frame)
                        {
                            if let Err(err) =
                                self.inner.dispatch(tx_token, svcs.core, dst_addr, packet)
                            {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ieee80211p")]
                    Medium::Ieee80211p => {
                        if let Some((svcs, dst_addr, packet)) =
                            self.inner.process_ieee80211p(srv, sockets, rx_meta, frame)
                        {
                            if let Err(err) =
                                self.inner.dispatch(tx_token, svcs.core, dst_addr, packet)
                            {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-pc5")]
                    Medium::PC5 => todo!(),
                }
                processed_any = true;
            });
        }

        processed_any
    }

    fn socket_egress<D>(
        &mut self,
        core: &mut GnCore,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> bool
    where
        D: Device + ?Sized,
    {
        let _caps = device.capabilities();

        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;
        for item in sockets.items_mut() {
            let mut respond = |inner: &mut InterfaceInner,
                               core: &mut GnCore,
                               meta: PacketMeta,
                               dst_ll_addr: EthernetAddress,
                               response: GeonetPacket| {
                let t = device.transmit(core.now).ok_or_else(|| {
                    net_debug!("failed to transmit geonet packet: device exhausted");
                    EgressError::Exhausted
                })?;

                inner
                    .dispatch_geonet(t, core, meta, dst_ll_addr, response)
                    .map_err(EgressError::Dispatch)?;

                emitted_any = true;

                Ok(())
            };

            let srv = InterfaceServices {
                core,
                ls: &mut self.location_service,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-geonet")]
                Socket::Geonet(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, (dst_ll_addr, gn, raw)| {
                        respond(
                            inner,
                            core,
                            PacketMeta::default(),
                            dst_ll_addr,
                            GeonetPacket::new(gn, GeonetPayload::Raw(raw)),
                        )
                    },
                ),
                #[cfg(feature = "socket-btp-a")]
                Socket::BtpA(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, (dst_ll_addr, gn, pl)| {
                        respond(
                            inner,
                            core,
                            PacketMeta::default(),
                            dst_ll_addr,
                            GeonetPacket::new(gn.into(), GeonetPayload::Raw(pl)),
                        )
                    },
                ),
                #[cfg(feature = "socket-btp-b")]
                Socket::BtpB(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, (dst_ll_addr, gn, pl)| {
                        respond(
                            inner,
                            core,
                            PacketMeta::default(),
                            dst_ll_addr,
                            GeonetPacket::new(gn, GeonetPayload::Raw(pl)),
                        )
                    },
                ),
            };

            match result {
                Err(EgressError::Exhausted) => break, // Device buffer full.
                Err(EgressError::Dispatch(_)) => {
                    net_trace!("");
                }
                Ok(()) => {}
            }
        }
        emitted_any
    }

    #[cfg(feature = "proto-geonet")]
    fn beacon_service_egress<D>(&mut self, core: &mut GnCore, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;

        let mut respond = |inner: &mut InterfaceInner,
                           core: &mut GnCore,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit beacon packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        let srv = InterfaceServices {
            core,
            ls: &mut self.location_service,
            ls_buffer: &mut self.ls_buffer,
            uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
            bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
            cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
        };

        let result = self.inner.dispatch_beacon(
            srv,
            |inner, core, (dst_ll_addr, bh_repr, ch_repr, bc_repr)| {
                respond(
                    inner,
                    core,
                    PacketMeta::default(),
                    dst_ll_addr,
                    GeonetPacket::new_beacon(bh_repr, ch_repr, bc_repr),
                )
            },
        );

        match result {
            Err(EgressError::Exhausted) => {} // Device buffer full.
            Err(EgressError::Dispatch(_)) => {
                net_debug!("failed to transmit beacon packet: dispatch error");
            }
            Ok(()) => {}
        }

        emitted_any
    }

    #[cfg(feature = "proto-geonet")]
    fn location_service_egress<D>(&mut self, core: &mut GnCore, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;

        let mut respond = |inner: &mut InterfaceInner,
                           core: &mut GnCore,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit location service packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        let srv = InterfaceServices {
            core,
            ls: &mut self.location_service,
            ls_buffer: &mut self.ls_buffer,
            uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
            bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
            cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
        };

        let result = self.inner.dispatch_ls_request(
            srv,
            |inner, core, (dst_ll_addr, bh_repr, ch_repr, ls_repr)| {
                respond(
                    inner,
                    core,
                    PacketMeta::default(),
                    dst_ll_addr,
                    GeonetPacket::new_location_service_request(bh_repr, ch_repr, ls_repr),
                )
            },
        );

        match result {
            Err(EgressError::Exhausted) => {} // Device buffer full.
            Err(EgressError::Dispatch(_)) => {
                net_debug!("failed to transmit location service packet: dispatch error");
            }
            Ok(()) => {}
        }

        emitted_any
    }

    #[cfg(feature = "proto-geonet")]
    fn ls_buffered_egress<D>(&mut self, core: &mut GnCore, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;

        let mut respond = |inner: &mut InterfaceInner,
                           core: &mut GnCore,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit LS buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            let srv = InterfaceServices {
                core,
                ls: &mut self.location_service,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            };

            let dequeued_some = self.inner.dispatch_ls_buffer(
                srv,
                |inner, core, (dst_ll_addr, bh_repr, ch_repr, uc_repr, raw)| {
                    respond(
                        inner,
                        core,
                        PacketMeta::default(),
                        dst_ll_addr,
                        GeonetPacket::new_unicast(
                            bh_repr,
                            ch_repr,
                            uc_repr,
                            GeonetPayload::Raw(raw),
                        ),
                    )
                },
            );

            let Some(result) = dequeued_some else {
                break;
            };

            match result {
                Err(EgressError::Exhausted) => {
                    // Device buffer full.
                    break;
                }
                Err(EgressError::Dispatch(_)) => {
                    net_debug!("failed to transmit LS buffered packet: dispatch error");
                    break;
                }
                Ok(()) => {}
            }
        }

        emitted_any
    }

    #[cfg(feature = "proto-geonet")]
    fn uc_buffered_egress<D>(&mut self, core: &mut GnCore, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;

        let mut respond = |inner: &mut InterfaceInner,
                           core: &mut GnCore,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit unicast buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            let srv = InterfaceServices {
                core,
                ls: &mut self.location_service,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            };

            let dequeued_some = self.inner.dispatch_unicast_buffer(
                srv,
                |inner, core, (dst_ll_addr, bh_repr, ch_repr, uc_repr, raw)| {
                    respond(
                        inner,
                        core,
                        PacketMeta::default(),
                        dst_ll_addr,
                        GeonetPacket::new_unicast(
                            bh_repr,
                            ch_repr,
                            uc_repr,
                            GeonetPayload::Raw(raw),
                        ),
                    )
                },
            );

            let Some(result) = dequeued_some else {
                break;
            };

            match result {
                Err(EgressError::Exhausted) => {
                    // Device buffer full.
                    break;
                }
                Err(EgressError::Dispatch(_)) => {
                    net_debug!("failed to transmit unicast buffered packet: dispatch error");
                    break;
                }
                Ok(()) => {}
            }
        }

        emitted_any
    }

    #[cfg(feature = "proto-geonet")]
    fn bc_buffered_egress<D>(&mut self, core: &mut GnCore, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;

        let mut respond = |inner: &mut InterfaceInner,
                           core: &mut GnCore,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit broadcast buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            let srv = InterfaceServices {
                core,
                ls: &mut self.location_service,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            };

            let dequeued_some = self.inner.dispatch_broadcast_buffer(
                srv,
                |inner, core, (dst_ll_addr, gn_repr, raw)| {
                    let response = match gn_repr {
                        GeonetRepr::Anycast(p) => GeonetPacket::new_anycast(
                            p.basic_header,
                            p.common_header,
                            p.extended_header,
                            GeonetPayload::Raw(raw),
                        ),
                        GeonetRepr::Broadcast(p) => GeonetPacket::new_broadcast(
                            p.basic_header,
                            p.common_header,
                            p.extended_header,
                            GeonetPayload::Raw(raw),
                        ),
                        GeonetRepr::SingleHopBroadcast(p) => {
                            GeonetPacket::new_single_hop_broadcast(
                                p.basic_header,
                                p.common_header,
                                p.extended_header,
                                GeonetPayload::Raw(raw),
                            )
                        }
                        GeonetRepr::TopoBroadcast(p) => GeonetPacket::new_topo_scoped_broadcast(
                            p.basic_header,
                            p.common_header,
                            p.extended_header,
                            GeonetPayload::Raw(raw),
                        ),
                        _ => unreachable!(), // No other packet type.
                    };
                    respond(inner, core, PacketMeta::default(), dst_ll_addr, response)
                },
            );

            let Some(result) = dequeued_some else {
                break;
            };

            match result {
                Err(EgressError::Exhausted) => {
                    // Device buffer full.
                    break;
                }
                Err(EgressError::Dispatch(_)) => {
                    net_debug!("failed to transmit broadcast buffered packet: dispatch error");
                    break;
                }
                Ok(()) => {}
            }
        }

        emitted_any
    }

    #[cfg(feature = "proto-geonet")]
    fn cb_buffered_egress<D>(&mut self, core: &mut GnCore, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;

        let mut respond = |inner: &mut InterfaceInner,
                           core: &mut GnCore,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit contention buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            let srv = InterfaceServices {
                core,
                ls: &mut self.location_service,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            };

            let dequeued_some = self.inner.dispatch_contention_buffer(
                srv,
                |inner, core, (dst_ll_addr, gn_repr, raw)| {
                    let response = match gn_repr {
                        GeonetRepr::Anycast(p) => GeonetPacket::new_anycast(
                            p.basic_header,
                            p.common_header,
                            p.extended_header,
                            GeonetPayload::Raw(raw),
                        ),
                        GeonetRepr::Broadcast(p) => GeonetPacket::new_broadcast(
                            p.basic_header,
                            p.common_header,
                            p.extended_header,
                            GeonetPayload::Raw(raw),
                        ),
                        GeonetRepr::SingleHopBroadcast(p) => {
                            GeonetPacket::new_single_hop_broadcast(
                                p.basic_header,
                                p.common_header,
                                p.extended_header,
                                GeonetPayload::Raw(raw),
                            )
                        }
                        GeonetRepr::TopoBroadcast(p) => GeonetPacket::new_topo_scoped_broadcast(
                            p.basic_header,
                            p.common_header,
                            p.extended_header,
                            GeonetPayload::Raw(raw),
                        ),
                        _ => unreachable!(), // No other packet type.
                    };
                    respond(inner, core, PacketMeta::default(), dst_ll_addr, response)
                },
            );

            let Some(result) = dequeued_some else {
                break;
            };

            match result {
                Err(EgressError::Exhausted) => {
                    // Device buffer full.
                    break;
                }
                Err(EgressError::Dispatch(_)) => {
                    net_debug!("failed to transmit contention buffered packet: dispatch error");
                    break;
                }
                Ok(()) => {}
            }
        }

        emitted_any
    }
}

impl InterfaceInner {
    #[cfg(feature = "medium-ethernet")]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> HardwareAddress {
        self.hardware_addr
    }

    #[cfg(feature = "medium-ethernet")]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Hardware address {addr} is not unicast")
        }
    }

    #[cfg(feature = "socket-geonet")]
    fn geonet_socket_filter(
        &mut self,
        sockets: &mut SocketSet,
        indication: Indication,
        payload: &[u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every GN packet to all geonet sockets we have registered.
        for raw_socket in sockets
            .items_mut()
            .filter_map(|i| GeonetSocket::downcast_mut(&mut i.socket))
        {
            raw_socket.process(self, indication, payload);
            handled_by_raw_socket = true;
        }
        handled_by_raw_socket
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-80211p"))]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        core: &mut GnCore,
        dst_hardware_addr: EthernetAddress,
        packet: EthernetPacket,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
    {
        match packet {
            EthernetPacket::Geonet(packet) => self.dispatch_geonet(
                tx_token,
                core,
                PacketMeta::default(),
                dst_hardware_addr,
                packet,
            ),
        }
    }

    fn dispatch_geonet<Tx: TxToken>(
        &mut self,
        mut tx_token: Tx,
        core: &mut GnCore,
        meta: PacketMeta,
        dst_hardware_addr: EthernetAddress,
        packet: GeonetPacket,
    ) -> Result<(), DispatchError> {
        let gn_repr = packet.geonet_repr();

        let caps = self.caps.clone();

        // First we calculate the total length that we will have to emit.
        let mut total_len = gn_repr.buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(self.caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);
            frame.set_ethertype(EthernetProtocol::Geonet);
        };

        // Add the size of the Ieee 802.11 Qos with LLC header if the medium is Ieee 802.11p.
        #[cfg(feature = "medium-ieee80211p")]
        if matches!(self.caps.medium, Medium::Ieee80211p) {
            total_len =
                total_len + Ieee80211Frame::<&[u8]>::header_len() + LlcFrame::<&[u8]>::header_len();
        }

        // Emit function for the Ieee 802.11 Qos with LLC header.
        #[cfg(feature = "medium-ieee80211p")]
        let emit_ieee80211 = |tx_buffer: &mut [u8]| {
            let src_addr = self.hardware_addr.ethernet_or_panic();

            let mut frame_ctrl = FrameControl::from_bytes(&[0, 0]);
            frame_ctrl.set_type(2); // Data frame
            frame_ctrl.set_sub_type(8); // QoS subtype

            let mut qos_ctrl = QoSControl::from_bytes(&[0, 0]);
            qos_ctrl.set_tc_id(3); // Best effort
            qos_ctrl.set_ack_policy(1); // No Ack

            let ieee80211_repr = Ieee80211Repr {
                frame_control: frame_ctrl,
                duration_or_id: Default::default(),
                dst_addr: dst_hardware_addr,
                src_addr: src_addr,
                bss_id: EthernetAddress::BROADCAST,
                sequence_control: Default::default(),
                qos_control: qos_ctrl,
            };

            let llc_repr = LlcRepr {
                dsap: 0xaa,
                ssap: 0xaa,
                control: 0x03,
                snap_vendor: [0; 3],
                snap_protocol: EthernetProtocol::Geonet,
            };

            let mut ieee80211_frame = Ieee80211Frame::new_unchecked(tx_buffer);
            ieee80211_repr.emit(&mut ieee80211_frame);

            let mut llc_frame = LlcFrame::new_unchecked(ieee80211_frame.payload_mut());
            llc_repr.emit(&mut llc_frame);
        };

        // Emit function for the Geonetworking header and payload.
        let emit_gn = |repr: &GeonetRepr, mut tx_buffer: &mut [u8]| {
            gn_repr.emit(&mut tx_buffer);

            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps)
        };

        tx_token.set_meta(meta);
        tx_token
            .consume(total_len, |mut tx_buffer| {
                #[cfg(feature = "medium-ethernet")]
                if matches!(self.caps.medium, Medium::Ethernet) {
                    emit_ethernet(tx_buffer);
                    tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                }

                #[cfg(feature = "medium-ieee80211p")]
                if matches!(self.caps.medium, Medium::Ieee80211p) {
                    emit_ieee80211(tx_buffer);
                    let pl_start =
                        Ieee80211Frame::<&[u8]>::header_len() + LlcFrame::<&[u8]>::header_len();
                    tx_buffer = &mut tx_buffer[pl_start..];
                }

                emit_gn(&gn_repr, tx_buffer);
                Ok(())
            })
            .and_then(|_| {
                self.defer_beacon(core, &gn_repr);
                Ok(())
            })
    }

    #[cfg(all(feature = "proto-geonet", feature = "conformance"))]
    pub fn clear_location_table(&mut self) {
        self.location_table.clear();
    }

    #[cfg(all(feature = "proto-geonet", feature = "conformance"))]
    pub fn reset_sequence_number(&mut self) {
        self.sequence_number.0 = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
enum DispatchError {
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
