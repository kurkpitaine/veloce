#[cfg(test)]
mod tests;

#[cfg(feature = "proto-btp")]
mod btp;
#[cfg(feature = "proto-geonet")]
pub mod congestion;
#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "proto-geonet")]
mod geonet;
#[cfg(feature = "medium-ieee80211p")]
mod ieee80211p;

use super::congestion::{AnyController, Congestion, CongestionSuccess};

use super::location_service::LocationService;
use super::location_table::LocationTable;
use super::packet::*;

use super::socket_set::SocketSet;

use crate::common::{ContentionBuffer, PacketBuffer};
use crate::config::{
    GN_BC_FORWARDING_PACKET_BUFFER_SIZE as BC_BUF_SIZE, GN_CBF_PACKET_BUFFER_SIZE as CBF_BUF_SIZE,
    GN_LOCATION_SERVICE_PACKET_BUFFER_SIZE as LS_BUF_SIZE,
    GN_UC_FORWARDING_PACKET_BUFFER_SIZE as UC_BUF_SIZE,
};
use crate::network::GnCore;
use crate::network::Indication;
use crate::phy::{
    Device, DeviceCapabilities, MacFilterCapabilities, Medium, PacketMeta, RxToken, TxToken,
};

#[cfg(feature = "proto-security")]
use crate::security::service::{decap::DecapConfirm, SecurityServiceError};

use crate::socket::geonet::Socket as GeonetSocket;
use crate::socket::*;
use crate::time::{Duration, Instant};

use crate::wire::ieee80211::{FrameControl, QoSControl};
use crate::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, GeonetRepr, GeonetUnicast, GeonetVariant,
    HardwareAddress, Ieee80211Frame, Ieee80211Repr, LlcFrame, LlcRepr, SequenceNumber,
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

#[cfg(feature = "proto-geonet")]
macro_rules! next_sequence_number {
    ($handler:ident) => {
        (|| {
            let sn = $handler.sequence_number.clone();
            $handler.sequence_number += 1;
            sn
        })()
    };
}

#[cfg(all(feature = "proto-geonet", feature = "proto-security"))]
#[inline]
pub(super) fn to_gn_repr<T>(variant: T, ctx: &mut DecapContext) -> GeonetRepr<T>
where
    T: crate::common::PacketBufferMeta,
{
    if let Some(d) = ctx.decap_confirm.take() {
        GeonetRepr::SecuredDecap {
            repr: variant,
            secured_message: d.secured_message,
            secured_message_size: d.size,
        }
    } else {
        GeonetRepr::Unsecured(variant)
    }
}

use check;

#[cfg(feature = "proto-geonet")]
use next_sequence_number;

type LsBuffer = PacketBuffer<GeonetRepr<GeonetUnicast>, LS_BUF_SIZE>;
type UcBuffer = PacketBuffer<GeonetRepr<GeonetUnicast>, UC_BUF_SIZE>;
type BcBuffer = PacketBuffer<GeonetRepr<GeonetVariant>, BC_BUF_SIZE>;
type CbfBuffer = ContentionBuffer<GeonetRepr<GeonetVariant>, CBF_BUF_SIZE>;

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
    /// Rate control (aka DCC)
    #[cfg(feature = "proto-geonet")]
    pub(crate) congestion_control: Congestion,
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
    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    pub hardware_addr: HardwareAddress,
}

impl Config {
    pub fn new(hardware_addr: HardwareAddress) -> Self {
        Config { hardware_addr }
    }
}

/// Utility struct containing metadata for [InterfaceInner] processing.
#[cfg(feature = "proto-geonet")]
pub(crate) struct InterfaceContext<'a> {
    /// Reference on the Geonetworking core services.
    pub core: &'a mut GnCore,
    /// Reference on the Location Service.
    pub ls: &'a mut LocationService,
    /// Reference on the Congestion Control Service.
    pub congestion_control: &'a mut Congestion,
    /// Location Service packet buffer.
    pub ls_buffer: &'a mut LsBuffer,
    /// Unicast forwarding packet buffer.
    pub uc_forwarding_buffer: &'a mut UcBuffer,
    /// Broadcast forwarding packet buffer.
    pub bc_forwarding_buffer: &'a mut BcBuffer,
    /// Contention Based forwarding packet buffer.
    pub cb_forwarding_buffer: &'a mut CbfBuffer,
    #[cfg(feature = "proto-security")]
    /// Security decapsulation context.
    pub decap_context: &'a mut DecapContext,
}

#[cfg(feature = "proto-security")]
#[derive(Default, Clone)]
pub(crate) struct DecapContext {
    /// Security decap service result.
    pub decap_confirm: Option<DecapConfirm>,
}

/// Buffer type for data enclosed in the security wrapper.
/// Becomes a zero-sized type when security is disabled, and will be zero-cost as
/// stripped by the optimizer.
#[derive(Default)]
pub(crate) struct SecuredDataBuffer {
    #[cfg(feature = "proto-security")]
    pub buffer: veloce_asn1::prelude::rasn::types::OctetString,
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
            congestion_control: Congestion::new(AnyController::new()),
            inner: InterfaceInner {
                caps,
                hardware_addr: config.hardware_addr,
                retransmit_beacon_at: Instant::from_millis(0),
                location_table: LocationTable::new(),
                sequence_number: SequenceNumber(0),
            },
        }
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
        #[cfg(feature = "proto-geonet")]
        {
            self.run_congestion_control(core.now, device.channel_busy_ratio());
            if self.congestion_control_egress(core, device) {
                return true;
            }
        }

        let mut readiness_may_have_changed = false;

        loop {
            let mut did_something = false;

            did_something |= self.socket_ingress(core, device, sockets);
            // net_trace!("socket_ingress = {}", did_something);
            did_something |= self.socket_egress(core, device, sockets);
            // net_trace!("socket_egress = {}", did_something);

            // Buffered packets inside different buffers are dequeued here after.
            // One call to xx_buffered_egress send ALL the packets marked for flush.
            // This could lead to some packets not being transmitted because of device exhaustion
            // if a large number of packets has to be sent.
            did_something |= self.ls_buffered_egress(core, device);
            // net_trace!("ls_buffered_egress = {}", did_something);
            did_something |= self.uc_buffered_egress(core, device);
            // net_trace!("uc_buffered_egress = {}", did_something);
            did_something |= self.bc_buffered_egress(core, device);
            // net_trace!("bc_buffered_egress = {}", did_something);
            did_something |= self.cb_buffered_egress(core, device);
            // net_trace!("cb_buffered_egress = {}", did_something);

            did_something |= self.location_service_egress(core, device);
            // net_trace!("location_service_egress = {}", did_something);
            did_something |= self.beacon_service_egress(core, device);
            // net_trace!("beacon_service_egress = {}", did_something);

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

        let trc_timeout = self.congestion_control.poll_at();
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

        let values = [
            trc_timeout,
            beacon_timeout,
            ls_timeout,
            cbf_timeout,
            sockets_timeout,
        ];

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

            rx_token.consume(|frame| {
                if frame.is_empty() {
                    return;
                }

                let mut sec_buf = SecuredDataBuffer::default();
                let ctx = InterfaceContext {
                    core,
                    ls: &mut self.location_service,
                    congestion_control: &mut self.congestion_control,
                    ls_buffer: &mut self.ls_buffer,
                    uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                    bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                    cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
                    #[cfg(feature = "proto-security")]
                    decap_context: &mut DecapContext::default(),
                };

                match self.inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        if let Some((ctx, dst_addr, packet)) =
                            self.inner
                                .process_ethernet(ctx, sockets, rx_meta, frame, &mut sec_buf)
                        {
                            if let Err(err) = self.inner.dispatch(
                                tx_token,
                                ctx.core,
                                dst_addr,
                                packet,
                                ctx.congestion_control,
                            ) {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ieee80211p")]
                    Medium::Ieee80211p => {
                        if let Some((ctx, dst_addr, packet)) = self.inner.process_ieee80211p(
                            ctx,
                            sockets,
                            rx_meta,
                            frame,
                            &mut sec_buf,
                        ) {
                            if let Err(err) = self.inner.dispatch(
                                tx_token,
                                ctx.core,
                                dst_addr,
                                packet,
                                ctx.congestion_control,
                            ) {
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

        // Update device filter.
        #[cfg(any(feature = "medium-pc5", feature = "medium-ieee80211p"))]
        if self.inner.caps.radio.mac_filter == MacFilterCapabilities::Rx {
            let hardware_addr = self.inner.hardware_addr;
            match device.filter_addr() {
                Some(filter_addr) if filter_addr != hardware_addr => {
                    device.set_filter_addr(Some(hardware_addr));
                }
                _ => {}
            }
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
                               congestion_ctrl: &mut Congestion,
                               meta: PacketMeta,
                               dst_ll_addr: EthernetAddress,
                               response: GeonetPacket| {
                let t = device.transmit(core.now).ok_or_else(|| {
                    net_debug!("failed to transmit geonet packet: device exhausted");
                    EgressError::Exhausted
                })?;

                inner
                    .dispatch_geonet(t, core, meta, dst_ll_addr, response, congestion_ctrl)
                    .map_err(EgressError::Dispatch)?;

                emitted_any = true;

                Ok(())
            };

            #[cfg(feature = "proto-security")]
            let mut sec_ctx = DecapContext::default();

            let srv = InterfaceContext {
                core,
                ls: &mut self.location_service,
                congestion_control: &mut self.congestion_control,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
                #[cfg(feature = "proto-security")]
                decap_context: &mut sec_ctx,
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-geonet")]
                Socket::Geonet(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, congestion, (dst_ll_addr, pkt)| {
                        respond(
                            inner,
                            core,
                            congestion,
                            PacketMeta::default(),
                            dst_ll_addr,
                            pkt,
                        )
                    },
                ),
                #[cfg(feature = "socket-btp-a")]
                Socket::BtpA(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, congestion, (dst_ll_addr, pkt)| {
                        respond(
                            inner,
                            core,
                            congestion,
                            PacketMeta::default(),
                            dst_ll_addr,
                            pkt,
                        )
                    },
                ),
                #[cfg(feature = "socket-btp-b")]
                Socket::BtpB(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, congestion, (dst_ll_addr, pkt)| {
                        respond(
                            inner,
                            core,
                            congestion,
                            PacketMeta::default(),
                            dst_ll_addr,
                            pkt,
                        )
                    },
                ),
                #[cfg(feature = "socket-cam")]
                Socket::Cam(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, congestion, (dst_ll_addr, pkt)| {
                        respond(
                            inner,
                            core,
                            congestion,
                            PacketMeta::default(),
                            dst_ll_addr,
                            pkt,
                        )
                    },
                ),
                #[cfg(feature = "socket-denm")]
                Socket::Denm(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, congestion, (dst_ll_addr, pkt)| {
                        respond(
                            inner,
                            core,
                            congestion,
                            PacketMeta::default(),
                            dst_ll_addr,
                            pkt,
                        )
                    },
                ),
            };

            match result {
                Err(EgressError::Exhausted) => break, // Device buffer full.
                Err(EgressError::Dispatch(d)) => {
                    net_trace!("failed to transmit geonet packet: dispatch error - {:?}", d);
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
                           congestion_ctrl: &mut Congestion,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit beacon packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response, congestion_ctrl)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        #[cfg(feature = "proto-security")]
        let mut sec_ctx = DecapContext::default();

        let srv = InterfaceContext {
            core,
            ls: &mut self.location_service,
            congestion_control: &mut self.congestion_control,
            ls_buffer: &mut self.ls_buffer,
            uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
            bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
            cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            #[cfg(feature = "proto-security")]
            decap_context: &mut sec_ctx,
        };

        let result =
            self.inner
                .dispatch_beacon(srv, |inner, core, congestion, (dst_ll_addr, pkt)| {
                    respond(
                        inner,
                        core,
                        congestion,
                        PacketMeta::default(),
                        dst_ll_addr,
                        pkt,
                    )
                });

        match result {
            Err(EgressError::Exhausted) => {} // Device buffer full.
            Err(EgressError::Dispatch(d)) => {
                net_debug!("failed to transmit beacon packet: dispatch error - {:?}", d);
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
                           congestion_ctrl: &mut Congestion,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit location service packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response, congestion_ctrl)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        #[cfg(feature = "proto-security")]
        let mut sec_ctx = DecapContext::default();

        let srv = InterfaceContext {
            core,
            ls: &mut self.location_service,
            congestion_control: &mut self.congestion_control,
            ls_buffer: &mut self.ls_buffer,
            uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
            bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
            cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
            #[cfg(feature = "proto-security")]
            decap_context: &mut sec_ctx,
        };

        let result = self.inner.dispatch_ls_request(
            srv,
            |inner, core, congestion, (dst_ll_addr, packet)| {
                respond(
                    inner,
                    core,
                    congestion,
                    PacketMeta::default(),
                    dst_ll_addr,
                    packet,
                )
            },
        );

        match result {
            Err(EgressError::Exhausted) => {} // Device buffer full.
            Err(EgressError::Dispatch(d)) => {
                net_debug!(
                    "failed to transmit location service packet: dispatch error - {:?}",
                    d
                );
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
                           congestion_ctrl: &mut Congestion,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit LS buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response, congestion_ctrl)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            #[cfg(feature = "proto-security")]
            let mut sec_ctx = DecapContext::default();

            let srv = InterfaceContext {
                core,
                ls: &mut self.location_service,
                congestion_control: &mut self.congestion_control,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
                #[cfg(feature = "proto-security")]
                decap_context: &mut sec_ctx,
            };

            let dequeued_some = self.inner.dispatch_ls_buffer(
                srv,
                |inner, core, congestion, (dst_ll_addr, gn_repr, raw)| {
                    respond(
                        inner,
                        core,
                        congestion,
                        PacketMeta::default(),
                        dst_ll_addr,
                        GeonetPacket::new(gn_repr, Some(raw)),
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
                Err(EgressError::Dispatch(d)) => {
                    net_debug!(
                        "failed to transmit LS buffered packet: dispatch error - {:?}",
                        d
                    );
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
                           congestion_ctrl: &mut Congestion,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit unicast buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response, congestion_ctrl)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            #[cfg(feature = "proto-security")]
            let mut sec_ctx = DecapContext::default();

            let srv = InterfaceContext {
                core,
                ls: &mut self.location_service,
                congestion_control: &mut self.congestion_control,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
                #[cfg(feature = "proto-security")]
                decap_context: &mut sec_ctx,
            };

            let dequeued_some = self.inner.dispatch_unicast_buffer(
                srv,
                |inner, core, congestion, (dst_ll_addr, gn_repr, raw)| {
                    respond(
                        inner,
                        core,
                        congestion,
                        PacketMeta::default(),
                        dst_ll_addr,
                        GeonetPacket::new(gn_repr, Some(raw)),
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
                Err(EgressError::Dispatch(d)) => {
                    net_debug!(
                        "failed to transmit unicast buffered packet: dispatch error - {:?}",
                        d
                    );
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
                           congestion_ctrl: &mut Congestion,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit broadcast buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response, congestion_ctrl)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            #[cfg(feature = "proto-security")]
            let mut sec_ctx = DecapContext::default();

            let srv = InterfaceContext {
                core,
                ls: &mut self.location_service,
                congestion_control: &mut self.congestion_control,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
                #[cfg(feature = "proto-security")]
                decap_context: &mut sec_ctx,
            };

            let dequeued_some = self.inner.dispatch_broadcast_buffer(
                srv,
                |inner, core, congestion, (dst_ll_addr, gn_repr, raw)| {
                    respond(
                        inner,
                        core,
                        congestion,
                        PacketMeta::default(),
                        dst_ll_addr,
                        GeonetPacket::new(gn_repr, Some(raw)),
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
                Err(EgressError::Dispatch(d)) => {
                    net_debug!(
                        "failed to transmit broadcast buffered packet: dispatch error - {:?}",
                        d
                    );
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
                           congestion_ctrl: &mut Congestion,
                           meta: PacketMeta,
                           dst_ll_addr: EthernetAddress,
                           response: GeonetPacket| {
            let t = device.transmit(core.now).ok_or_else(|| {
                net_debug!("failed to transmit contention buffered packet: device exhausted");
                EgressError::Exhausted
            })?;

            inner
                .dispatch_geonet(t, core, meta, dst_ll_addr, response, congestion_ctrl)
                .map_err(EgressError::Dispatch)?;

            emitted_any = true;

            Ok(())
        };

        loop {
            #[cfg(feature = "proto-security")]
            let mut sec_ctx = DecapContext::default();

            let srv = InterfaceContext {
                core,
                ls: &mut self.location_service,
                congestion_control: &mut self.congestion_control,
                ls_buffer: &mut self.ls_buffer,
                uc_forwarding_buffer: &mut self.uc_forwarding_buffer,
                bc_forwarding_buffer: &mut self.bc_forwarding_buffer,
                cb_forwarding_buffer: &mut self.cb_forwarding_buffer,
                #[cfg(feature = "proto-security")]
                decap_context: &mut sec_ctx,
            };

            let dequeued_some = self.inner.dispatch_contention_buffer(
                srv,
                |inner, core, congestion, (dst_ll_addr, gn_repr, raw)| {
                    respond(
                        inner,
                        core,
                        congestion,
                        PacketMeta::default(),
                        dst_ll_addr,
                        GeonetPacket::new(gn_repr, Some(raw)),
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
                Err(EgressError::Dispatch(d)) => {
                    net_debug!(
                        "failed to transmit contention buffered packet: dispatch error - {:?}",
                        d
                    );
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
    #[allow(unused)]
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
            raw_socket.process(self, indication.clone(), payload);
            handled_by_raw_socket = true;
        }
        handled_by_raw_socket
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        core: &mut GnCore,
        dst_hardware_addr: EthernetAddress,
        packet: EthernetPacket,
        trc: &mut Congestion,
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
                trc,
            ),
        }
    }

    fn dispatch_geonet<Tx: TxToken>(
        &mut self,
        mut tx_token: Tx,
        core: &mut GnCore,
        meta: PacketMeta,
        dst_hw_addr: EthernetAddress,
        packet: GeonetPacket,
        trc: &mut Congestion,
    ) -> Result<(), DispatchError> {
        self.defer_beacon(core, &packet.repr().inner());

        #[cfg(feature = "proto-security")]
        let position = core.position().position;
        #[cfg(feature = "proto-security")]
        let (packet, mut total_len) = match (&mut core.security, packet.repr()) {
            (Some(sec_srv), GeonetRepr::ToSecure { repr, permission }) => {
                // Packet has to be secured. Secured content consists of the common header, extended header and payload.

                // Emit the common header, extended header and payload in a buffer.
                let mut buffer =
                    vec![0u8; repr.common_and_extended_header_len() + repr.payload_len()];

                repr.emit_common_and_extended_header(&mut buffer);
                let payload_buf = &mut buffer[repr.common_and_extended_header_len()..];
                packet.emit_payload(payload_buf);

                // Sign the emitted content.
                match sec_srv.encap_packet(&buffer, permission.clone(), core.now, position) {
                    Ok(encapsulated) => {
                        let len = repr.basic_header_len() + encapsulated.len();
                        let pkt = GeonetPacket::new(
                            GeonetRepr::Secured {
                                repr: repr.to_owned(),
                                encapsulated,
                            },
                            packet.payload(),
                        );
                        (pkt, len)
                    }
                    Err(e) => return Err(DispatchError::Security(e)),
                }
            }
            (
                Some(_),
                GeonetRepr::SecuredDecap {
                    repr,
                    secured_message,
                    ..
                },
            ) => match secured_message.as_bytes() {
                // Packet is already secured, we just need to emit it.
                Ok(encapsulated) => {
                    let len = repr.basic_header_len() + encapsulated.len();
                    let pkt = GeonetPacket::new(
                        GeonetRepr::Secured {
                            repr: repr.to_owned(),
                            encapsulated,
                        },
                        packet.payload(),
                    );
                    (pkt, len)
                }
                Err(e) => {
                    return Err(DispatchError::Security(
                        SecurityServiceError::InvalidContent(e),
                    ))
                }
            },
            _ => {
                let len = packet.repr().inner().buffer_len();
                let pkt = GeonetPacket::new(
                    GeonetRepr::Unsecured(packet.repr().inner().to_owned()),
                    packet.payload(),
                );
                (pkt, len)
            }
        };

        match trc.dispatch(&packet, dst_hw_addr, core.timestamp()) {
            Ok(CongestionSuccess::ImmediateTx) => {
                // net_trace!("CongestionSuccess::ImmediateTx");
            }
            Ok(CongestionSuccess::Enqueued) => {
                // net_trace!("CongestionSuccess::Enqueued");
                return Ok(());
            }
            Err(_) => {
                net_trace!("Error in DCC transmit rate control");
                return Err(DispatchError::RateControl);
            }
        }

        let gn_repr = packet.repr();
        let caps = self.caps.clone();

        #[cfg(not(feature = "proto-security"))]
        // First we calculate the total length that we will have to emit.
        let mut total_len = gn_repr.inner().buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hw_addr);
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
            let cat = gn_repr.inner().traffic_class().access_category();
            qos_ctrl.set_access_category(cat);
            qos_ctrl.set_ack_policy(1); // No Ack

            let ieee80211_repr = Ieee80211Repr {
                frame_control: frame_ctrl,
                duration_or_id: Default::default(),
                dst_addr: dst_hw_addr,
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
        #[allow(unused_mut)]
        let emit_gn = |gn_repr: &GeonetRepr<GeonetVariant>, mut tx_buffer: &mut [u8]| {
            #[cfg(feature = "proto-security")]
            if let GeonetRepr::Secured { encapsulated, .. } = gn_repr {
                // Emit the basic header.
                gn_repr.inner().emit_basic_header(&mut tx_buffer);
                // Put the encapsulated content in the tx buffer.
                tx_buffer[gn_repr.inner().basic_header_len()..].copy_from_slice(&encapsulated);
            } else {
                gn_repr.inner().emit(&mut tx_buffer);
                packet.emit_payload(&mut tx_buffer[gn_repr.inner().header_len()..]);
            };

            #[cfg(not(feature = "proto-security"))]
            let payload_buf = &mut tx_buffer[gn_repr.inner().header_len()..];
            #[cfg(not(feature = "proto-security"))]
            packet.emit_payload(payload_buf)
        };

        tx_token.set_meta(meta);
        tx_token
            .consume(total_len, |mut tx_buffer| {
                #[cfg(feature = "medium-ethernet")]
                if matches!(caps.medium, Medium::Ethernet) {
                    emit_ethernet(tx_buffer);
                    tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                }

                #[cfg(feature = "medium-ieee80211p")]
                if matches!(caps.medium, Medium::Ieee80211p) {
                    emit_ieee80211(tx_buffer);
                    let pl_start =
                        Ieee80211Frame::<&[u8]>::header_len() + LlcFrame::<&[u8]>::header_len();
                    tx_buffer = &mut tx_buffer[pl_start..];
                }

                emit_gn(&gn_repr, tx_buffer);
                Ok(())
            })
            .and_then(|_| {
                // G5 bandwidth is 6 Mbps.
                let bytes_per_usec: f64 = 6.144 / 8.0;
                let tx_duration_usec = bytes_per_usec * total_len as f64;
                trc.controller
                    .inner_mut()
                    .notify_tx(core.now, Duration::from_micros(tx_duration_usec as u64));
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

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
enum DispatchError {
    /// Rate control returned an error on dispatch.
    #[cfg(feature = "proto-geonet")]
    RateControl,
    /// Security service returned an error on dispatch.
    #[cfg(feature = "proto-security")]
    Security(SecurityServiceError),
}
