#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "proto-geonet")]
mod geonet;

use super::location_service::LocationService;
use super::location_table::LocationTable;
use super::v2x_packet::*;

use super::socket_set::SocketSet;

use crate::geonet::common::PacketBuffer;
use crate::geonet::config::{
    GN_BC_FORWARDING_PACKET_BUFFER_ENTRY_COUNT as BC_BUF_ENTRY_NUM,
    GN_BC_FORWARDING_PACKET_BUFFER_SIZE as BC_BUF_SIZE,
    GN_LOCATION_SERVICE_PACKET_BUFFER_ENTRY_COUNT as LS_BUF_ENTRY_NUM,
    GN_LOCATION_SERVICE_PACKET_BUFFER_SIZE as LS_BUF_SIZE,
    GN_UC_FORWARDING_PACKET_BUFFER_ENTRY_COUNT as UC_BUF_ENTRY_NUM,
    GN_UC_FORWARDING_PACKET_BUFFER_SIZE as UC_BUF_SIZE,
};
use crate::geonet::network::GnCore;
use crate::geonet::network::Indication;
use crate::geonet::phy::PacketMeta;
use crate::geonet::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};

use crate::geonet::socket::geonet::Socket as GeonetSocket;
use crate::geonet::socket::*;
use crate::geonet::time::{Duration, Instant};

use crate::geonet::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, GeonetRepr, GeonetUnicast, HardwareAddress,
    SequenceNumber,
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
    location_service: LocationService,
}

type LsBuffer = PacketBuffer<GeonetUnicast, LS_BUF_ENTRY_NUM, LS_BUF_SIZE>;
type UcBuffer = PacketBuffer<GeonetUnicast, UC_BUF_ENTRY_NUM, UC_BUF_SIZE>;
type BcBuffer = PacketBuffer<GeonetRepr, BC_BUF_ENTRY_NUM, BC_BUF_SIZE>;

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
    /// Location Service packet buffer.
    #[cfg(feature = "proto-geonet")]
    ls_buffer: LsBuffer,
    /// Unicast forwarding packet buffer.
    #[cfg(feature = "proto-geonet")]
    uc_forwarding_buffer: UcBuffer,
    /// Broadcast forwarding packet buffer.
    #[cfg(feature = "proto-geonet")]
    bc_forwarding_buffer: BcBuffer,
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
pub struct InterfaceServices<'a> {
    /// Reference on the Geonetworking core services.
    pub core: &'a mut GnCore,
    /// Reference on the Location Service.
    pub ls: &'a mut LocationService,
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
            inner: InterfaceInner {
                caps,
                hardware_addr: config.hardware_addr,
                retransmit_beacon_at: Instant::from_millis(0),
                location_table: LocationTable::new(),
                sequence_number: SequenceNumber(0),
                ls_buffer: PacketBuffer::new(),
                uc_forwarding_buffer: PacketBuffer::new(),
                bc_forwarding_buffer: PacketBuffer::new(),
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
            did_something |= self.socket_ingress(core, device, sockets);
            did_something |= self.socket_egress(core, device, sockets);

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

        sockets
            .items()
            .filter_map(move |item| {
                let socket_poll_at = item.socket.poll_at(inner);
                match socket_poll_at {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::ZERO),
                }
            })
            .min()
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
            };

            rx_token.consume(|frame| {
                match self.inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        if let Some((dst_addr, packet)) =
                            self.inner.process_ethernet(srv, sockets, rx_meta, frame)
                        {
                            if let Err(err) = self.inner.dispatch(tx_token, dst_addr, packet) {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    Medium::Ieee80211p => todo!(),
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
                    net_debug!("failed to transmit IP: device exhausted");
                    EgressError::Exhausted
                })?;

                inner
                    .dispatch_geonet(t, meta, dst_ll_addr, response)
                    .map_err(EgressError::Dispatch)?;

                emitted_any = true;

                Ok(())
            };

            let srv: InterfaceServices<'_> = InterfaceServices {
                core,
                ls: &mut self.location_service,
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-geonet")]
                Socket::Geonet(socket) => socket.dispatch(
                    &mut self.inner,
                    srv,
                    |inner, core, (dst_ll_addr, ip, raw)| {
                        respond(
                            inner,
                            core,
                            PacketMeta::default(),
                            dst_ll_addr,
                            GeonetPacket::new(ip, GeonetPayload::Raw(raw)),
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
}

impl InterfaceInner {
    #[cfg(feature = "medium-ethernet")]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> HardwareAddress {
        self.hardware_addr
    }

    /// Return the current sequence number value and increment it.
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(super) fn sequence_number(&mut self) -> SequenceNumber {
        let sn = self.sequence_number.clone();
        self.sequence_number += 1;
        sn
    }

    #[cfg(feature = "medium-ethernet")]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Hardware address {addr} is not unicast")
        }
    }

    #[cfg(feature = "socket-geonet")]
    fn raw_socket_filter(
        &mut self,
        sockets: &mut SocketSet,
        indication: Indication,
        payload: &[u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for raw_socket in sockets
            .items_mut()
            .filter_map(|i| GeonetSocket::downcast_mut(&mut i.socket))
        {
            raw_socket.process(self, indication, payload);
            handled_by_raw_socket = true;
        }
        handled_by_raw_socket
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        dst_hardware_addr: EthernetAddress,
        packet: EthernetPacket,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
    {
        match packet {
            EthernetPacket::Geonet(packet) => {
                self.dispatch_geonet(tx_token, PacketMeta::default(), dst_hardware_addr, packet)
            }
        }
    }

    fn dispatch_geonet<Tx: TxToken>(
        &mut self,
        // NOTE(unused_mut): tx_token isn't always mutated, depending on
        // the feature set that is used.
        #[allow(unused_mut)] mut tx_token: Tx,
        meta: PacketMeta,
        dst_hardware_addr: EthernetAddress,
        packet: GeonetPacket,
    ) -> Result<(), DispatchError> {
        let mut gn_repr = packet.geonet_repr();

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
        let emit_ethernet = |repr: &GeonetRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);
            frame.set_ethertype(EthernetProtocol::Geonet);
        };

        // Emit function for the IP header and payload.
        let emit_ip = |repr: &GeonetRepr, mut tx_buffer: &mut [u8]| {
            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps)
        };

        tx_token.set_meta(meta);
        tx_token.consume(total_len, |mut tx_buffer| {
            #[cfg(feature = "medium-ethernet")]
            if matches!(self.caps.medium, Medium::Ethernet) {
                emit_ethernet(&gn_repr, tx_buffer);
                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
            }

            emit_ip(&gn_repr, tx_buffer);
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum DispatchError {
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
