use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use uom::si::area::square_kilometer;
use uom::si::f32::Area;

use crate::geonet::config;
use crate::geonet::iface::{Context, ContextMeta};
use crate::geonet::network::{
    GeoAnycastReqMeta, GeoBroadcastReqMeta, GnCore, Indication, Request, SingleHopReqMeta,
    TopoScopedReqMeta, Transport, UnicastReqMeta,
};
use crate::geonet::socket::PollAt;
#[cfg(feature = "async")]
use crate::geonet::socket::WakerRegistration;

use crate::geonet::storage::Empty;
use crate::geonet::wire::{EthernetAddress, GeonetRepr};

use super::SendError;

/* /// Error returned by [`Socket::bind`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BindError {
    InvalidState,
    Unaddressable,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BindError {} */

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecvError {
    Exhausted,
}

impl core::fmt::Display for RecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecvError {}

/// Packet metadata.
pub type RxPacketMetadata = crate::geonet::storage::PacketMetadata<Indication>;
pub type TxPacketMetadata = crate::geonet::storage::PacketMetadata<Request>;

/// Packet ring buffer.
pub type RxPacketBuffer<'a> = crate::geonet::storage::PacketBuffer<'a, Indication>;
pub type TxPacketBuffer<'a> = crate::geonet::storage::PacketBuffer<'a, Request>;

/// A Geonetworking socket.
///
/// A geonet socket is bound to the Geonetworking protocol, and owns
/// transmit and receive packet buffers.
#[derive(Debug)]
pub struct Socket<'a> {
    rx_buffer: RxPacketBuffer<'a>,
    tx_buffer: TxPacketBuffer<'a>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl<'a> Socket<'a> {
    /// Create a geonet socket with the given buffers.
    pub fn new(rx_buffer: RxPacketBuffer<'a>, tx_buffer: TxPacketBuffer<'a>) -> Socket<'a> {
        Socket {
            rx_buffer,
            tx_buffer,
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Return the maximum number packets the socket can receive.
    #[inline]
    pub fn packet_recv_capacity(&self) -> usize {
        self.rx_buffer.packet_capacity()
    }

    /// Return the maximum number packets the socket can transmit.
    #[inline]
    pub fn packet_send_capacity(&self) -> usize {
        self.tx_buffer.packet_capacity()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn payload_recv_capacity(&self) -> usize {
        self.rx_buffer.payload_capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn payload_send_capacity(&self) -> usize {
        self.tx_buffer.payload_capacity()
    }

    /// Enqueue a packet to send, and return a pointer to its payload.
    ///
    /// This function returns `Err(SendError::SizeTooLong)` if packet size is too long,
    /// `Err(SendError::LifetimeTooHigh)` if packet lifetime is too high,
    /// `Err(SendError::AreaTooBig)` if the packet contains a destination area size which is too big,
    /// `Err(SendError::BufferFull)` if the transmit buffer is full,
    /// or if there is not enough transmit buffer capacity to ever send this packet.
    pub fn send(&mut self, size: usize, meta: Request) -> Result<&mut [u8], SendError> {
        if size > config::GN_MAX_SDU_SIZE {
            return Err(SendError::SizeTooLong);
        }
        if meta.max_lifetime > config::GN_MAX_PACKET_LIFETIME {
            return Err(SendError::LifetimeTooHigh);
        }
        match meta.transport {
            Transport::Anycast(a) | Transport::Broadcast(a)
                if a.size() > Area::new::<square_kilometer>(config::GN_MAX_GEO_AREA_SIZE) =>
            {
                return Err(SendError::AreaTooBig)
            }
            _ => {}
        };

        let packet_buf = self
            .tx_buffer
            .enqueue(size, meta)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!("gn: buffer to send {} octets", packet_buf.len());
        Ok(packet_buf)
    }

    /// Enqueue a packet to be send and pass the buffer to the provided closure.
    /// The closure then returns the size of the data written into the buffer.
    ///
    /// Also see [send](#method.send).
    pub fn send_with<F>(&mut self, max_size: usize, meta: Request, f: F) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        if max_size > config::GN_MAX_SDU_SIZE {
            return Err(SendError::SizeTooLong);
        }
        if meta.max_lifetime > config::GN_MAX_PACKET_LIFETIME {
            return Err(SendError::LifetimeTooHigh);
        }
        match meta.transport {
            Transport::Anycast(a) | Transport::Broadcast(a)
                if a.size() > Area::new::<square_kilometer>(config::GN_MAX_GEO_AREA_SIZE) =>
            {
                return Err(SendError::AreaTooBig)
            }
            _ => {}
        };

        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, meta, f)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!("gn: buffer to send {} octets", size);

        Ok(size)
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], meta: Request) -> Result<(), SendError> {
        self.send(data.len(), meta)?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], Indication), RecvError> {
        let (indication, packet_buf) =
            self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!("gn: receive {} buffered octets", packet_buf.len());
        Ok((packet_buf, indication))
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, Indication), RecvError> {
        let (buffer, indication) = self.recv()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, indication))
    }

    /// Peek at a packet in the receive buffer and return a pointer to the
    /// payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn peek(&mut self) -> Result<(&[u8], &Indication), RecvError> {
        let (indication, packet_buf) = self.rx_buffer.peek().map_err(|_| RecvError::Exhausted)?;

        net_trace!("gn: receive {} buffered octets", packet_buf.len());

        Ok((packet_buf, indication))
    }

    /// Peek at a packet in the receive buffer, copy the payload into the given slice,
    /// and return the amount of octets copied without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<(usize, &Indication), RecvError> {
        let (buffer, indication) = self.peek()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, indication))
    }

    pub(crate) fn process(&mut self, _cx: &mut Context, indication: Indication, payload: &[u8]) {
        net_trace!("gn: receiving {} octets", payload.len());

        match self.rx_buffer.enqueue(payload.len(), indication) {
            Ok(buf) => {
                buf.copy_from_slice(payload);
            }
            Err(_) => net_trace!("gn: buffer full, dropped incoming packet"),
        }

        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }

    pub(crate) fn dispatch<F, E>(
        &mut self,
        cx: &mut Context,
        srv: ContextMeta,
        emit: F,
    ) -> Result<(), E>
    where
        F: FnOnce(&mut Context, &mut GnCore, (EthernetAddress, GeonetRepr, &[u8])) -> Result<(), E>,
    {
        let res = self.tx_buffer.dequeue_with(|&mut req, payload_buf| {
            net_trace!("gn: sending {} octets", payload_buf.len());

            match req.transport {
                Transport::Unicast(destination) => {
                    let meta = UnicastReqMeta::new(
                        req.upper_proto,
                        destination,
                        req.ali_id,
                        req.its_aid,
                        req.max_lifetime,
                        req.max_hop_limit,
                        req.traffic_class,
                    );
                    cx.dispatch_unicast(
                        srv,
                        meta,
                        payload_buf,
                        |cx, core, (dst_ll_addr, bh_repr, ch_repr, uc_repr, pl)| {
                            let gn_repr = GeonetRepr::new_unicast(bh_repr, ch_repr, uc_repr);
                            emit(cx, core, (dst_ll_addr, gn_repr, pl))
                        },
                    )
                }
                Transport::Anycast(destination) => {
                    let meta = GeoAnycastReqMeta::new(
                        req.upper_proto,
                        destination,
                        req.ali_id,
                        req.its_aid,
                        req.max_lifetime,
                        req.max_hop_limit,
                        req.traffic_class,
                    );
                    cx.dispatch_geo_anycast(
                        srv,
                        meta,
                        payload_buf,
                        |cx, core, (dst_ll_addr, bh_repr, ch_repr, gac_repr, pl)| {
                            let gn_repr = GeonetRepr::new_anycast(bh_repr, ch_repr, gac_repr);
                            emit(cx, core, (dst_ll_addr, gn_repr, pl))
                        },
                    )
                }
                Transport::Broadcast(destination) => {
                    let meta = GeoBroadcastReqMeta::new(
                        req.upper_proto,
                        destination,
                        req.ali_id,
                        req.its_aid,
                        req.max_lifetime,
                        req.max_hop_limit,
                        req.traffic_class,
                    );
                    cx.dispatch_geo_broadcast(
                        srv,
                        meta,
                        payload_buf,
                        |cx, core, (dst_ll_addr, bh_repr, ch_repr, gac_repr, pl)| {
                            let gn_repr = GeonetRepr::new_broadcast(bh_repr, ch_repr, gac_repr);
                            emit(cx, core, (dst_ll_addr, gn_repr, pl))
                        },
                    )
                }
                Transport::SingleHopBroadcast => {
                    let meta = SingleHopReqMeta::new(
                        req.upper_proto,
                        req.ali_id,
                        req.its_aid,
                        req.max_lifetime,
                        req.max_hop_limit,
                        req.traffic_class,
                    );
                    cx.dispatch_single_hop_broadcast(
                        srv,
                        meta,
                        payload_buf,
                        |cx, core, (dst_ll_addr, bh_repr, ch_repr, shb_repr, pl)| {
                            let gn_repr =
                                GeonetRepr::new_single_hop_broadcast(bh_repr, ch_repr, shb_repr);
                            emit(cx, core, (dst_ll_addr, gn_repr, pl))
                        },
                    )
                }
                Transport::TopoBroadcast => {
                    let meta = TopoScopedReqMeta::new(
                        req.upper_proto,
                        req.ali_id,
                        req.its_aid,
                        req.max_lifetime,
                        req.max_hop_limit,
                        req.traffic_class,
                    );
                    cx.dispatch_topo_scoped_broadcast(
                        srv,
                        meta,
                        payload_buf,
                        |cx, core, (dst_ll_addr, bh_repr, ch_repr, tsb_repr, pl)| {
                            let gn_repr =
                                GeonetRepr::new_topo_scoped_broadcast(bh_repr, ch_repr, tsb_repr);
                            emit(cx, core, (dst_ll_addr, gn_repr, pl))
                        },
                    )
                }
            }
        });
        match res {
            Err(Empty) => Ok(()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => {
                #[cfg(feature = "async")]
                self.tx_waker.wake();
                Ok(())
            }
        }
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}
