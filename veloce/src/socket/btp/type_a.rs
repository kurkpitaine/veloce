use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use uom::si::area::square_kilometer;
use uom::si::f64::Area;

use super::{BindError, Endpoint, Indication, ListenEndpoint, RecvError, Request};
use crate::iface::packet::GeonetPacket;
use crate::iface::{Congestion, Context, ContextMeta};
use crate::network::{GnCore, Transport, UnicastReqMeta, UpperProtocol};
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;
use crate::socket::{PollAt, SendError};
use crate::{config, wire};

use crate::storage::Empty;
use crate::wire::{BtpAHeader, BtpARepr, EthernetAddress, GeonetUnicast};

/// Metadata for a sent or received BTP-A packet.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct BtpAMetadata {
    pub endpoint: Endpoint,
}

impl<T: Into<Endpoint>> From<T> for BtpAMetadata {
    fn from(value: T) -> Self {
        Self {
            endpoint: value.into(),
        }
    }
}

impl core::fmt::Display for BtpAMetadata {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.endpoint)
    }
}

/// A BTP-A packet metadata.
pub type RxPacketMetadata = crate::storage::PacketMetadata<(BtpAMetadata, Indication)>;
pub type TxPacketMetadata = crate::storage::PacketMetadata<(BtpAMetadata, Request)>;

/// A BTP-A packet ring buffer.
pub type RxPacketBuffer<'a> = crate::storage::PacketBuffer<'a, (BtpAMetadata, Indication)>;
pub type TxPacketBuffer<'a> = crate::storage::PacketBuffer<'a, (BtpAMetadata, Request)>;

/// A BTP-A type socket.
///
/// A BTP-A socket is bound to the BTP type B protocol, and owns
/// transmit and receive packet buffers.
#[derive(Debug)]
pub struct Socket<'a> {
    endpoint: ListenEndpoint,
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
            endpoint: ListenEndpoint::default(),
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

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> ListenEndpoint {
        self.endpoint
    }

    /// Bind the socket to the given port.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn bind<T: Into<ListenEndpoint>>(&mut self, endpoint: T) -> Result<(), BindError> {
        let endpoint = endpoint.into();
        if endpoint.port == 0 {
            return Err(BindError::Unaddressable);
        }

        if self.is_open() {
            return Err(BindError::InvalidState);
        }

        self.endpoint = endpoint;

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }

        Ok(())
    }

    /// Close the socket.
    pub fn close(&mut self) {
        // Clear the bound endpoint of the socket.
        self.endpoint = ListenEndpoint::default();

        // Reset the RX and TX buffers of the socket.
        self.tx_buffer.reset();
        self.rx_buffer.reset();

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    /// Check whether the socket is open.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.endpoint.port != 0
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
    pub fn send(
        &mut self,
        size: usize,
        meta: (impl Into<BtpAMetadata>, Request),
    ) -> Result<&mut [u8], SendError> {
        let (meta, req) = (meta.0.into(), meta.1);
        if self.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }

        let segment_len = size + wire::BTP_A_HEADER_LEN;
        if segment_len > config::GN_MAX_SDU_SIZE {
            return Err(SendError::SizeTooLong);
        }
        if req.max_lifetime > config::GN_MAX_PACKET_LIFETIME {
            return Err(SendError::LifetimeTooHigh);
        }
        /* match req.transport {
            Transport::Anycast(a) | Transport::Broadcast(a)
                if a.size() > Area::new::<square_kilometer>(config::GN_MAX_GEO_AREA_SIZE) =>
            {
                return Err(SendError::AreaTooBig)
            }
            _ => {}
        }; */

        let mut packet_buf = self
            .tx_buffer
            .enqueue(segment_len, (meta, req))
            .map_err(|_| SendError::BufferFull)?;

        // Serialize BTP header into buffer.
        // We need to serialize it early because it might be buffer
        // on the Geonetworking layer.
        let btp_repr = BtpARepr {
            dst_port: meta.endpoint.port,
            src_port: self.endpoint.port,
        };

        btp_repr.emit(&mut BtpAHeader::new_unchecked(&mut packet_buf));

        net_trace!(
            "BTP-A:{}:{}: buffer to send {} octets",
            self.endpoint,
            meta.endpoint,
            size
        );
        Ok(&mut packet_buf[wire::BTP_A_HEADER_LEN..])
    }

    /// Enqueue a packet to be send and pass the buffer to the provided closure.
    /// The closure then returns the size of the data written into the buffer.
    ///
    /// Also see [send](#method.send).
    pub fn send_with<F>(
        &mut self,
        max_size: usize,
        meta: (impl Into<BtpAMetadata>, Request),
        f: F,
    ) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let (meta, req) = (meta.0.into(), meta.1);
        if self.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }

        if max_size + wire::BTP_A_HEADER_LEN > config::GN_MAX_SDU_SIZE {
            return Err(SendError::SizeTooLong);
        }
        if req.max_lifetime > config::GN_MAX_PACKET_LIFETIME {
            return Err(SendError::LifetimeTooHigh);
        }
        match req.transport {
            Transport::Anycast(a) | Transport::Broadcast(a)
                if a.size() > Area::new::<square_kilometer>(config::GN_MAX_GEO_AREA_SIZE) =>
            {
                return Err(SendError::AreaTooBig)
            }
            _ => {}
        };

        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, (meta, req), |mut buf| {
                let btp_repr = BtpARepr {
                    dst_port: meta.endpoint.port,
                    src_port: self.endpoint.port,
                };

                btp_repr.emit(&mut BtpAHeader::new_unchecked(&mut buf));
                f(&mut buf[wire::BTP_A_HEADER_LEN..])
            })
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "BTP-A:{}:{}: buffer to send {} octets",
            self.endpoint,
            meta.endpoint,
            size
        );

        Ok(size)
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(
        &mut self,
        data: &[u8],
        meta: (impl Into<BtpAMetadata>, Request),
    ) -> Result<(), SendError> {
        self.send(data.len(), meta)?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], BtpAMetadata, Indication), RecvError> {
        let ((meta, indication), packet_buf) =
            self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "BTP-A:{}:{}: receive {} buffered octets",
            self.endpoint,
            meta.endpoint,
            packet_buf.len()
        );
        Ok((packet_buf, meta, indication))
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// the packet is dropped and a `RecvError::Truncated` error is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(
        &mut self,
        data: &mut [u8],
    ) -> Result<(usize, BtpAMetadata, Indication), RecvError> {
        let (buffer, meta, indication) = self.recv()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, meta, indication))
    }

    /// Peek at a packet in the receive buffer and return a pointer to the
    /// payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn peek(&mut self) -> Result<(&[u8], &BtpAMetadata, &Indication), RecvError> {
        let endpoint = self.endpoint;
        let ((remote_endpoint, indication), packet_buf) =
            self.rx_buffer.peek().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "BTP-A:{}:{}: peek {} buffered octets",
            endpoint,
            remote_endpoint.endpoint,
            packet_buf.len()
        );

        Ok((packet_buf, remote_endpoint, indication))
    }

    /// Peek at a packet in the receive buffer, copy the payload into the given slice,
    /// and return the amount of octets copied without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// no data is copied into the provided buffer and a `RecvError::Truncated` error is returned.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(
        &mut self,
        data: &mut [u8],
    ) -> Result<(usize, &BtpAMetadata, &Indication), RecvError> {
        let (buffer, remote_endpoint, indication) = self.peek()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, remote_endpoint, indication))
    }

    /// Query whether this BTP-A socket accepts the segment.
    pub(crate) fn accepts(
        &self,
        _cx: &mut Context,
        _srv: &ContextMeta,
        uc_repr: &GeonetUnicast,
        repr: &BtpARepr,
    ) -> bool {
        if self.endpoint.port != repr.dst_port {
            return false;
        }

        if self.endpoint.addr.is_some()
            && self.endpoint.addr != Some(uc_repr.extended_header.dst_addr())
        {
            return false;
        }

        true
    }

    /// Process a newly received BTP-A segment.
    /// Check if the socket must handle the segment with [Socket::accepts] before calling this function.
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        srv: &ContextMeta,
        indication: Indication,
        uc_repr: &GeonetUnicast,
        repr: &BtpARepr,
        payload: &[u8],
    ) {
        debug_assert!(self.accepts(cx, srv, uc_repr, repr));

        let size = payload.len();

        let remote_endpoint = Endpoint {
            addr: uc_repr.extended_header.src_addr(),
            port: repr.src_port,
        };

        net_trace!(
            "BTP-A:{}:{}: receiving {} octets",
            self.endpoint,
            remote_endpoint,
            size
        );

        let metadata = BtpAMetadata {
            endpoint: remote_endpoint,
        };

        match self
            .rx_buffer
            .enqueue(payload.len(), (metadata, indication))
        {
            Ok(buf) => {
                buf.copy_from_slice(payload);
            }
            Err(_) => net_trace!(
                "BTP-A:{}:{}: buffer full, dropped incoming packet",
                self.endpoint,
                remote_endpoint
            ),
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
        F: FnOnce(
            &mut Context,
            &mut GnCore,
            &mut Congestion,
            (EthernetAddress, GeonetPacket),
        ) -> Result<(), E>,
    {
        let res = self.tx_buffer.dequeue().map(|(req, payload_buf)| {
            let endpoint = self.endpoint;
            let (packet_meta, req) = req;

            net_trace!(
                "btp-a:{}:{}: sending {} octets",
                endpoint,
                packet_meta.endpoint,
                payload_buf.len()
            );

            #[cfg(feature = "proto-security")]
            let meta = UnicastReqMeta::new(
                UpperProtocol::BtpA,
                packet_meta.endpoint.addr,
                req.ali_id,
                req.its_aid.clone(),
                req.max_lifetime,
                req.max_hop_limit,
                req.traffic_class,
            );

            #[cfg(not(feature = "proto-security"))]
            let meta = UnicastReqMeta::new(
                UpperProtocol::BtpA,
                packet_meta.endpoint.addr,
                req.ali_id,
                req.max_lifetime,
                req.max_hop_limit,
                req.traffic_class,
            );
            cx.dispatch_unicast(
                srv,
                meta,
                payload_buf,
                |cx, core, congestion, (dst_ll_addr, pkt)| {
                    emit(cx, core, congestion, (dst_ll_addr, pkt))
                },
            )
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
