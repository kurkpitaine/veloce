/*! Communication between endpoints.

The `socket` module deals with *network endpoints* and *buffering*.
It provides interfaces for accessing buffers of data, and protocol state machines
for filling and emptying these buffers.

The programming interface implemented here differs greatly from the common Berkeley socket
interface. Specifically, in the Berkeley interface the buffering is implicit:
the operating system decides on the good size for a buffer and manages it.
The interface implemented by this module uses explicit buffering: you decide on the good
size for a buffer, allocate it, and let the networking stack use it.
*/

use crate::iface::Context;
use crate::time::Instant;

#[cfg(feature = "socket-geonet")]
pub mod geonet;

#[cfg(any(feature = "socket-btp-a", feature = "socket-btp-b"))]
pub mod btp;

#[cfg(feature = "socket-cam")]
pub mod cam;

#[cfg(feature = "async")]
mod waker;

#[cfg(feature = "async")]
pub(crate) use self::waker::WakerRegistration;

/// Gives an indication on the next time the socket should be polled.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum PollAt {
    /// The socket needs to be polled immediately.
    Now,
    /// The socket needs to be polled at given [Instant][struct.Instant].
    #[allow(unused)]
    Time(Instant),
    /// The socket does not need to be polled unless there are external changes.
    Ingress,
}

/// A network socket.
///
/// This enumeration abstracts the various types of sockets based on the IP protocol.
/// To downcast a `Socket` value to a concrete socket, use the [AnySocket] trait,
/// e.g. to get `udp::Socket`, call `udp::Socket::downcast(socket)`.
///
/// It is usually more convenient to use [SocketSet::get] instead.
///
/// [AnySocket]: trait.AnySocket.html
/// [SocketSet::get]: struct.SocketSet.html#method.get
#[derive(Debug)]
pub enum Socket<'a> {
    #[cfg(feature = "socket-geonet")]
    Geonet(geonet::Socket<'a>),
    #[cfg(feature = "socket-btp-a")]
    BtpA(btp::SocketA<'a>),
    #[cfg(feature = "socket-btp-b")]
    BtpB(btp::SocketB<'a>),
    #[cfg(feature = "socket-cam")]
    Cam(cam::Socket<'a>),
}

impl<'a> Socket<'a> {
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        match self {
            #[cfg(feature = "socket-geonet")]
            Socket::Geonet(s) => s.poll_at(cx),
            #[cfg(feature = "socket-btp-a")]
            Socket::BtpA(s) => s.poll_at(cx),
            #[cfg(feature = "socket-btp-b")]
            Socket::BtpB(s) => s.poll_at(cx),
            #[cfg(feature = "socket-cam")]
            Socket::Cam(s) => s.poll_at(cx),
        }
    }
}

/// A conversion trait for network sockets.
pub trait AnySocket<'a> {
    fn upcast(self) -> Socket<'a>;
    fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self>
    where
        Self: Sized;
    fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self>
    where
        Self: Sized;
}

macro_rules! from_socket {
    ($socket:ty, $variant:ident) => {
        impl<'a> AnySocket<'a> for $socket {
            fn upcast(self) -> Socket<'a> {
                Socket::$variant(self)
            }

            fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self> {
                #[allow(unreachable_patterns)]
                match socket {
                    Socket::$variant(socket) => Some(socket),
                    _ => None,
                }
            }

            fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self> {
                #[allow(unreachable_patterns)]
                match socket {
                    Socket::$variant(socket) => Some(socket),
                    _ => None,
                }
            }
        }
    };
}

#[cfg(feature = "socket-geonet")]
from_socket!(geonet::Socket<'a>, Geonet);
#[cfg(feature = "socket-btp-a")]
from_socket!(btp::SocketA<'a>, BtpA);
#[cfg(feature = "socket-btp-b")]
from_socket!(btp::SocketB<'a>, BtpB);
#[cfg(feature = "socket-cam")]
from_socket!(cam::Socket<'a>, Cam);

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    Unaddressable,
    SizeTooLong,
    LifetimeTooHigh,
    AreaTooBig,
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendError::Unaddressable => write!(f, "unadressable"),
            SendError::SizeTooLong => write!(f, "size too long"),
            SendError::LifetimeTooHigh => write!(f, "lifetime too high"),
            SendError::AreaTooBig => write!(f, "area size too big"),
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendError {}
