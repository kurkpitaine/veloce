use core::fmt;

use crate::geonet::common::PacketBufferMeta;
use crate::geonet::time::Duration;
use crate::geonet::wire::{
    BasicHeader, BasicHeaderRepr, BeaconHeader, BeaconHeaderRepr, CommonHeader, CommonHeaderRepr,
    GeoAnycastHeader, GeoAnycastRepr, GeoBroadcastHeader, GeoBroadcastRepr,
    LocationServiceReplyHeader, LocationServiceReplyRepr, LocationServiceRequestHeader,
    LocationServiceRequestRepr, LongPositionVectorRepr as LongPositionVector, SingleHopHeader,
    SingleHopHeaderRepr, TopoBroadcastHeader, TopoBroadcastRepr, UnicastHeader, UnicastRepr,
};

enum_with_unknown! {
   /// Geonetworking Next Header value as carried inside the Common Header.
   pub enum Protocol(u8) {
       Any = 0,
       BtpA = 1,
       BtpB = 2,
       Ipv6 = 3,
   }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Protocol::Any => write!(f, "Any Header"),
            Protocol::BtpA => write!(f, "Btp-A"),
            Protocol::BtpB => write!(f, "Btp-B"),
            Protocol::Ipv6 => write!(f, "Ipv6"),
            Protocol::Unknown(id) => write!(f, "0x{:02x}", id),
        }
    }
}

/// A Geonetworking packet representation.
///
/// This enum abstracts the various headers of Geonetworking packets.
/// It contains the [BasicHeaderRepr], the [CommonHeaderRepr] and the
/// `extended_header` which is the variant of the packet.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr {
    /// Beacon packet.
    Beacon(GeonetBeacon),
    /// Unicast packet.
    Unicast(GeonetUnicast),
    /// Anycast packet.
    Anycast(GeonetGeoAnycast),
    /// Broadcast packet.
    Broadcast(GeonetGeoBroadcast),
    /// Single Hop Broadcast packet.
    SingleHopBroadcast(GeonetSingleHop),
    /// Topologically Scoped Broadcast packet.
    TopoBroadcast(GeonetTopoBroadcast),
    /// Location Service Request packet.
    LocationServiceRequest(GeonetLocationServiceRequest),
    /// Location Service Reply packet.
    LocationServiceReply(GeonetLocationServiceReply),
}

macro_rules! make_repr {
    ($variant: ident, $gn: ident, $repr: ident, $hdr: ident) => {
        #[derive(Debug, Clone, PartialEq)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct $gn {
            pub basic_header: BasicHeaderRepr,
            pub common_header: CommonHeaderRepr,
            pub extended_header: $repr,
        }

        impl $gn {
            pub fn new(
                basic_header: BasicHeaderRepr,
                common_header: CommonHeaderRepr,
                extended_header: $repr,
            ) -> Self {
                Self {
                    basic_header,
                    common_header,
                    extended_header,
                }
            }

            pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
                let mut bh = BasicHeader::new_unchecked(buffer);
                self.basic_header.emit(&mut bh);
                let mut ch = CommonHeader::new_unchecked(bh.payload_mut());
                self.common_header.emit(&mut ch);
                let mut eh = $hdr::new_unchecked(ch.payload_mut());
                self.extended_header.emit(&mut eh);
            }
        }

        impl PacketBufferMeta for $gn {
            fn size(&self) -> usize {
                self.basic_header.buffer_len()
                    + self.common_header.buffer_len()
                    + self.extended_header.buffer_len()
                    + self.common_header.payload_len
            }

            fn lifetime(&self) -> Duration {
                self.basic_header.lifetime
            }
        }

        impl From<$gn> for Repr {
            fn from(repr: $gn) -> Repr {
                Repr::$variant(repr)
            }
        }
    };
}

make_repr!(Beacon, GeonetBeacon, BeaconHeaderRepr, BeaconHeader);
make_repr!(Unicast, GeonetUnicast, UnicastRepr, UnicastHeader);
make_repr!(Anycast, GeonetGeoAnycast, GeoAnycastRepr, GeoAnycastHeader);
make_repr!(
    Broadcast,
    GeonetGeoBroadcast,
    GeoBroadcastRepr,
    GeoBroadcastHeader
);
make_repr!(
    SingleHopBroadcast,
    GeonetSingleHop,
    SingleHopHeaderRepr,
    SingleHopHeader
);
make_repr!(
    TopoBroadcast,
    GeonetTopoBroadcast,
    TopoBroadcastRepr,
    TopoBroadcastHeader
);
make_repr!(
    LocationServiceRequest,
    GeonetLocationServiceRequest,
    LocationServiceRequestRepr,
    LocationServiceRequestHeader
);
make_repr!(
    LocationServiceReply,
    GeonetLocationServiceReply,
    LocationServiceReplyRepr,
    LocationServiceReplyHeader
);

impl Repr {
    /// Constructs a new Beaconing packet.
    pub(crate) fn new_beacon(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        beacon_header: BeaconHeaderRepr,
    ) -> Self {
        Self::Beacon(GeonetBeacon {
            basic_header,
            common_header,
            extended_header: beacon_header,
        })
    }

    /// Constructs a new Unicast packet.
    pub(crate) fn new_unicast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        unicast_header: UnicastRepr,
    ) -> Self {
        Self::Unicast(GeonetUnicast {
            basic_header,
            common_header,
            extended_header: unicast_header,
        })
    }

    /// Constructs a new Anycast packet.
    pub(crate) fn new_anycast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        anycast_header: GeoAnycastRepr,
    ) -> Self {
        Self::Anycast(GeonetGeoAnycast {
            basic_header,
            common_header,
            extended_header: anycast_header,
        })
    }

    /// Constructs a new Broadcast packet.
    pub(crate) fn new_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        broadcast_header: GeoBroadcastRepr,
    ) -> Self {
        Self::Broadcast(GeonetGeoBroadcast {
            basic_header,
            common_header,
            extended_header: broadcast_header,
        })
    }

    /// Constructs a new Single Hop Broadcast packet.
    pub(crate) fn new_single_hop_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        shb_header: SingleHopHeaderRepr,
    ) -> Self {
        Self::SingleHopBroadcast(GeonetSingleHop {
            basic_header,
            common_header,
            extended_header: shb_header,
        })
    }

    /// Constructs a new Topologically Scoped Broadcast packet.
    pub(crate) fn new_topo_scoped_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        tsb_header: TopoBroadcastRepr,
    ) -> Self {
        Self::TopoBroadcast(GeonetTopoBroadcast {
            basic_header,
            common_header,
            extended_header: tsb_header,
        })
    }

    /// Constructs a new Location Service Request packet.
    pub(crate) fn new_location_service_request(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_req_header: LocationServiceRequestRepr,
    ) -> Self {
        Self::LocationServiceRequest(GeonetLocationServiceRequest {
            basic_header,
            common_header,
            extended_header: ls_req_header,
        })
    }

    /// Constructs a new Location Service Reply packet.
    pub(crate) fn new_location_service_reply(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_rep_header: LocationServiceReplyRepr,
    ) -> Self {
        Self::LocationServiceReply(GeonetLocationServiceReply {
            basic_header,
            common_header,
            extended_header: ls_rep_header,
        })
    }

    /// Return the next header (protocol).
    pub const fn next_header(&self) -> Protocol {
        match self {
            Repr::Beacon(repr) => repr.common_header.next_header,
            Repr::Unicast(repr) => repr.common_header.next_header,
            Repr::Anycast(repr) => repr.common_header.next_header,
            Repr::Broadcast(repr) => repr.common_header.next_header,
            Repr::SingleHopBroadcast(repr) => repr.common_header.next_header,
            Repr::TopoBroadcast(repr) => repr.common_header.next_header,
            Repr::LocationServiceRequest(repr) => repr.common_header.next_header,
            Repr::LocationServiceReply(repr) => repr.common_header.next_header,
        }
    }

    /// Return the source position vector.
    pub const fn source_position_vector(&self) -> LongPositionVector {
        match self {
            Repr::Beacon(repr) => repr.extended_header.source_position_vector,
            Repr::Unicast(repr) => repr.extended_header.source_position_vector,
            Repr::Anycast(repr) => repr.extended_header.source_position_vector,
            Repr::Broadcast(repr) => repr.extended_header.source_position_vector,
            Repr::SingleHopBroadcast(repr) => repr.extended_header.source_position_vector,
            Repr::TopoBroadcast(repr) => repr.extended_header.source_position_vector,
            Repr::LocationServiceRequest(repr) => repr.extended_header.source_position_vector,
            Repr::LocationServiceReply(repr) => repr.extended_header.source_position_vector,
        }
    }

    /// Return the payload length.
    pub const fn payload_len(&self) -> usize {
        match self {
            Repr::Beacon(repr) => repr.common_header.payload_len,
            Repr::Unicast(repr) => repr.common_header.payload_len,
            Repr::Anycast(repr) => repr.common_header.payload_len,
            Repr::Broadcast(repr) => repr.common_header.payload_len,
            Repr::SingleHopBroadcast(repr) => repr.common_header.payload_len,
            Repr::TopoBroadcast(repr) => repr.common_header.payload_len,
            Repr::LocationServiceRequest(repr) => repr.common_header.payload_len,
            Repr::LocationServiceReply(repr) => repr.common_header.payload_len,
        }
    }

    /// Set the payload length.
    pub fn set_payload_len(&mut self, length: usize) {
        match self {
            Repr::Beacon(repr) => repr.common_header.payload_len = length,
            Repr::Unicast(repr) => repr.common_header.payload_len = length,
            Repr::Anycast(repr) => repr.common_header.payload_len = length,
            Repr::Broadcast(repr) => repr.common_header.payload_len = length,
            Repr::SingleHopBroadcast(repr) => repr.common_header.payload_len = length,
            Repr::TopoBroadcast(repr) => repr.common_header.payload_len = length,
            Repr::LocationServiceRequest(repr) => repr.common_header.payload_len = length,
            Repr::LocationServiceReply(repr) => repr.common_header.payload_len = length,
        }
    }

    /// Return the remaining hop limit.
    pub const fn hop_limit(&self) -> u8 {
        match self {
            Repr::Beacon(repr) => repr.basic_header.remaining_hop_limit,
            Repr::Unicast(repr) => repr.basic_header.remaining_hop_limit,
            Repr::Anycast(repr) => repr.basic_header.remaining_hop_limit,
            Repr::Broadcast(repr) => repr.basic_header.remaining_hop_limit,
            Repr::SingleHopBroadcast(repr) => repr.basic_header.remaining_hop_limit,
            Repr::TopoBroadcast(repr) => repr.basic_header.remaining_hop_limit,
            Repr::LocationServiceRequest(repr) => repr.basic_header.remaining_hop_limit,
            Repr::LocationServiceReply(repr) => repr.basic_header.remaining_hop_limit,
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub const fn header_len(&self) -> usize {
        match self {
            Repr::Beacon(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Repr::Unicast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Repr::Anycast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Repr::Broadcast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Repr::SingleHopBroadcast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Repr::TopoBroadcast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Repr::LocationServiceRequest(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Repr::LocationServiceReply(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
        }
    }

    /// Emit this high-level representation into a buffer.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
        match self {
            Repr::Beacon(repr) => repr.emit(buffer),
            Repr::Unicast(repr) => repr.emit(buffer),
            Repr::Anycast(repr) => repr.emit(buffer),
            Repr::Broadcast(repr) => repr.emit(buffer),
            Repr::SingleHopBroadcast(repr) => repr.emit(buffer),
            Repr::TopoBroadcast(repr) => repr.emit(buffer),
            Repr::LocationServiceRequest(repr) => repr.emit(buffer),
            Repr::LocationServiceReply(repr) => repr.emit(buffer),
        }
    }

    /// Return the total length of a packet that will be emitted from this
    /// high-level representation.
    ///
    /// This is the same as `repr.buffer_len() + repr.payload_len()`.
    pub const fn buffer_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }
}

impl PacketBufferMeta for Repr {
    fn size(&self) -> usize {
        match self {
            Repr::Beacon(repr) => repr.size(),
            Repr::Unicast(repr) => repr.size(),
            Repr::Anycast(repr) => repr.size(),
            Repr::Broadcast(repr) => repr.size(),
            Repr::SingleHopBroadcast(repr) => repr.size(),
            Repr::TopoBroadcast(repr) => repr.size(),
            Repr::LocationServiceRequest(repr) => repr.size(),
            Repr::LocationServiceReply(repr) => repr.size(),
        }
    }

    fn lifetime(&self) -> Duration {
        match self {
            Repr::Beacon(repr) => repr.lifetime(),
            Repr::Unicast(repr) => repr.lifetime(),
            Repr::Anycast(repr) => repr.lifetime(),
            Repr::Broadcast(repr) => repr.lifetime(),
            Repr::SingleHopBroadcast(repr) => repr.lifetime(),
            Repr::TopoBroadcast(repr) => repr.lifetime(),
            Repr::LocationServiceRequest(repr) => repr.lifetime(),
            Repr::LocationServiceReply(repr) => repr.lifetime(),
        }
    }
}
