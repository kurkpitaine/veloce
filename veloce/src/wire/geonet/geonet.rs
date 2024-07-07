use core::fmt;

use crate::common::geo_area::{GeoArea, GeoPosition};
use crate::common::PacketBufferMeta;
use crate::network::Transport;
use crate::time::Duration;
use crate::wire::{
    BasicHeader, BasicHeaderRepr, BeaconHeader, BeaconHeaderRepr, CommonHeader, CommonHeaderRepr,
    GeoAnycastHeader, GeoAnycastRepr, GeoBroadcastHeader, GeoBroadcastRepr,
    LocationServiceReplyHeader, LocationServiceReplyRepr, LocationServiceRequestHeader,
    LocationServiceRequestRepr, LongPositionVectorRepr as LongPositionVector,
    ShortPositionVectorRepr as ShortPositionVector, SingleHopHeader, SingleHopHeaderRepr,
    TopoBroadcastHeader, TopoBroadcastRepr, UnicastHeader, UnicastRepr, BASIC_HEADER_LEN,
};

#[cfg(feature = "proto-security")]
use crate::security::{permission::Permission, secured_message::SecuredMessage};

use super::{Address, SequenceNumber, TrafficClass};

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

/// Geonetworking packet Repr.
#[derive(Debug, Clone, PartialEq)]
pub enum Repr<T: PacketBufferMeta> {
    /// Unsecured packet kind.
    Unsecured(T),
    #[cfg(feature = "proto-security")]
    /// Secured Decapsulated packet keeps the original packet representation,
    /// along with the secured message (which does not contain the basic header).
    SecuredDecap {
        repr: T,
        secured_message: SecuredMessage,
        secured_message_size: usize,
    },
    #[cfg(feature = "proto-security")]
    /// Secured packet keeps the original packet representation,
    /// along with its secured emitted representation (which does not contain the basic header).
    Secured { repr: T, encapsulated: Vec<u8> },
    #[cfg(feature = "proto-security")]
    /// Packet to be secured (has to be signed),
    ToSecure { repr: T, permission: Permission },
}

impl<T: PacketBufferMeta> Repr<T> {
    /// Query whether the packet is secured.
    pub(crate) fn is_secured(&self) -> bool {
        match self {
            #[cfg(feature = "proto-security")]
            Repr::SecuredDecap { .. } | Repr::Secured { .. } => true,
            _ => false,
        }
    }

    /// Get a reference on the underlying packet type.
    pub(crate) fn inner(&self) -> &T {
        match self {
            Repr::Unsecured(repr) => repr,
            #[cfg(feature = "proto-security")]
            Repr::SecuredDecap { repr, .. } => repr,
            #[cfg(feature = "proto-security")]
            Repr::Secured { repr, .. } => repr,
            #[cfg(feature = "proto-security")]
            Repr::ToSecure { repr, .. } => repr,
        }
    }

    /// Get a mutable reference on the underlying packet type.
    pub(crate) fn inner_mut(&mut self) -> &mut T {
        match self {
            Repr::Unsecured(repr) => repr,
            #[cfg(feature = "proto-security")]
            Repr::SecuredDecap { repr, .. } => repr,
            #[cfg(feature = "proto-security")]
            Repr::Secured { repr, .. } => repr,
            #[cfg(feature = "proto-security")]
            Repr::ToSecure { repr, .. } => repr,
        }
    }
}

impl<T: PacketBufferMeta> PacketBufferMeta for Repr<T> {
    fn size(&self) -> usize {
        match self {
            Repr::Unsecured(repr) => repr.size(),
            #[cfg(feature = "proto-security")]
            Repr::SecuredDecap {
                secured_message_size,
                ..
            } => BASIC_HEADER_LEN + secured_message_size,
            Repr::Secured { encapsulated, .. } => BASIC_HEADER_LEN + encapsulated.len(),
            #[cfg(feature = "proto-security")]
            Repr::ToSecure { repr, .. } => repr.size(),
        }
    }

    fn lifetime(&self) -> Duration {
        match self {
            Repr::Unsecured(repr) => repr.lifetime(),
            #[cfg(feature = "proto-security")]
            Repr::SecuredDecap { repr, .. } => repr.lifetime(),
            #[cfg(feature = "proto-security")]
            Repr::Secured { repr, .. } => repr.lifetime(),
            #[cfg(feature = "proto-security")]
            Repr::ToSecure { repr, .. } => repr.lifetime(),
        }
    }
}
/// A Geonetworking packet variant.
///
/// This enum abstracts the various headers of Geonetworking packets.
/// It contains the [BasicHeaderRepr], the [CommonHeaderRepr] and the
/// `extended_header` which is the variant of the packet.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Variant {
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

            #[cfg(feature = "proto-security")]
            pub fn emit_basic_header<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
                let mut bh = BasicHeader::new_unchecked(buffer);
                self.basic_header.emit(&mut bh);
            }

            #[cfg(feature = "proto-security")]
            pub fn emit_common_and_extended_header<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
                let mut ch = CommonHeader::new_unchecked(buffer);
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

        impl From<$gn> for Variant {
            fn from(repr: $gn) -> Variant {
                Variant::$variant(repr)
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

impl GeonetUnicast {
    /// Return the destination address contained inside the Unicast packet.
    pub const fn dst_addr(&self) -> Address {
        self.extended_header.dst_addr()
    }

    /// Set the lifetime of the packet.
    pub fn set_lifetime(&mut self, lifetime: Duration) {
        self.basic_header.lifetime = lifetime;
    }

    /// Get the source position vector of the packet.
    pub const fn source_position_vector(&self) -> LongPositionVector {
        self.extended_header.source_position_vector
    }

    /// Set the source position vector of the packet.
    pub fn set_source_position_vector(&mut self, spv: LongPositionVector) {
        self.extended_header.source_position_vector = spv;
    }

    /// Set the destination position vector of the packet.
    pub fn set_destination_position_vector(&mut self, dpv: ShortPositionVector) {
        self.extended_header.destination_position_vector = dpv;
    }
}

impl Variant {
    #[cfg(test)]
    pub(crate) fn basic_header(&self) -> BasicHeaderRepr {
        match self {
            Self::Beacon(b) => b.basic_header,
            Self::Unicast(u) => u.basic_header,
            Self::Anycast(a) => a.basic_header,
            Self::Broadcast(b) => b.basic_header,
            Self::SingleHopBroadcast(s) => s.basic_header,
            Self::TopoBroadcast(t) => t.basic_header,
            Self::LocationServiceRequest(l) => l.basic_header,
            Self::LocationServiceReply(l) => l.basic_header,
        }
    }

    #[cfg(test)]
    pub(crate) fn common_header(&self) -> CommonHeaderRepr {
        match self {
            Self::Beacon(b) => b.common_header,
            Self::Unicast(u) => u.common_header,
            Self::Anycast(a) => a.common_header,
            Self::Broadcast(b) => b.common_header,
            Self::SingleHopBroadcast(s) => s.common_header,
            Self::TopoBroadcast(t) => t.common_header,
            Self::LocationServiceRequest(l) => l.common_header,
            Self::LocationServiceReply(l) => l.common_header,
        }
    }

    /// Return the next protocol.
    pub const fn next_proto(&self) -> Protocol {
        match self {
            Self::Beacon(repr) => repr.common_header.next_header,
            Self::Unicast(repr) => repr.common_header.next_header,
            Self::Anycast(repr) => repr.common_header.next_header,
            Self::Broadcast(repr) => repr.common_header.next_header,
            Self::SingleHopBroadcast(repr) => repr.common_header.next_header,
            Self::TopoBroadcast(repr) => repr.common_header.next_header,
            Self::LocationServiceRequest(repr) => repr.common_header.next_header,
            Self::LocationServiceReply(repr) => repr.common_header.next_header,
        }
    }

    /// Return the source position vector.
    pub const fn source_position_vector(&self) -> LongPositionVector {
        match self {
            Self::Beacon(repr) => repr.extended_header.source_position_vector,
            Self::Unicast(repr) => repr.extended_header.source_position_vector,
            Self::Anycast(repr) => repr.extended_header.source_position_vector,
            Self::Broadcast(repr) => repr.extended_header.source_position_vector,
            Self::SingleHopBroadcast(repr) => repr.extended_header.source_position_vector,
            Self::TopoBroadcast(repr) => repr.extended_header.source_position_vector,
            Self::LocationServiceRequest(repr) => repr.extended_header.source_position_vector,
            Self::LocationServiceReply(repr) => repr.extended_header.source_position_vector,
        }
    }

    /// Set the source position vector.
    pub fn set_source_position_vector(&mut self, spv: LongPositionVector) {
        match self {
            Self::Beacon(repr) => repr.extended_header.source_position_vector = spv,
            Self::Unicast(repr) => repr.extended_header.source_position_vector = spv,
            Self::Anycast(repr) => repr.extended_header.source_position_vector = spv,
            Self::Broadcast(repr) => repr.extended_header.source_position_vector = spv,
            Self::SingleHopBroadcast(repr) => repr.extended_header.source_position_vector = spv,
            Self::TopoBroadcast(repr) => repr.extended_header.source_position_vector = spv,
            Self::LocationServiceRequest(repr) => repr.extended_header.source_position_vector = spv,
            Self::LocationServiceReply(repr) => repr.extended_header.source_position_vector = spv,
        }
    }

    /// Return the payload length.
    pub const fn payload_len(&self) -> usize {
        match self {
            Self::Beacon(repr) => repr.common_header.payload_len,
            Self::Unicast(repr) => repr.common_header.payload_len,
            Self::Anycast(repr) => repr.common_header.payload_len,
            Self::Broadcast(repr) => repr.common_header.payload_len,
            Self::SingleHopBroadcast(repr) => repr.common_header.payload_len,
            Self::TopoBroadcast(repr) => repr.common_header.payload_len,
            Self::LocationServiceRequest(repr) => repr.common_header.payload_len,
            Self::LocationServiceReply(repr) => repr.common_header.payload_len,
        }
    }

    /// Set the payload length.
    pub fn set_payload_len(&mut self, length: usize) {
        match self {
            Self::Beacon(repr) => repr.common_header.payload_len = length,
            Self::Unicast(repr) => repr.common_header.payload_len = length,
            Self::Anycast(repr) => repr.common_header.payload_len = length,
            Self::Broadcast(repr) => repr.common_header.payload_len = length,
            Self::SingleHopBroadcast(repr) => repr.common_header.payload_len = length,
            Self::TopoBroadcast(repr) => repr.common_header.payload_len = length,
            Self::LocationServiceRequest(repr) => repr.common_header.payload_len = length,
            Self::LocationServiceReply(repr) => repr.common_header.payload_len = length,
        }
    }

    /// Return the remaining hop limit.
    pub const fn hop_limit(&self) -> u8 {
        match self {
            Self::Beacon(repr) => repr.basic_header.remaining_hop_limit,
            Self::Unicast(repr) => repr.basic_header.remaining_hop_limit,
            Self::Anycast(repr) => repr.basic_header.remaining_hop_limit,
            Self::Broadcast(repr) => repr.basic_header.remaining_hop_limit,
            Self::SingleHopBroadcast(repr) => repr.basic_header.remaining_hop_limit,
            Self::TopoBroadcast(repr) => repr.basic_header.remaining_hop_limit,
            Self::LocationServiceRequest(repr) => repr.basic_header.remaining_hop_limit,
            Self::LocationServiceReply(repr) => repr.basic_header.remaining_hop_limit,
        }
    }

    /// Return the lifetime of the packet.
    pub const fn lifetime(&self) -> Duration {
        match self {
            Self::Beacon(repr) => repr.basic_header.lifetime,
            Self::Unicast(repr) => repr.basic_header.lifetime,
            Self::Anycast(repr) => repr.basic_header.lifetime,
            Self::Broadcast(repr) => repr.basic_header.lifetime,
            Self::SingleHopBroadcast(repr) => repr.basic_header.lifetime,
            Self::TopoBroadcast(repr) => repr.basic_header.lifetime,
            Self::LocationServiceRequest(repr) => repr.basic_header.lifetime,
            Self::LocationServiceReply(repr) => repr.basic_header.lifetime,
        }
    }

    /// Sets the lifetime of the packet.
    pub fn set_lifetime(&mut self, lifetime: Duration) {
        match self {
            Self::Beacon(repr) => repr.basic_header.lifetime = lifetime,
            Self::Unicast(repr) => repr.basic_header.lifetime = lifetime,
            Self::Anycast(repr) => repr.basic_header.lifetime = lifetime,
            Self::Broadcast(repr) => repr.basic_header.lifetime = lifetime,
            Self::SingleHopBroadcast(repr) => repr.basic_header.lifetime = lifetime,
            Self::TopoBroadcast(repr) => repr.basic_header.lifetime = lifetime,
            Self::LocationServiceRequest(repr) => repr.basic_header.lifetime = lifetime,
            Self::LocationServiceReply(repr) => repr.basic_header.lifetime = lifetime,
        }
    }

    /// Return the traffic class field of the packet.
    pub const fn traffic_class(&self) -> TrafficClass {
        match self {
            Self::Beacon(repr) => repr.common_header.traffic_class,
            Self::Unicast(repr) => repr.common_header.traffic_class,
            Self::Anycast(repr) => repr.common_header.traffic_class,
            Self::Broadcast(repr) => repr.common_header.traffic_class,
            Self::SingleHopBroadcast(repr) => repr.common_header.traffic_class,
            Self::TopoBroadcast(repr) => repr.common_header.traffic_class,
            Self::LocationServiceRequest(repr) => repr.common_header.traffic_class,
            Self::LocationServiceReply(repr) => repr.common_header.traffic_class,
        }
    }

    /// Return the packet transport type.
    /// # Panics
    ///
    /// This method panics when packet is any of [`Self::Beacon`],
    /// [`Self::LocationServiceRequest`] or [`Self::LocationServiceReply`] type.
    pub const fn transport(&self) -> Transport {
        match self {
            Self::Unicast(repr) => Transport::Unicast(repr.extended_header.dst_addr()),
            Self::Anycast(repr) => Transport::Anycast(GeoArea::from_gac(
                &repr.common_header.header_type,
                &repr.extended_header,
            )),
            Self::Broadcast(repr) => Transport::Broadcast(GeoArea::from_gbc(
                &repr.common_header.header_type,
                &repr.extended_header,
            )),
            Self::SingleHopBroadcast(_) => Transport::SingleHopBroadcast,
            Self::TopoBroadcast(_) => Transport::TopoBroadcast,
            _ => panic!(),
        }
    }

    /// Returns the source Geonetworking address contained inside the packet.
    pub(crate) fn source_address(&self) -> Address {
        match self {
            Self::Beacon(p) => p.extended_header.source_position_vector.address,
            Self::Unicast(p) => p.extended_header.source_position_vector.address,
            Self::Anycast(p) => p.extended_header.source_position_vector.address,
            Self::Broadcast(p) => p.extended_header.source_position_vector.address,
            Self::SingleHopBroadcast(p) => p.extended_header.source_position_vector.address,
            Self::TopoBroadcast(p) => p.extended_header.source_position_vector.address,
            Self::LocationServiceRequest(p) => p.extended_header.source_position_vector.address,
            Self::LocationServiceReply(p) => p.extended_header.source_position_vector.address,
        }
    }

    /// Returns the sequence number the packet.
    ///
    /// # Panics
    ///
    /// This method panics if the packet does not contain a sequence number.
    pub(crate) fn sequence_number(&self) -> SequenceNumber {
        match self {
            Self::Beacon(_) => panic!("No sequence number in a Beacon packet!"),
            Self::SingleHopBroadcast(_) => panic!("No sequence number in a SHB packet!"),
            Self::Unicast(p) => p.extended_header.sequence_number,
            Self::Anycast(p) => p.extended_header.sequence_number,
            Self::Broadcast(p) => p.extended_header.sequence_number,
            Self::TopoBroadcast(p) => p.extended_header.sequence_number,
            Self::LocationServiceRequest(p) => p.extended_header.sequence_number,
            Self::LocationServiceReply(p) => p.extended_header.sequence_number,
        }
    }

    /// Returns the destination for packet types containing a destination target,
    /// ie: a destination position vector or a destination area.
    ///
    /// # Panics
    ///
    /// This method panics if the packet does not contain a destination.
    pub(crate) fn geo_destination(&self) -> GeoPosition {
        match self {
            Self::Beacon(_) => panic!("No geo destination in a Beacon packet!"),
            Self::SingleHopBroadcast(_) => panic!("No geo destination in a SHB packet!"),
            Self::TopoBroadcast(_) => panic!("No geo destination in a TSB packet!"),
            Self::LocationServiceRequest(_) => {
                panic!("No geo destination in a LS request packet!")
            }
            Self::Unicast(u) => GeoPosition {
                latitude: u.extended_header.destination_position_vector.latitude,
                longitude: u.extended_header.destination_position_vector.longitude,
            },
            Self::Anycast(a) => GeoPosition {
                latitude: a.extended_header.latitude,
                longitude: a.extended_header.longitude,
            },
            Self::Broadcast(b) => GeoPosition {
                latitude: b.extended_header.latitude,
                longitude: b.extended_header.longitude,
            },
            Self::LocationServiceReply(r) => GeoPosition {
                latitude: r.extended_header.destination_position_vector.latitude,
                longitude: r.extended_header.destination_position_vector.longitude,
            },
        }
    }

    /// Returns the destination area for Anycast and Broadcast packet types.
    ///
    /// # Panics
    ///
    /// This method panics if the packet does not contain a destination area.
    pub(crate) fn geo_area(&self) -> GeoArea {
        match self {
            Self::Beacon(_) => panic!("No geo area in a Beacon packet!"),
            Self::SingleHopBroadcast(_) => {
                panic!("No geo area in a SHB packet!")
            }
            Self::TopoBroadcast(_) => panic!("No geo area in a TSB packet!"),
            Self::LocationServiceRequest(_) => {
                panic!("No geo area in a LS request packet!")
            }
            Self::LocationServiceReply(_) => {
                panic!("No geo area in a LS reply packet!")
            }
            Self::Unicast(_) => panic!("No geo area in a Unicast packet!"),
            Self::Anycast(a) => GeoArea::from_gac(&a.common_header.header_type, &a.extended_header),
            Self::Broadcast(b) => {
                GeoArea::from_gbc(&b.common_header.header_type, &b.extended_header)
            }
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub const fn header_len(&self) -> usize {
        match self {
            Self::Beacon(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Self::Unicast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Self::Anycast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Self::Broadcast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Self::SingleHopBroadcast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Self::TopoBroadcast(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Self::LocationServiceRequest(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
            Self::LocationServiceReply(repr) => {
                repr.basic_header.buffer_len()
                    + repr.common_header.buffer_len()
                    + repr.extended_header.buffer_len()
            }
        }
    }

    /// Emit this high-level representation into a buffer.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
        match self {
            Self::Beacon(repr) => repr.emit(buffer),
            Self::Unicast(repr) => repr.emit(buffer),
            Self::Anycast(repr) => repr.emit(buffer),
            Self::Broadcast(repr) => repr.emit(buffer),
            Self::SingleHopBroadcast(repr) => repr.emit(buffer),
            Self::TopoBroadcast(repr) => repr.emit(buffer),
            Self::LocationServiceRequest(repr) => repr.emit(buffer),
            Self::LocationServiceReply(repr) => repr.emit(buffer),
        }
    }

    #[cfg(feature = "proto-security")]
    /// Emit the common header into a buffer.
    pub fn emit_basic_header<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
        match self {
            Self::Beacon(repr) => repr.emit_basic_header(buffer),
            Self::Unicast(repr) => repr.emit_basic_header(buffer),
            Self::Anycast(repr) => repr.emit_basic_header(buffer),
            Self::Broadcast(repr) => repr.emit_basic_header(buffer),
            Self::SingleHopBroadcast(repr) => repr.emit_basic_header(buffer),
            Self::TopoBroadcast(repr) => repr.emit_basic_header(buffer),
            Self::LocationServiceRequest(repr) => repr.emit_basic_header(buffer),
            Self::LocationServiceReply(repr) => repr.emit_basic_header(buffer),
        }
    }

    /// Get the basic header length.
    pub const fn basic_header_len(&self) -> usize {
        BASIC_HEADER_LEN
    }

    #[cfg(feature = "proto-security")]
    /// Emit the common header into a buffer.
    pub fn emit_common_and_extended_header<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
        match self {
            Self::Beacon(repr) => repr.emit_common_and_extended_header(buffer),
            Self::Unicast(repr) => repr.emit_common_and_extended_header(buffer),
            Self::Anycast(repr) => repr.emit_common_and_extended_header(buffer),
            Self::Broadcast(repr) => repr.emit_common_and_extended_header(buffer),
            Self::SingleHopBroadcast(repr) => repr.emit_common_and_extended_header(buffer),
            Self::TopoBroadcast(repr) => repr.emit_common_and_extended_header(buffer),
            Self::LocationServiceRequest(repr) => repr.emit_common_and_extended_header(buffer),
            Self::LocationServiceReply(repr) => repr.emit_common_and_extended_header(buffer),
        }
    }

    #[cfg(feature = "proto-security")]
    /// Return the length of the common and extended header that will be emitted from this high-level representation.
    pub fn common_and_extended_header_len(&self) -> usize {
        match self {
            Self::Beacon(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
            Self::Unicast(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
            Self::Anycast(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
            Self::Broadcast(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
            Self::SingleHopBroadcast(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
            Self::TopoBroadcast(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
            Self::LocationServiceRequest(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
            Self::LocationServiceReply(repr) => {
                repr.common_header.buffer_len() + repr.extended_header.buffer_len()
            }
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

impl PacketBufferMeta for Variant {
    fn size(&self) -> usize {
        match self {
            Variant::Beacon(repr) => repr.size(),
            Variant::Unicast(repr) => repr.size(),
            Variant::Anycast(repr) => repr.size(),
            Variant::Broadcast(repr) => repr.size(),
            Variant::SingleHopBroadcast(repr) => repr.size(),
            Variant::TopoBroadcast(repr) => repr.size(),
            Variant::LocationServiceRequest(repr) => repr.size(),
            Variant::LocationServiceReply(repr) => repr.size(),
        }
    }

    fn lifetime(&self) -> Duration {
        match self {
            Variant::Beacon(repr) => repr.lifetime(),
            Variant::Unicast(repr) => repr.lifetime(),
            Variant::Anycast(repr) => repr.lifetime(),
            Variant::Broadcast(repr) => repr.lifetime(),
            Variant::SingleHopBroadcast(repr) => repr.lifetime(),
            Variant::TopoBroadcast(repr) => repr.lifetime(),
            Variant::LocationServiceRequest(repr) => repr.lifetime(),
            Variant::LocationServiceReply(repr) => repr.lifetime(),
        }
    }
}

pub(crate) fn unicast_to_variant_repr(unicast: &Repr<GeonetUnicast>) -> Repr<Variant> {
    match unicast {
        Repr::Unsecured(u) => Repr::Unsecured(Variant::Unicast(u.to_owned())),
        #[cfg(feature = "proto-security")]
        Repr::SecuredDecap {
            repr: u,
            secured_message,
            secured_message_size,
        } => Repr::SecuredDecap {
            repr: Variant::Unicast(u.to_owned()),
            secured_message: secured_message.to_owned(),
            secured_message_size: *secured_message_size,
        },
        #[cfg(feature = "proto-security")]
        Repr::Secured {
            repr: u,
            encapsulated,
        } => Repr::Secured {
            repr: Variant::Unicast(u.to_owned()),
            encapsulated: encapsulated.to_owned(),
        },
        #[cfg(feature = "proto-security")]
        Repr::ToSecure {
            repr: u,
            permission,
        } => Repr::ToSecure {
            repr: Variant::Unicast(u.to_owned()),
            permission: permission.to_owned(),
        },
    }
}
