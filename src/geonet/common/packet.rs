use crate::geonet::{
    time::Duration,
    wire::{
        BasicHeaderRepr, BeaconHeaderRepr, CommonHeaderRepr, GeoAnycastRepr, GeoBroadcastRepr,
        GnAddress as Address, LocationServiceReplyRepr, LocationServiceRequestRepr,
        SingleHopHeaderRepr, TopoBroadcastRepr, UnicastRepr,
    },
};

use super::packet_buffer::PacketMeta;

/// Geonetworking packet metadata.
/// Same as [`GeonetPacket`] but without the payload.
#[derive(Debug)]
pub(crate) struct PacketMetadata {
    /// Basic Header part of a Geonetworking packet.
    pub basic_header: BasicHeaderRepr,
    /// Common Header part of a Geonetworking packet.
    pub common_header: CommonHeaderRepr,
    /// Extended Header part of a Geonetworking packet.
    pub extended_header: ExtendedHeader,
}

impl PacketMeta for PacketMetadata {
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

impl PacketMetadata {
    pub fn new(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        extended_header: ExtendedHeader,
    ) -> PacketMetadata {
        PacketMetadata {
            basic_header,
            common_header,
            extended_header,
        }
    }

    /// Constructs a new Beaconing packet.
    pub fn new_beacon(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        beacon_header: BeaconHeaderRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Beacon(beacon_header),
        )
    }

    /// Constructs a new Unicast packet.
    pub fn new_unicast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        unicast_header: UnicastRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Unicast(unicast_header),
        )
    }

    /// Constructs a new Anycast packet.
    pub fn new_anycast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        anycast_header: GeoAnycastRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Anycast(anycast_header),
        )
    }

    /// Constructs a new Broadcast packet.
    pub fn new_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        broadcast_header: GeoBroadcastRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Broadcast(broadcast_header),
        )
    }

    /// Constructs a new Single Hop Broadcast packet.
    pub fn new_single_hop_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        shb_header: SingleHopHeaderRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::SingleHopBroadcast(shb_header),
        )
    }

    /// Constructs a new Topologically Scoped Broadcast packet.
    pub fn new_topo_scoped_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        tsb_header: TopoBroadcastRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::TopoBroadcast(tsb_header),
        )
    }

    /// Constructs a new Location Service Request packet.
    pub fn new_location_service_request(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_req_header: LocationServiceRequestRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::LocationServiceRequest(ls_req_header),
        )
    }

    /// Constructs a new Location Service Reply packet.
    pub fn new_location_service_reply(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_rep_header: LocationServiceReplyRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::LocationServiceReply(ls_rep_header),
        )
    }

    /// Returns the source geonet address contained in this packet.
    pub fn source_address(&self) -> Address {
        match &self.extended_header {
            ExtendedHeader::Beacon(extended) => extended.source_position_vector.address,
            ExtendedHeader::Unicast(extended) => extended.source_position_vector.address,
            ExtendedHeader::Anycast(extended) => extended.source_position_vector.address,
            ExtendedHeader::Broadcast(extended) => extended.source_position_vector.address,
            ExtendedHeader::SingleHopBroadcast(extended) => extended.source_position_vector.address,
            ExtendedHeader::TopoBroadcast(extended) => extended.source_position_vector.address,
            ExtendedHeader::LocationServiceRequest(extended) => {
                extended.source_position_vector.address
            }
            ExtendedHeader::LocationServiceReply(extended) => {
                extended.source_position_vector.address
            }
        }
    }
}

/// Geonetworking packet.
#[derive(Debug)]
pub(crate) struct GeonetPacket<'p> {
    /// Basic Header part of a Geonetworking packet.
    pub basic_header: BasicHeaderRepr,
    /// Common Header part of a Geonetworking packet.
    pub common_header: CommonHeaderRepr,
    /// Extended Header part of a Geonetworking packet.
    pub extended_header: ExtendedHeader,
    /// Payload carried by a Geonetworking packet.
    /// Optional as Beaconing packets don't carry a payload.
    pub payload: GeonetPayload<'p>,
}

impl<'p> GeonetPacket<'p> {
    pub fn new(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        extended_header: ExtendedHeader,
        payload: GeonetPayload<'p>,
    ) -> GeonetPacket {
        GeonetPacket {
            basic_header,
            common_header,
            extended_header,
            payload,
        }
    }

    /// Constructs a new Beaconing packet.
    pub fn new_beacon(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        beacon_header: BeaconHeaderRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Beacon(beacon_header),
            GeonetPayload::NoPayload,
        )
    }

    /// Constructs a new Unicast packet.
    pub fn new_unicast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        unicast_header: UnicastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Unicast(unicast_header),
            payload,
        )
    }

    /// Constructs a new Anycast packet.
    pub fn new_anycast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        anycast_header: GeoAnycastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Anycast(anycast_header),
            payload,
        )
    }

    /// Constructs a new Broadcast packet.
    pub fn new_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        broadcast_header: GeoBroadcastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::Broadcast(broadcast_header),
            payload,
        )
    }

    /// Constructs a new Single Hop Broadcast packet.
    pub fn new_single_hop_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        shb_header: SingleHopHeaderRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::SingleHopBroadcast(shb_header),
            payload,
        )
    }

    /// Constructs a new Topologically Scoped Broadcast packet.
    pub fn new_topo_scoped_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        tsb_header: TopoBroadcastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::TopoBroadcast(tsb_header),
            payload,
        )
    }

    /// Constructs a new Location Service Request packet.
    pub fn new_location_service_request(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_req_header: LocationServiceRequestRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::LocationServiceRequest(ls_req_header),
            GeonetPayload::NoPayload,
        )
    }

    /// Constructs a new Location Service Reply packet.
    pub fn new_location_service_reply(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_rep_header: LocationServiceReplyRepr,
    ) -> Self {
        Self::new(
            basic_header,
            common_header,
            ExtendedHeader::LocationServiceReply(ls_rep_header),
            GeonetPayload::NoPayload,
        )
    }

    /// Returns the source geonet address contained in this packet.
    pub fn source_address(&self) -> Address {
        match &self.extended_header {
            ExtendedHeader::Beacon(extended) => extended.source_position_vector.address,
            ExtendedHeader::Unicast(extended) => extended.source_position_vector.address,
            ExtendedHeader::Anycast(extended) => extended.source_position_vector.address,
            ExtendedHeader::Broadcast(extended) => extended.source_position_vector.address,
            ExtendedHeader::SingleHopBroadcast(extended) => extended.source_position_vector.address,
            ExtendedHeader::TopoBroadcast(extended) => extended.source_position_vector.address,
            ExtendedHeader::LocationServiceRequest(extended) => {
                extended.source_position_vector.address
            }
            ExtendedHeader::LocationServiceReply(extended) => {
                extended.source_position_vector.address
            }
        }
    }
}

/// Extended header types.
#[derive(Debug)]
pub(crate) enum ExtendedHeader {
    /// Extended Header for a Beacon packet.
    Beacon(BeaconHeaderRepr),
    /// Extended Header for a Unicast packet.
    Unicast(UnicastRepr),
    /// Extended Header for an Anycast packet.
    Anycast(GeoAnycastRepr),
    /// Extended Header for a Broadcast packet.
    Broadcast(GeoBroadcastRepr),
    /// Extended Header for a Single Hop Broadcast packet.
    SingleHopBroadcast(SingleHopHeaderRepr),
    /// Extended Header for a Topologically Scoped Broadcast packet.
    TopoBroadcast(TopoBroadcastRepr),
    /// Extended Header for a Location Service Request packet.
    LocationServiceRequest(LocationServiceRequestRepr),
    /// Extended Header for a Location Service Reply packet.
    LocationServiceReply(LocationServiceReplyRepr),
}

impl ExtendedHeader {
    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            ExtendedHeader::Beacon(r) => r.buffer_len(),
            ExtendedHeader::Unicast(r) => r.buffer_len(),
            ExtendedHeader::Anycast(r) => r.buffer_len(),
            ExtendedHeader::Broadcast(r) => r.buffer_len(),
            ExtendedHeader::SingleHopBroadcast(r) => r.buffer_len(),
            ExtendedHeader::TopoBroadcast(r) => r.buffer_len(),
            ExtendedHeader::LocationServiceRequest(r) => r.buffer_len(),
            ExtendedHeader::LocationServiceReply(r) => r.buffer_len(),
        }
    }
}

/// Geonetworking payload types.
#[derive(Debug)]
pub(crate) enum GeonetPayload<'p> {
    /// Payload is Any type.
    /// Used to carry an opaque protocol to the Geonetworking layer.
    Any(&'p [u8]),
    /// Payload is BTP-A type.
    BtpA(()),
    /// Payload is BTP-B type.
    BtpB(()),
    /// Payload is IPv6 type.
    IPv6(()),
    /// Payload is Raw type.
    /// Used for forwarding.
    Raw(&'p [u8]),
    /// Payload is not existent.
    NoPayload,
}
