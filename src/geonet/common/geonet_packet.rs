use crate::geonet::wire::{
    AnycastBroadcastRepr, BasicHeaderRepr, BeaconHeaderRepr, CommonHeaderRepr,
    LocationServiceReplyRepr, LocationServiceRequestRepr, SingleHopHeaderRepr, TopoBroadcastRepr,
    UnicastRepr,
};

/// Geonetworking packet.
pub(crate) struct GeonetPacket<'p> {
    /// Basic Header part of a Geonetworking packet.
    basic_header: BasicHeaderRepr,
    /// Common Header part of a Geonetworking packet.
    common_header: CommonHeaderRepr,
    /// Extended Header part of a Geonetworking packet.
    extended_header: ExtendedHeader,
    /// Payload carried by a Geonetworking packet.
    payload: GeonetPayload<'p>,
}

/// Extended header types.
pub(crate) enum ExtendedHeader {
    /// Extended Header for a Beacon packet.
    Beacon(BeaconHeaderRepr),
    /// Extended Header for a Unicast packet.
    Unicast(UnicastRepr),
    /// Extended Header for an Anycast packet.
    Anycast(AnycastBroadcastRepr),
    /// Extended Header for a Broadcast packet.
    Broadcast(AnycastBroadcastRepr),
    /// Extended Header for a Single Hop Broadcast packet.
    SingleHopBroadcast(SingleHopHeaderRepr),
    /// Extended Header for a Topologically Scoped Broadcast packet.
    TopoBroadcast(TopoBroadcastRepr),
    /// Extended Header for a Location Service Request packet.
    LocationServiceRequest(LocationServiceRequestRepr),
    /// Extended Header for a Location Service Reply packet.
    LocationServiceReply(LocationServiceReplyRepr),
}

/// Geonetworking payload types.
pub(crate) enum GeonetPayload<'p> {
    /// Payload is BTP-A type.
    BtpA(()),
    /// Payload is BTP-B type.
    BtpB(()),
    /// Payload is Any type.
    /// Used to carry an opaque protocol to the Geonetworking layer.
    Any(&'p [u8]),
}
