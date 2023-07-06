mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

pub mod ethernet;
pub mod geonet;

pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    Repr as EthernetRepr, HEADER_LEN as ETHERNET_HEADER_LEN,
};

pub use self::geonet::{
    anycast_broadcast_header::{
        Header as AnycastBroadcastHeader, Repr as AnycastBroadcastRepr,
        HEADER_LEN as ANYCAST_BROADCAST_HEADER_LEN,
    },
    basic_header::{
        Header as BasicHeader, Repr as BasicHeaderRepr, HEADER_LEN as BASIC_HEADER_LEN,
    },
    beacon_header::{
        Header as BeaconHeader, Repr as BeaconHeaderRepr, HEADER_LEN as BEACON_HEADER_LEN,
    },
    common_header::{
        Header as CommonHeader, Repr as CommonHeaderRepr, HEADER_LEN as COMMON_HEADER_LEN,
    },
    location_service_req_header::{
        Header as LocationServiceRequestHeader, Repr as LocationServiceRequestRepr,
        HEADER_LEN as LOCATION_SERVICE_REQ_HEADER_LEN,
    },
    long_position_vector::{
        Header as LongPositionVectorHeader, Repr as LongPositionVectorRepr,
        HEADER_LEN as LONG_POSITION_VECTOR_HEADER_LEN,
    },
    short_position_vector::{
        Header as ShortPositionVectorHeader, Repr as ShortPositionVectorRepr,
        HEADER_LEN as SHORT_POSITION_VECTOR_HEADER_LEN,
    },
    single_hop_header::{
        Header as SingleHopHeader, Repr as SingleHopHeaderRepr, HEADER_LEN as SINGLE_HOP_HEADER_LEN,
    },
    topo_header::{
        Header as TopoBroadcastHeader, Repr as TopoBroadcastRepr,
        HEADER_LEN as TOPO_BROADCAST_HEADER_LEN,
    },
    unicast_header::{
        Header as UnicastHeader, Header as LocationServiceReplyHeader, Repr as UnicastRepr,
        Repr as LocationServiceReplyRepr, HEADER_LEN as UNICAST_HEADER_LEN,
        HEADER_LEN as LOCATION_SERVICE_REP_HEADER_LEN,
    },
    Address as GnAddress, SequenceNumber, TrafficClass as GnTrafficClass,
};
