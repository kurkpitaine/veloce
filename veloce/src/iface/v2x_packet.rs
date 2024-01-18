use crate::common::geo_area::{GeoArea, GeoPosition};
use crate::phy::DeviceCapabilities;
use crate::wire::{
    BasicHeaderRepr, BeaconHeaderRepr, CommonHeaderRepr, GeoAnycastRepr, GeoBroadcastRepr,
    GeonetBeacon, GeonetGeoAnycast, GeonetGeoBroadcast, GeonetLocationServiceReply,
    GeonetLocationServiceRequest, GeonetRepr, GeonetSingleHop, GeonetTopoBroadcast, GeonetUnicast,
    GnAddress, LocationServiceReplyRepr, LocationServiceRequestRepr, SequenceNumber,
    SingleHopHeaderRepr, TopoBroadcastRepr, UnicastRepr,
};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "medium-ethernet")]
pub(crate) enum EthernetPacket<'a> {
    Geonet(GeonetPacket<'a>),
}

/// Geonetworking packet types.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum GeonetPacket<'p> {
    /// Beacon packet.
    Beacon(BeaconPacket<'p>),
    /// Unicast packet.
    Unicast(UnicastPacket<'p>),
    /// Anycast packet.
    Anycast(GeoAnycastPacket<'p>),
    /// Broadcast packet.
    Broadcast(GeoBroadcastPacket<'p>),
    /// Single Hop Broadcast packet.
    SingleHopBroadcast(SingleHopPacket<'p>),
    /// Topologically Scoped Broadcast packet.
    TopoBroadcast(TopoBroadcastPacket<'p>),
    /// Location Service Request packet.
    LocationServiceRequest(LocationServiceRequestPacket<'p>),
    /// Location Service Reply packet.
    LocationServiceReply(LocationServiceReplyPacket<'p>),
}

macro_rules! make_packet {
    ($packet: ident, $repr: ty, $gn_variant: ident) => {
        #[derive(Debug, PartialEq)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[cfg(feature = "proto-geonet")]
        pub(crate) struct $packet<'p> {
            basic_header: BasicHeaderRepr,
            common_header: CommonHeaderRepr,
            extended_header: $repr,
            payload: GeonetPayload<'p>,
        }

        #[cfg(feature = "proto-geonet")]
        impl $packet<'_> {
            #[allow(unused)]
            pub fn geonet_variant(&self) -> $gn_variant {
                $gn_variant::new(self.basic_header, self.common_header, self.extended_header)
            }
        }
    };
}

make_packet!(BeaconPacket, BeaconHeaderRepr, GeonetBeacon);
make_packet!(UnicastPacket, UnicastRepr, GeonetUnicast);
make_packet!(GeoAnycastPacket, GeoAnycastRepr, GeonetGeoAnycast);
make_packet!(GeoBroadcastPacket, GeoBroadcastRepr, GeonetGeoBroadcast);
make_packet!(SingleHopPacket, SingleHopHeaderRepr, GeonetSingleHop);
make_packet!(TopoBroadcastPacket, TopoBroadcastRepr, GeonetTopoBroadcast);
make_packet!(
    LocationServiceRequestPacket,
    LocationServiceRequestRepr,
    GeonetLocationServiceRequest
);
make_packet!(
    LocationServiceReplyPacket,
    LocationServiceReplyRepr,
    GeonetLocationServiceReply
);

impl<'p> GeonetPacket<'p> {
    pub(crate) fn new(gn_repr: GeonetRepr, payload: GeonetPayload<'p>) -> Self {
        match gn_repr {
            GeonetRepr::Beacon(header) => Self::new_beacon(
                header.basic_header,
                header.common_header,
                header.extended_header,
            ),
            GeonetRepr::Unicast(header) => Self::new_unicast(
                header.basic_header,
                header.common_header,
                header.extended_header,
                payload,
            ),
            GeonetRepr::Anycast(header) => Self::new_anycast(
                header.basic_header,
                header.common_header,
                header.extended_header,
                payload,
            ),
            GeonetRepr::Broadcast(header) => Self::new_broadcast(
                header.basic_header,
                header.common_header,
                header.extended_header,
                payload,
            ),
            GeonetRepr::SingleHopBroadcast(header) => Self::new_single_hop_broadcast(
                header.basic_header,
                header.common_header,
                header.extended_header,
                payload,
            ),
            GeonetRepr::TopoBroadcast(header) => Self::new_topo_scoped_broadcast(
                header.basic_header,
                header.common_header,
                header.extended_header,
                payload,
            ),
            GeonetRepr::LocationServiceRequest(header) => Self::new_location_service_request(
                header.basic_header,
                header.common_header,
                header.extended_header,
            ),
            GeonetRepr::LocationServiceReply(header) => Self::new_location_service_reply(
                header.basic_header,
                header.common_header,
                header.extended_header,
            ),
        }
    }

    /// Constructs a new Beaconing packet.
    pub(crate) fn new_beacon(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        beacon_header: BeaconHeaderRepr,
    ) -> Self {
        Self::Beacon(BeaconPacket {
            basic_header,
            common_header,
            extended_header: beacon_header,
            payload: GeonetPayload::NoPayload,
        })
    }

    /// Constructs a new Unicast packet.
    pub(crate) fn new_unicast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        unicast_header: UnicastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::Unicast(UnicastPacket {
            basic_header,
            common_header,
            extended_header: unicast_header,
            payload,
        })
    }

    /// Constructs a new Anycast packet.
    pub(crate) fn new_anycast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        anycast_header: GeoAnycastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::Anycast(GeoAnycastPacket {
            basic_header,
            common_header,
            extended_header: anycast_header,
            payload,
        })
    }

    /// Constructs a new Broadcast packet.
    pub(crate) fn new_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        broadcast_header: GeoBroadcastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::Broadcast(GeoBroadcastPacket {
            basic_header,
            common_header,
            extended_header: broadcast_header,
            payload,
        })
    }

    /// Constructs a new Single Hop Broadcast packet.
    pub(crate) fn new_single_hop_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        shb_header: SingleHopHeaderRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::SingleHopBroadcast(SingleHopPacket {
            basic_header,
            common_header,
            extended_header: shb_header,
            payload,
        })
    }

    /// Constructs a new Topologically Scoped Broadcast packet.
    pub(crate) fn new_topo_scoped_broadcast(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        tsb_header: TopoBroadcastRepr,
        payload: GeonetPayload<'p>,
    ) -> Self {
        Self::TopoBroadcast(TopoBroadcastPacket {
            basic_header,
            common_header,
            extended_header: tsb_header,
            payload,
        })
    }

    /// Constructs a new Location Service Request packet.
    pub(crate) fn new_location_service_request(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_req_header: LocationServiceRequestRepr,
    ) -> Self {
        Self::LocationServiceRequest(LocationServiceRequestPacket {
            basic_header,
            common_header,
            extended_header: ls_req_header,
            payload: GeonetPayload::NoPayload,
        })
    }

    /// Constructs a new Location Service Reply packet.
    pub(crate) fn new_location_service_reply(
        basic_header: BasicHeaderRepr,
        common_header: CommonHeaderRepr,
        ls_rep_header: LocationServiceReplyRepr,
    ) -> Self {
        Self::LocationServiceReply(LocationServiceReplyPacket {
            basic_header,
            common_header,
            extended_header: ls_rep_header,
            payload: GeonetPayload::NoPayload,
        })
    }

    #[allow(unused)]
    pub(crate) fn basic_header(&self) -> BasicHeaderRepr {
        match self {
            GeonetPacket::Beacon(b) => b.basic_header,
            GeonetPacket::Unicast(u) => u.basic_header,
            GeonetPacket::Anycast(a) => a.basic_header,
            GeonetPacket::Broadcast(b) => b.basic_header,
            GeonetPacket::SingleHopBroadcast(s) => s.basic_header,
            GeonetPacket::TopoBroadcast(t) => t.basic_header,
            GeonetPacket::LocationServiceRequest(l) => l.basic_header,
            GeonetPacket::LocationServiceReply(l) => l.basic_header,
        }
    }

    pub(crate) fn common_header(&self) -> CommonHeaderRepr {
        match self {
            GeonetPacket::Beacon(b) => b.common_header,
            GeonetPacket::Unicast(u) => u.common_header,
            GeonetPacket::Anycast(a) => a.common_header,
            GeonetPacket::Broadcast(b) => b.common_header,
            GeonetPacket::SingleHopBroadcast(s) => s.common_header,
            GeonetPacket::TopoBroadcast(t) => t.common_header,
            GeonetPacket::LocationServiceRequest(l) => l.common_header,
            GeonetPacket::LocationServiceReply(l) => l.common_header,
        }
    }

    /// Constructs a [`GeonetRepr`] from [`GeonetPacket`].
    pub(crate) fn geonet_repr(&self) -> GeonetRepr {
        match self {
            GeonetPacket::Beacon(packet) => GeonetRepr::new_beacon(
                packet.basic_header,
                packet.common_header,
                packet.extended_header,
            ),
            GeonetPacket::Unicast(packet) => GeonetRepr::new_unicast(
                packet.basic_header,
                packet.common_header,
                packet.extended_header,
            ),
            GeonetPacket::Anycast(packet) => GeonetRepr::new_anycast(
                packet.basic_header,
                packet.common_header,
                packet.extended_header,
            ),
            GeonetPacket::Broadcast(packet) => GeonetRepr::new_broadcast(
                packet.basic_header,
                packet.common_header,
                packet.extended_header,
            ),
            GeonetPacket::SingleHopBroadcast(packet) => GeonetRepr::new_single_hop_broadcast(
                packet.basic_header,
                packet.common_header,
                packet.extended_header,
            ),
            GeonetPacket::TopoBroadcast(packet) => GeonetRepr::new_topo_scoped_broadcast(
                packet.basic_header,
                packet.common_header,
                packet.extended_header,
            ),
            GeonetPacket::LocationServiceRequest(packet) => {
                GeonetRepr::new_location_service_request(
                    packet.basic_header,
                    packet.common_header,
                    packet.extended_header,
                )
            }
            GeonetPacket::LocationServiceReply(packet) => GeonetRepr::new_location_service_reply(
                packet.basic_header,
                packet.common_header,
                packet.extended_header,
            ),
        }
    }

    /// Returns the source Geonetworking address contained inside the packet.
    pub(crate) fn source_address(&self) -> GnAddress {
        match self {
            GeonetPacket::Beacon(p) => p.extended_header.source_position_vector.address,
            GeonetPacket::Unicast(p) => p.extended_header.source_position_vector.address,
            GeonetPacket::Anycast(p) => p.extended_header.source_position_vector.address,
            GeonetPacket::Broadcast(p) => p.extended_header.source_position_vector.address,
            GeonetPacket::SingleHopBroadcast(p) => p.extended_header.source_position_vector.address,
            GeonetPacket::TopoBroadcast(p) => p.extended_header.source_position_vector.address,
            GeonetPacket::LocationServiceRequest(p) => {
                p.extended_header.source_position_vector.address
            }
            GeonetPacket::LocationServiceReply(p) => {
                p.extended_header.source_position_vector.address
            }
        }
    }

    /// Returns the sequence number the packet.
    ///
    /// # Panics
    ///
    /// This method panics if the packet does not contain a sequence number.
    pub(crate) fn sequence_number(&self) -> SequenceNumber {
        match self {
            GeonetPacket::Beacon(_) => panic!("No sequence number in a Beacon packet!"),
            GeonetPacket::SingleHopBroadcast(_) => panic!("No sequence number in a SHB packet!"),
            GeonetPacket::Unicast(p) => p.extended_header.sequence_number,
            GeonetPacket::Anycast(p) => p.extended_header.sequence_number,
            GeonetPacket::Broadcast(p) => p.extended_header.sequence_number,
            GeonetPacket::TopoBroadcast(p) => p.extended_header.sequence_number,
            GeonetPacket::LocationServiceRequest(p) => p.extended_header.sequence_number,
            GeonetPacket::LocationServiceReply(p) => p.extended_header.sequence_number,
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
            GeonetPacket::Beacon(_) => panic!("No geo destination in a Beacon packet!"),
            GeonetPacket::SingleHopBroadcast(_) => panic!("No geo destination in a SHB packet!"),
            GeonetPacket::TopoBroadcast(_) => panic!("No geo destination in a TSB packet!"),
            GeonetPacket::LocationServiceRequest(_) => {
                panic!("No geo destination in a LS request packet!")
            }
            GeonetPacket::Unicast(u) => GeoPosition {
                latitude: u.extended_header.destination_position_vector.latitude,
                longitude: u.extended_header.destination_position_vector.longitude,
            },
            GeonetPacket::Anycast(a) => GeoPosition {
                latitude: a.extended_header.latitude,
                longitude: a.extended_header.longitude,
            },
            GeonetPacket::Broadcast(b) => GeoPosition {
                latitude: b.extended_header.latitude,
                longitude: b.extended_header.longitude,
            },
            GeonetPacket::LocationServiceReply(r) => GeoPosition {
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
            GeonetPacket::Beacon(_) => panic!("No geo area in a Beacon packet!"),
            GeonetPacket::SingleHopBroadcast(_) => {
                panic!("No geo area in a SHB packet!")
            }
            GeonetPacket::TopoBroadcast(_) => panic!("No geo area in a TSB packet!"),
            GeonetPacket::LocationServiceRequest(_) => {
                panic!("No geo area in a LS request packet!")
            }
            GeonetPacket::LocationServiceReply(_) => {
                panic!("No geo area in a LS reply packet!")
            }
            GeonetPacket::Unicast(_) => panic!("No geo area in a Unicast packet!"),
            GeonetPacket::Anycast(a) => {
                GeoArea::from_gac(&a.common_header.header_type, &a.extended_header)
            }
            GeonetPacket::Broadcast(b) => {
                GeoArea::from_gbc(&b.common_header.header_type, &b.extended_header)
            }
        }
    }

    /// Returns the payload contained in the packet.
    pub(crate) fn payload(&self) -> &GeonetPayload<'p> {
        match self {
            GeonetPacket::Beacon(p) => &p.payload,
            GeonetPacket::Unicast(p) => &p.payload,
            GeonetPacket::Anycast(p) => &p.payload,
            GeonetPacket::Broadcast(p) => &p.payload,
            GeonetPacket::SingleHopBroadcast(p) => &p.payload,
            GeonetPacket::TopoBroadcast(p) => &p.payload,
            GeonetPacket::LocationServiceRequest(p) => &p.payload,
            GeonetPacket::LocationServiceReply(p) => &p.payload,
        }
    }

    /// Emits the payload inside the packet to transmit.
    pub(crate) fn emit_payload(
        &self,
        _gn_repr: &GeonetRepr,
        payload: &mut [u8],
        _caps: &DeviceCapabilities,
    ) {
        match self.payload() {
            GeonetPayload::Raw(pl) => {
                payload.copy_from_slice(pl);
            }
            GeonetPayload::Any(pl) => {
                payload.copy_from_slice(pl);
            }
            #[cfg(feature = "socket-btp-b")]
            GeonetPayload::BtpA(_) => {}
            #[cfg(feature = "socket-btp-b")]
            GeonetPayload::BtpB(pl) => {
                payload.copy_from_slice(pl);
            }
            GeonetPayload::IPv6(_) => {}
            GeonetPayload::NoPayload => {}
        }
    }
}

/// Extended header types.
#[derive(Debug)]
#[allow(unused)]
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
    #[allow(unused)]
    pub(crate) fn buffer_len(&self) -> usize {
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
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub(crate) enum GeonetPayload<'p> {
    /// Payload is Any type.
    /// Used to carry an opaque protocol to the Geonetworking layer.
    Any(&'p [u8]),
    /// Payload is BTP-A type.
    BtpA(&'p [u8]),
    /// Payload is BTP-B type.
    BtpB(&'p [u8]),
    /// Payload is IPv6 type.
    IPv6(&'p [u8]),
    /// Payload is Raw type.
    /// Used for forwarding when BTP layer is not
    /// processed and on Geonet socket.
    Raw(&'p [u8]),
    /// No Payload carried in packet.
    NoPayload,
}

impl<'p> GeonetPayload<'p> {
    /// Converts the payload type into an option.
    pub(crate) fn into_option(&self) -> Option<&'p [u8]> {
        let res = match self {
            GeonetPayload::Any(p) => Some(*p),
            GeonetPayload::BtpA(p) => Some(*p),
            GeonetPayload::BtpB(p) => Some(*p),
            GeonetPayload::IPv6(p) => Some(*p),
            GeonetPayload::Raw(p) => Some(*p),
            GeonetPayload::NoPayload => None,
        };

        res
    }
}
