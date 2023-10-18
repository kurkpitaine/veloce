use ::core::marker::PhantomData;

use crate::geonet::common::area::Area;
use crate::geonet::time::Duration;
use crate::geonet::wire::{GnAddress, GnTrafficClass};

use super::{Addressable, GeoZonable, Hoppable, UpperProtocol};

#[non_exhaustive]
pub struct AddressableRequest<Transport> {
    pub upper_proto: UpperProtocol,
    pub destination: GnAddress,
    pub ali_id: (),
    pub its_aid: (),
    pub max_lifetime: Duration,
    pub max_hop_limit: u8,
    pub traffic_class: GnTrafficClass,
    _transport: PhantomData<Transport>,
}

#[non_exhaustive]
pub struct GeoZonableRequest<Transport> {
    pub upper_proto: UpperProtocol,
    pub destination: Area,
    pub ali_id: (),
    pub its_aid: (),
    pub max_lifetime: Duration,
    pub max_hop_limit: u8,
    pub traffic_class: GnTrafficClass,
    _transport: PhantomData<Transport>,
}

#[non_exhaustive]
pub struct HoppableRequest<Transport> {
    pub upper_proto: UpperProtocol,
    pub ali_id: (),
    pub its_aid: (),
    pub max_lifetime: Duration,
    pub max_hop_limit: u8,
    pub traffic_class: GnTrafficClass,
    _transport: PhantomData<Transport>,
}

impl<Transport: Addressable> AddressableRequest<Transport> {
    pub fn new(
        upper_proto: UpperProtocol,
        destination: GnAddress,
        ali_id: (),
        its_aid: (),
        max_lifetime: Duration,
        max_hop_limit: u8,
        traffic_class: GnTrafficClass,
    ) -> Self {
        AddressableRequest {
            upper_proto,
            destination,
            ali_id,
            its_aid,
            max_lifetime,
            max_hop_limit,
            traffic_class,
            _transport: PhantomData,
        }
    }
}

impl<Transport: GeoZonable> GeoZonableRequest<Transport> {
    pub fn new(
        upper_proto: UpperProtocol,
        destination: Area,
        ali_id: (),
        its_aid: (),
        max_lifetime: Duration,
        max_hop_limit: u8,
        traffic_class: GnTrafficClass,
    ) -> Self {
        GeoZonableRequest {
            upper_proto,
            destination,
            ali_id,
            its_aid,
            max_lifetime,
            max_hop_limit,
            traffic_class,
            _transport: PhantomData,
        }
    }
}

impl<Transport: Hoppable> HoppableRequest<Transport> {
    pub fn new(
        upper_proto: UpperProtocol,
        ali_id: (),
        its_aid: (),
        max_lifetime: Duration,
        max_hop_limit: u8,
        traffic_class: GnTrafficClass,
    ) -> Self {
        HoppableRequest {
            upper_proto,
            ali_id,
            its_aid,
            max_lifetime,
            max_hop_limit,
            traffic_class,
            _transport: PhantomData,
        }
    }
}
