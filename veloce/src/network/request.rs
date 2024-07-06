use ::core::marker::PhantomData;

use crate::common::geo_area::GeoArea;
use crate::time::Duration;
use crate::wire::{GnAddress, GnTrafficClass};

use super::{Addressable, GeoZonable, Hoppable, UpperProtocol};

#[cfg(feature = "proto-security")]
use crate::security::permission::Permission;

#[non_exhaustive]
pub struct AddressableRequest<Transport> {
    pub upper_proto: UpperProtocol,
    pub destination: GnAddress,
    pub ali_id: (),
    #[cfg(feature = "proto-security")]
    pub its_aid: Permission,
    pub max_lifetime: Duration,
    pub max_hop_limit: u8,
    pub traffic_class: GnTrafficClass,
    _transport: PhantomData<Transport>,
}

#[non_exhaustive]
pub struct GeoZonableRequest<Transport> {
    pub upper_proto: UpperProtocol,
    pub destination: GeoArea,
    pub ali_id: (),
    #[cfg(feature = "proto-security")]
    pub its_aid: Permission,
    pub max_lifetime: Duration,
    pub max_hop_limit: u8,
    pub traffic_class: GnTrafficClass,
    _transport: PhantomData<Transport>,
}

#[non_exhaustive]
pub struct HoppableRequest<Transport> {
    pub upper_proto: UpperProtocol,
    pub ali_id: (),
    #[cfg(feature = "proto-security")]
    pub its_aid: Permission,
    pub max_lifetime: Duration,
    pub max_hop_limit: u8,
    pub traffic_class: GnTrafficClass,
    _transport: PhantomData<Transport>,
}

impl<Transport: Addressable> AddressableRequest<Transport> {
    #[cfg(feature = "proto-security")]
    pub fn new(
        upper_proto: UpperProtocol,
        destination: GnAddress,
        ali_id: (),
        its_aid: Permission,
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

    #[cfg(not(feature = "proto-security"))]
    pub fn new(
        upper_proto: UpperProtocol,
        destination: GnAddress,
        ali_id: (),
        max_lifetime: Duration,
        max_hop_limit: u8,
        traffic_class: GnTrafficClass,
    ) -> Self {
        AddressableRequest {
            upper_proto,
            destination,
            ali_id,
            max_lifetime,
            max_hop_limit,
            traffic_class,
            _transport: PhantomData,
        }
    }
}

impl<Transport: GeoZonable> GeoZonableRequest<Transport> {
    #[cfg(feature = "proto-security")]
    pub fn new(
        upper_proto: UpperProtocol,
        destination: GeoArea,
        ali_id: (),
        its_aid: Permission,
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

    #[cfg(not(feature = "proto-security"))]
    pub fn new(
        upper_proto: UpperProtocol,
        destination: GeoArea,
        ali_id: (),
        max_lifetime: Duration,
        max_hop_limit: u8,
        traffic_class: GnTrafficClass,
    ) -> Self {
        GeoZonableRequest {
            upper_proto,
            destination,
            ali_id,
            max_lifetime,
            max_hop_limit,
            traffic_class,
            _transport: PhantomData,
        }
    }
}

impl<Transport: Hoppable> HoppableRequest<Transport> {
    #[cfg(feature = "proto-security")]
    pub fn new(
        upper_proto: UpperProtocol,
        ali_id: (),
        its_aid: Permission,
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

    #[cfg(not(feature = "proto-security"))]
    pub fn new(
        upper_proto: UpperProtocol,
        ali_id: (),
        max_lifetime: Duration,
        max_hop_limit: u8,
        traffic_class: GnTrafficClass,
    ) -> Self {
        HoppableRequest {
            upper_proto,
            ali_id,
            max_lifetime,
            max_hop_limit,
            traffic_class,
            _transport: PhantomData,
        }
    }
}
