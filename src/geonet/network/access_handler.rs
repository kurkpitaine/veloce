use crate::geonet::{
    common::location_table::LocationTable,
    wire::{BasicHeader, SequenceNumber},
};

/// Geonetworking Access Layer Interface Handler.
pub struct AccessHandler {
    /// Location Table of the Access Handler.
    location_table: LocationTable,
    /// Sequence Number of the Access Handler.
    sequence_number: SequenceNumber,
    /// Location Service packet buffer.
    ls_buffer: (),
    /// Forwarding packet buffer.
    forwarding_buffer: (),
}

impl AccessHandler {
    pub fn process_basic_header<'a>(&self, gn_packet: &BasicHeader<&'a [u8]>) {}
}
