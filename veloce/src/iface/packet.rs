use crate::wire::{GeonetRepr, GeonetVariant};

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee80211p"))]
pub(crate) enum EthernetPacket<'a> {
    Geonet(GeonetPacket<'a>),
}

#[derive(Debug, PartialEq)]
pub(crate) struct GeonetPacket<'a> {
    repr: GeonetRepr<GeonetVariant>,
    payload: Option<&'a [u8]>,
}

impl<'a> GeonetPacket<'a> {
    /// Constructs a GeonetPacket from a GeonetRepr and an optional payload.
    pub fn new(repr: GeonetRepr<GeonetVariant>, payload: Option<&'a [u8]>) -> Self {
        Self { repr, payload }
    }

    /// Get a reference on the inner GeonetRepr.
    pub fn repr(&self) -> &GeonetRepr<GeonetVariant> {
        &self.repr
    }

    /// Get the payload of the packet.
    pub fn payload(&self) -> Option<&'a [u8]> {
        self.payload
    }

    /// Emits the payload inside buffer `buf`.
    pub fn emit_payload(&self, buf: &mut [u8]) {
        if let Some(payload) = self.payload {
            buf.copy_from_slice(payload);
        }
    }
}

impl<'a> From<GeonetPacket<'a>> for EthernetPacket<'a> {
    fn from(value: GeonetPacket<'a>) -> Self {
        Self::Geonet(value)
    }
}
