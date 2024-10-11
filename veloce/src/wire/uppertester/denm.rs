use byteorder::{ByteOrder, NetworkEndian};

use crate::time::{Duration, TAI2004};

mod field {
    use crate::wire::field::*;

    /// UtDenmTrigger fields.
    /// Flags byte.
    pub const TRIG_FLAGS: usize = 0;
    /// Detection time.
    pub const TRIG_DETECTION_TIME: Field = 1..7;
    /// Validity duration.
    pub const TRIG_VALIDITY_DURATION: Field = 7..10;
    /// Repetition duration.
    pub const TRIG_REPETITION_DURATION: Field = 10..13;
    /// Information quality.
    pub const TRIG_INFO_QUALITY: usize = 13;
    /// Cause code.
    pub const TRIG_CAUSE_CODE: usize = 14;
    /// Cause code sub cause.
    pub const TRIG_CAUSE_CODE_SUB_CAUSE: usize = 15;
    /// Relevance distance.
    pub const TRIG_RELEVANCE_DISTANCE: usize = 16;
    /// Relevance traffic direction.
    pub const TRIG_RELEVANCE_TRAFFIC_DIRECTION: usize = 17;
    /// Transmission interval.
    pub const TRIG_TRANSMISSION_INTERVAL: Field = 18..20;
    /// Repetition interval.
    pub const TRIG_REPETITION_INTERVAL: Field = 20..22;
    /// A la carte length.
    pub const TRIG_A_LA_CARTE_LEN: usize = 22;
    /// A la carte data.
    pub const TRIG_A_LA_CARTE: Rest = 23..;

    /// UtDenmUpdateResult fields.
    /// Station ID.
    pub const TRIG_RES_STATION_ID: Field = 0..4;
    /// Sequence number.
    pub const TRIG_RES_SEQ_NUM: Field = 4..6;

    /// UtDenmUpdate fields.
    /// Flags byte.
    pub const UPD_FLAGS: usize = 0;
    /// Station ID.
    pub const UPD_STATION_ID: Field = 1..5;
    /// Sequence number.
    pub const UPD_SEQ_NUM: Field = 5..7;
    /// Detection time.
    pub const UPD_DETECTION_TIME: Field = 7..13;
    /// Validity duration.
    pub const UPD_VALIDITY_DURATION: Field = 13..16;
    /// Information quality.
    pub const UPD_INFO_QUALITY: usize = 16;
    /// Cause code.
    pub const UPD_CAUSE_CODE: usize = 17;
    /// Cause code sub cause.
    pub const UPD_CAUSE_CODE_SUB_CAUSE: usize = 18;
    /// Relevance distance.
    pub const UPD_RELEVANCE_DISTANCE: usize = 19;
    /// Relevance traffic direction.
    pub const UPD_RELEVANCE_TRAFFIC_DIRECTION: usize = 20;
    /// Transmission interval.
    pub const UPD_TRANSMISSION_INTERVAL: Field = 21..23;
    /// Repetition interval.
    pub const UPD_REPETITION_INTERVAL: Field = 23..25;
    /// A la carte length.
    pub const UPD_A_LA_CARTE_LEN: usize = 25;
    /// A la carte data.
    pub const UPD_A_LA_CARTE: Rest = 26..;

    /// UtDenmUpdateResult fields.
    /// Station ID.
    pub const UPD_RES_STATION_ID: Field = 0..4;
    /// Sequence number.
    pub const UPD_RES_SEQ_NUM: Field = 4..6;

    /// UtDenmTermination fields.
    /// Station ID.
    pub const TERM_STATION_ID: Field = 0..4;
    /// Sequence number.
    pub const TERM_SEQ_NUM: Field = 4..6;

    /// UtDenmEventInd fields.
    /// Length of 'Packet' field.
    pub const IND_PAYLOAD_LEN: Field = 0..2;
    /// Packet Payload.
    pub const IND_PAYLOAD: Rest = 2..;
}

/// A read/write wrapper around a UtDenmTrigger packet.
#[derive(Debug, PartialEq)]
pub struct UtDenmTrigger<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtDenmTrigger<T> {
    /// Create a raw octet buffer with a UtDenmTrigger packet structure.
    pub fn new(buffer: T) -> UtDenmTrigger<T> {
        UtDenmTrigger { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Query wether the repetition interval value has to be considered or not.
    #[inline]
    pub fn has_repetition_interval(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::TRIG_FLAGS] & 0x40 == 1
    }

    /// Query wether the transmission interval value has to be considered or not.
    #[inline]
    pub fn has_transmission_interval(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::TRIG_FLAGS] & 0x20 == 1
    }

    /// Query wether the relevance traffic direction value has to be considered or not.
    #[inline]
    pub fn has_relevance_traffic_direction(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::TRIG_FLAGS] & 0x08 == 1
    }

    /// Query wether the repetition duration value has to be considered or not.
    #[inline]
    pub fn has_repetition_duration(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::TRIG_FLAGS] & 0x02 == 1
    }

    /// Query wether the validity duration value has to be considered or not.
    #[inline]
    pub fn has_validity_duration(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::TRIG_FLAGS] & 0x01 == 1
    }

    /// Return the detection time field.
    #[inline]
    pub fn detection_time(&self) -> TAI2004 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u48(&data[field::TRIG_DETECTION_TIME]) as i64;
        TAI2004::from_millis_const(raw)
    }

    /// Return the validity duration field.
    #[inline]
    pub fn validity_duration(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u24(&data[field::TRIG_VALIDITY_DURATION]);
        Duration::from_secs(raw.into())
    }

    /// Return the repetition duration field.
    #[inline]
    pub fn repetition_duration(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u24(&data[field::TRIG_REPETITION_DURATION]);
        Duration::from_secs(raw.into())
    }

    /// Return the information quality field.
    #[inline]
    pub fn information_quality(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TRIG_INFO_QUALITY]
    }

    /// Return the cause code field.
    #[inline]
    pub fn cause_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TRIG_CAUSE_CODE]
    }

    /// Return the sub cause code field.
    #[inline]
    pub fn sub_cause_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TRIG_CAUSE_CODE_SUB_CAUSE]
    }

    /// Return the relevance distance field.
    #[inline]
    pub fn relevance_distance(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TRIG_RELEVANCE_DISTANCE]
    }

    /// Return the relevance traffic direction field.
    #[inline]
    pub fn relevance_traffic_direction(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TRIG_RELEVANCE_TRAFFIC_DIRECTION]
    }

    /// Return the transmission interval field.
    #[inline]
    pub fn transmission_interval(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::TRIG_TRANSMISSION_INTERVAL]);
        Duration::from_millis(raw.into())
    }

    /// Return the repetition interval field.
    #[inline]
    pub fn repetition_interval(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::TRIG_REPETITION_INTERVAL]);
        Duration::from_millis(raw.into())
    }

    /// Return the A la carte length field.
    #[inline]
    pub fn a_la_carte_len(&self) -> usize {
        let data = self.buffer.as_ref();
        data[field::TRIG_A_LA_CARTE_LEN].into()
    }

    /// Return the A la carte data field.
    #[inline]
    pub fn a_la_carte(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::TRIG_A_LA_CARTE]
    }
}

/// A read/write wrapper around a UtDenmTriggerResult packet.
#[derive(Debug, PartialEq)]
pub struct UtDenmTriggerResult<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtDenmTriggerResult<T> {
    /// Create a raw octet buffer with a UtDenmTriggerResult packet structure.
    pub fn new(buffer: T) -> UtDenmTriggerResult<T> {
        UtDenmTriggerResult { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UtDenmTriggerResult<T> {
    /// Set the Station ID field.
    #[inline]
    pub fn set_station_id(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::TRIG_RES_STATION_ID], value);
    }

    /// Set the sequence number field.
    #[inline]
    pub fn set_sequence_number(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::TRIG_RES_SEQ_NUM], value);
    }
}

/// A read/write wrapper around a UtDenmUpdate packet.
#[derive(Debug, PartialEq)]
pub struct UtDenmUpdate<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtDenmUpdate<T> {
    /// Create a raw octet buffer with a UtDenmUpdate packet structure.
    pub fn new(buffer: T) -> UtDenmUpdate<T> {
        UtDenmUpdate { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Query wether the repetition interval value has to be considered or not.
    #[inline]
    pub fn has_repetition_interval(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::UPD_FLAGS] & 0x40 == 1
    }

    /// Query wether the transmission interval value has to be considered or not.
    #[inline]
    pub fn has_transmission_interval(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::UPD_FLAGS] & 0x20 == 1
    }

    /// Query wether the traffic class value has to be considered or not.
    #[inline]
    pub fn has_traffic_class(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::UPD_FLAGS] & 0x10 == 1
    }

    /// Query wether the relevance traffic direction value has to be considered or not.
    #[inline]
    pub fn has_relevance_traffic_direction(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::UPD_FLAGS] & 0x08 == 1
    }

    /// Query wether the relevance distance value has to be considered or not.
    #[inline]
    pub fn has_relevance_distance(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::UPD_FLAGS] & 0x04 == 1
    }

    /// Query wether the information quality/cause code/sub-cause code values has to be considered or not.
    #[inline]
    pub fn has_info_quality_cause_code_sub_cause_code(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::UPD_FLAGS] & 0x02 == 1
    }

    /// Query wether the validity duration value has to be considered or not.
    #[inline]
    pub fn has_validity_duration(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::UPD_FLAGS] & 0x01 == 1
    }

    /// Return the station ID field.
    #[inline]
    pub fn station_id(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::UPD_STATION_ID])
    }

    /// Return the sequence number field.
    #[inline]
    pub fn sequence_number(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::UPD_SEQ_NUM])
    }

    /// Return the detection time field.
    #[inline]
    pub fn detection_time(&self) -> TAI2004 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u48(&data[field::UPD_DETECTION_TIME]) as i64;
        TAI2004::from_millis_const(raw)
    }

    /// Return the validity duration field.
    #[inline]
    pub fn validity_duration(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u24(&data[field::UPD_VALIDITY_DURATION]);
        Duration::from_secs(raw.into())
    }

    /// Return the information quality field.
    #[inline]
    pub fn information_quality(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::UPD_INFO_QUALITY]
    }

    /// Return the cause code field.
    #[inline]
    pub fn cause_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::UPD_CAUSE_CODE]
    }

    /// Return the sub cause code field.
    #[inline]
    pub fn sub_cause_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::UPD_CAUSE_CODE_SUB_CAUSE]
    }

    /// Return the relevance distance field.
    #[inline]
    pub fn relevance_distance(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::UPD_RELEVANCE_DISTANCE]
    }

    /// Return the relevance traffic direction field.
    #[inline]
    pub fn relevance_traffic_direction(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::UPD_RELEVANCE_TRAFFIC_DIRECTION]
    }

    /// Return the transmission interval field.
    #[inline]
    pub fn transmission_interval(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::UPD_TRANSMISSION_INTERVAL]);
        Duration::from_millis(raw.into())
    }

    /// Return the repetition interval field.
    #[inline]
    pub fn repetition_interval(&self) -> Duration {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::UPD_REPETITION_INTERVAL]);
        Duration::from_millis(raw.into())
    }

    /// Return the A la carte length field.
    #[inline]
    pub fn a_la_carte_len(&self) -> usize {
        let data = self.buffer.as_ref();
        data[field::UPD_A_LA_CARTE_LEN].into()
    }

    /// Return the A la carte data field.
    #[inline]
    pub fn a_la_carte(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::UPD_A_LA_CARTE]
    }
}

/// A read/write wrapper around a UtDenmUpdateResult packet.
#[derive(Debug, PartialEq)]
pub struct UtDenmUpdateResult<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtDenmUpdateResult<T> {
    /// Create a raw octet buffer with a UtDenmUpdateResult packet structure.
    pub fn new(buffer: T) -> UtDenmUpdateResult<T> {
        UtDenmUpdateResult { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UtDenmUpdateResult<T> {
    /// Set the station ID field.
    #[inline]
    pub fn set_station_id(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::UPD_RES_STATION_ID], value);
    }

    /// Set the sequence number field.
    #[inline]
    pub fn set_sequence_number(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::UPD_RES_SEQ_NUM], value);
    }
}

/// A read/write wrapper around a UtDenmTermination packet.
#[derive(Debug, PartialEq)]
pub struct UtDenmTermination<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtDenmTermination<T> {
    /// Create a raw octet buffer with a UtDenmTermination packet structure.
    pub fn new(buffer: T) -> UtDenmTermination<T> {
        UtDenmTermination { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the station ID field.
    #[inline]
    pub fn station_id(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::TERM_STATION_ID])
    }

    /// Return the sequence number field.
    #[inline]
    pub fn sequence_number(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::TERM_SEQ_NUM])
    }
}

/// A read/write wrapper around a UtDenmEventInd packet.
#[derive(Debug, PartialEq)]
pub struct UtDenmEventInd<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UtDenmEventInd<T> {
    /// Create a raw octet buffer with a UtDenmEventInd packet structure.
    pub fn new(buffer: T) -> UtDenmEventInd<T> {
        UtDenmEventInd { buffer }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UtDenmEventInd<T> {
    /// Set the payload length field.
    #[inline]
    pub fn set_payload_len(&mut self, value: usize) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::IND_PAYLOAD_LEN], value as u16);
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::IND_PAYLOAD]
    }
}
