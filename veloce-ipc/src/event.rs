use std::time::{Instant, SystemTime};

use rkyv::{
    ser::{serializers::AllocSerializer, Serializer},
    with::UnixTimestamp,
    AlignedVec, Archive, Deserialize, Serialize,
};

use crate::{IpcDeserializationError, IpcSerializationError, IpcSerializer};

#[derive(Archive, Debug, Deserialize, Serialize)]
#[archive(check_bytes)]
pub struct Event {
    /// Monotonic timestamp at which this event was generated.
    pub timestamp: u64,
    /// System time at which this event was generated.
    #[with(UnixTimestamp)]
    pub time: SystemTime,
    /// Type of the data carried in this event.
    pub r#type: EventType,
}

/// Event type.
/// Contains all the different types of events carried in the IPC protocol.
#[derive(Archive, Debug, Deserialize, Serialize)]
#[archive(check_bytes)]
pub enum EventType {
    /// Received CAM event.
    CamRx(Vec<u8>),
    /// Transmitted CAM event.
    CamTx(Vec<u8>),
}

impl Event {
    /// Constructs an [Event] of type `event_type`.
    /// `mono_start` contains the instant at which the monotonic clock started. Used to fingerprint the [Event]
    /// with a strictly incrementing time base.
    pub fn new(event_type: EventType, mono_start: Instant) -> Self {
        Event {
            timestamp: mono_start.elapsed().as_micros() as u64,
            time: SystemTime::now(),
            r#type: event_type,
        }
    }

    /// Serialize as an [AlignedVec] byte buffer.
    pub fn to_bytes(&self) -> Result<AlignedVec, IpcSerializationError> {
        let mut serializer = IpcSerializer::<AllocSerializer<2048>>::default();
        serializer
            .serialize_value(self)
            .map_err(|_| IpcSerializationError)?;

        let bytes = serializer.into_inner().into_serializer().into_inner();
        Ok(bytes)
    }

    /// Read an [Event] from a buffer containing an [Archive].
    /// This method use a zero copy method to read the data which is accessed with references.
    /// To returned an owned [Event], use the [Event::from_bytes] method.
    pub fn from_archive(bytes: &[u8]) -> Result<&ArchivedEvent, IpcDeserializationError> {
        let archived =
            rkyv::check_archived_root::<Event>(bytes).map_err(|_| IpcDeserializationError)?;

        Ok(archived)
    }

    /// Construct an [Event] from a byte buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Event, IpcDeserializationError> {
        let archive = Event::from_archive(bytes)?;
        let deserialized: Event = archive
            .deserialize(&mut rkyv::Infallible)
            .map_err(|_| IpcDeserializationError)?;

        Ok(deserialized)
    }
}
