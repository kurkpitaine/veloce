use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};

/// Contains all the events emitted and received with the IPC.
pub mod event;

impl event::Event {
    pub fn new(r#type: event::event::EventType) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("start time must not be before the unix epoch")
                .as_millis() as u64,
            event_type: Some(r#type),
        }
    }

    /// Serialize `self` into a vector allocated at encoding.
    pub fn serialize_to_vec(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Deserialize from a
    pub fn deserialize(buf: &[u8]) -> Result<Self, prost::DecodeError> {
        Self::decode(buf)
    }
}
