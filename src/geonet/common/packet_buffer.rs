use heapless::linked_list::{LinkedIndexUsize, LinkedList};

use crate::geonet::time::Instant;

/// Packet buffer node.
#[derive(Debug)]
pub struct Node<T> {
    size: usize,
    inserted_at: Instant,
    expires_at: Instant,
    elem: T,
}

/// Generic packet buffer.
pub struct PacketBuffer<T, const N: usize, const C: usize> {
    /// Buffer underlying storage.
    storage: LinkedList<Node<T>, LinkedIndexUsize, N>,
    /// Buffer total capacity in bytes.
    capacity: usize,
    /// Used length in buffer in bytes.
    len: usize,
}

impl<T, const N: usize, const C: usize> PacketBuffer<T, N, C> {
    /// Builds a new `packet buffer`.
    pub fn new() -> PacketBuffer<T, N, C> {
        PacketBuffer {
            storage: LinkedList::new_usize(),
            capacity: C,
            len: 0,
        }
    }

    /// Returns the maximum number of bytes the buffer can hold.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of remaining free bytes available in the buffer.
    pub fn rem_capacity(&self) -> usize {
        self.capacity - self.len
    }

    /// Push a new element in the buffer.
    pub fn push(&mut self, packet: Node<T>, timestamp: Instant) -> Result<(), Node<T>> {
        // Remove expired packets.
        self.drop_expired(timestamp);

        // Check size
        if packet.size <= self.rem_capacity() {
            if self.storage.is_full() {
                // No slot available in the buffer, remove oldest packet.
                if let Ok(removed) = self.storage.pop_front() {
                    self.len -= removed.size;
                }
            }

            let size = packet.size;
            self.storage.push_back(packet)?;
            self.len += size;

            Ok(())
        } else {
            Err(packet)
        }
    }

    /// Drop expired packets.
    pub fn drop_expired(&mut self, timestamp: Instant) {
        self.storage.retain(|node| {
            let expired = node.expires_at >= timestamp;
            if expired {
                self.len -= node.size;
            }

            !expired
        });
    }

    /// Flushes the buffer.
    pub fn flush(&mut self, _timestamp: Instant) {}
}
