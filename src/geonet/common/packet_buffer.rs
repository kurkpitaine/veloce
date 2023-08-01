use heapless::linked_list::{LinkedIndexUsize, LinkedList};

use crate::geonet::config::GN_MAX_SDU_SIZE;
use crate::geonet::time::{Duration, Instant};

/// Trait stored metadata structures must implement.
pub trait PacketMeta {
    fn size(&self) -> usize;
    fn lifetime(&self) -> Duration;
}

pub const PAYLOAD_MAX_SIZE: usize = GN_MAX_SDU_SIZE;

/// Packet buffer node.
#[derive(Debug)]
pub struct Node<T>
where
    T: PacketMeta,
{
    size: usize,
    inserted_at: Instant,
    expires_at: Instant,
    metadata: T,
    payload: [u8; PAYLOAD_MAX_SIZE],
}

impl<T> Node<T>
where
    T: PacketMeta,
{
    pub const fn payload_max_size() -> usize {
        PAYLOAD_MAX_SIZE
    }

    /// Accessor to metadata.
    pub fn metadata(&self) -> &T {
        &self.metadata
    }
}

/// Generic packet buffer.
pub struct PacketBuffer<T, const N: usize, const C: usize>
where
    T: PacketMeta,
{
    /// Buffer underlying storage.
    storage: LinkedList<Node<T>, LinkedIndexUsize, N>,
    /// Buffer total capacity in bytes.
    capacity: usize,
    /// Used length in buffer in bytes.
    len: usize,
}

impl<T, const N: usize, const C: usize> PacketBuffer<T, N, C>
where
    T: PacketMeta,
{
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

    /// Enqueue a new packet in the buffer.
    /// Packet is described in `meta`.
    pub fn enqueue(
        &mut self,
        meta: T,
        payload: &[u8],
        timestamp: Instant,
    ) -> Result<(), PacketBufferError> {
        // Check payload length vs Node payload capacity.
        if payload.len() > Node::<T>::payload_max_size() {
            return Err(PacketBufferError::PayloadTooLong);
        }

        let mut node = Node {
            size: meta.size(),
            inserted_at: timestamp,
            expires_at: timestamp + meta.lifetime(),
            metadata: meta,
            payload: [0; PAYLOAD_MAX_SIZE],
        };

        node.payload[0..payload.len()].copy_from_slice(payload);

        self.push(node, timestamp)
            .map_err(|_| PacketBufferError::PacketTooBig)?;

        Ok(())
    }

    /// Push a new element in the buffer.
    pub fn push(&mut self, node: Node<T>, timestamp: Instant) -> Result<(), TooBig> {
        // Remove expired packets.
        self.drop_expired(timestamp);

        // Check packet could fit in the buffer
        if node.size > self.capacity() {
            return Err(TooBig);
        }

        // Buffer could be full either by: no sufficient bytes available or no slots available.
        // The first check ensure the packet will fit in terms of bytes.
        while node.size > self.rem_capacity() {
            if let Ok(removed) = self.storage.pop_front() {
                self.len -= removed.size;
            }
        }

        // The second check ensure the packet will fit in terms slots.
        if self.storage.is_full() {
            // No slot available in the buffer, remove oldest packet.
            if let Ok(removed) = self.storage.pop_front() {
                self.len -= removed.size;
            }
        }

        let size = node.size;
        // Safety: we have checked the buffer is not full.
        unsafe { self.storage.push_back_unchecked(node) };
        self.len += size;

        Ok(())
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

    /// Flushes the buffer entirely.
    pub fn flush(&mut self, _timestamp: Instant) {}

    /// Flushes only the packets specified by the predicate, passing a mutable reference to it.
    pub fn flush_with<F>(&mut self, _timestamp: Instant, mut f: F)
    where
        F: FnMut(&mut Node<T>) -> bool,
    {
        self.storage.retain_mut(|node| f(node));
    }
}

/// Too Big packet error. Used when a packet cannot fit in the buffer.
pub struct TooBig;

/// Error returned by `enqueue()`.
pub enum PacketBufferError {
    /// Payload is too long.
    PayloadTooLong,
    /// Packet is too big to fit in buffer.
    PacketTooBig,
}
