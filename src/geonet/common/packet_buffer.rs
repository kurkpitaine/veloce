use core::ops::DerefMut;
use heapless::linked_list::{LinkedIndexUsize, LinkedList};
use heapless::Vec;

use crate::geonet::config::GN_MAX_SDU_SIZE;
use crate::geonet::time::{Duration, Instant};

/// Trait stored metadata structures must implement.
pub trait BufferMeta {
    fn size(&self) -> usize;
    fn lifetime(&self) -> Duration;
}

pub const PAYLOAD_MAX_SIZE: usize = GN_MAX_SDU_SIZE;

/// Packet buffer node.
#[derive(Debug)]
pub struct Node<T>
where
    T: BufferMeta,
{
    size: usize,
    expires_at: Instant,
    flushable: bool,
    metadata: T,
    payload: [u8; PAYLOAD_MAX_SIZE],
}

impl<T> Node<T>
where
    T: BufferMeta,
{
    pub const fn payload_max_size() -> usize {
        PAYLOAD_MAX_SIZE
    }

    /// Accessor to metadata.
    pub fn metadata(&mut self) -> &mut T {
        &mut self.metadata
    }

    /// Instant at which the nodes expires.
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Accessor to payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Generic packet buffer.
#[derive(Debug)]
pub struct PacketBuffer<T, const N: usize, const C: usize>
where
    T: BufferMeta,
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
    T: BufferMeta,
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
            expires_at: timestamp + meta.lifetime(),
            flushable: false,
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

    /// Drops only the packets where the predicate is true
    pub fn drop_with<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Node<T>) -> bool,
    {
        self.storage.retain_mut(|node| {
            let to_drop = f(node);
            if to_drop {
                self.len -= node.size;
            }

            !to_drop
        })
    }

    /// Mark flushable only the packets specified by the predicate `f`, passing a mutable reference to it.
    /// Expired packets are ignored and dropped.
    /// This method marks the specified packets as ready to flush. Packets are removed from buffer
    /// when [flush_one] is called.
    pub fn mark_flush<F>(&mut self, timestamp: Instant, mut f: F)
    where
        F: FnMut(&mut Node<T>) -> bool,
    {
        self.storage.retain_mut(|node| {
            // Filter expired packets
            if node.expires_at >= timestamp {
                self.len -= node.size;
                return false;
            }
            if f(node) {
                node.flushable = true;
            }
            true
        });
    }

    /// Flush one packet marked as flushable from the buffer.
    pub fn flush_one<F, E>(&mut self, f: F) -> Option<Result<(), E>>
    where
        F: FnOnce(&mut Node<T>) -> Result<(), E>,
    {
        let Some(mut fm) = self.storage.find_mut(|e| e.flushable) else {
            return None;
        };

        let rc = f(fm.deref_mut());
        fm.pop();

        Some(rc)
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
