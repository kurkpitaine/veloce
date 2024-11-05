#[cfg(not(feature = "std"))]
use alloc::collections::vec_deque::VecDeque;

#[cfg(feature = "std")]
use std::collections::VecDeque;

use crate::time::{Duration, Instant};
use core::fmt;

/// Trait stored metadata structures must implement.
pub trait BufferMeta: fmt::Debug {
    fn size(&self) -> usize;
    fn lifetime(&self) -> Duration;
}

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
    payload: Vec<u8>,
}

impl<T> Node<T>
where
    T: BufferMeta,
{
    /// Accessor to metadata.
    pub fn metadata(&self) -> &T {
        &self.metadata
    }

    /// Mutable accessor to metadata.
    pub fn metadata_mut(&mut self) -> &mut T {
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
pub struct PacketBuffer<T, const C: usize>
where
    T: BufferMeta,
{
    /// Buffer underlying storage.
    storage: VecDeque<Node<T>>,
    /// Buffer total capacity in bytes.
    capacity: usize,
    /// Used length in buffer in bytes.
    len: usize,
}

impl<T, const C: usize> Default for PacketBuffer<T, C>
where
    T: BufferMeta,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const C: usize> PacketBuffer<T, C>
where
    T: BufferMeta,
{
    /// Builds a new `packet buffer`.
    pub fn new() -> PacketBuffer<T, C> {
        PacketBuffer {
            storage: VecDeque::new(),
            capacity: C,
            len: 0,
        }
    }

    /// Self explaining.
    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.storage.is_empty()
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
        let node = Node {
            size: meta.size(),
            expires_at: timestamp + meta.lifetime(),
            flushable: false,
            metadata: meta,
            payload: Vec::new(),
        };

        self.push(node, timestamp)
            .map(|n| n.payload.extend_from_slice(payload))
            .map_err(|_| PacketBufferError::PacketTooBig)?;

        Ok(())
    }

    /// Push a new element in the buffer. Returns a mutable reference on the pushed element.
    fn push(&mut self, node: Node<T>, timestamp: Instant) -> Result<&mut Node<T>, TooBig> {
        // Remove expired packets.
        self.drop_expired(timestamp);

        // Check packet could fit in the buffer
        if node.size > self.capacity() {
            return Err(TooBig);
        }

        // Buffer could be full by: no sufficient bytes available.
        // This check ensure the packet will fit in terms of bytes.
        while node.size > self.rem_capacity() {
            if let Some(removed) = self.storage.pop_front() {
                self.len -= removed.size;
            }
        }

        let size = node.size;
        self.storage.push_back(node);
        self.len += size;

        Ok(self.storage.back_mut().unwrap_or_else(|| unreachable!()))
    }

    /// Drop expired packets.
    fn drop_expired(&mut self, timestamp: Instant) {
        self.storage.retain(|node| {
            let expired = node.expires_at <= timestamp;
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
            if node.expires_at <= timestamp {
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
        let (pos, fm) = self
            .storage
            .iter_mut()
            .enumerate()
            .find(|(_, e)| e.flushable)?;

        let rc = f(fm);
        self.len -= fm.size;
        self.storage.remove(pos);

        Some(rc)
    }

    /// Dequeue one packet from the buffer.
    pub fn dequeue_one<F, E, S>(&mut self, f: F) -> Option<Result<S, E>>
    where
        F: FnOnce(&mut Node<T>) -> Result<S, E>,
    {
        let mut node = self.storage.pop_front()?;
        let rc = f(&mut node);
        self.len -= node.size;

        Some(rc)
    }

    /// Remove all the elements from the buffer.
    pub fn clear(&mut self) {
        self.storage.clear();
        self.len = 0;
    }
}

/// Too Big packet error. Used when a packet cannot fit in the buffer.
pub struct TooBig;

/// Error returned by `enqueue()`.
pub enum PacketBufferError {
    /// Packet is too big to fit in buffer.
    PacketTooBig,
}
