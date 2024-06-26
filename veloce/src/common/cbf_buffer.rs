use core::ops::DerefMut;
use heapless::linked_list::{LinkedIndexUsize, LinkedList};

use crate::config::GN_MAX_SDU_SIZE;
use crate::time::{Duration, Instant};
use crate::wire::{EthernetAddress, GnAddress, SequenceNumber};

use super::packet_buffer::BufferMeta;

/// Packet identifier inside CBF buffer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct CbfIdentifier(pub GnAddress, pub SequenceNumber);

pub const PAYLOAD_MAX_SIZE: usize = GN_MAX_SDU_SIZE;

/// CBF buffer node.
#[derive(Debug)]
pub struct Node<T>
where
    T: BufferMeta,
{
    /// CBF packet identifier.
    cbf_identifier: CbfIdentifier,
    /// CBF timer expiration time.
    pub cbf_expires_at: Instant,
    /// CBF retransmit counter.
    pub cbf_counter: u8,
    /// Sender Mac Address.
    sender: EthernetAddress,
    /// Size of the packet, headers including payload.
    size: usize,
    /// Time at which the packet lifetime expires.
    expires_at: Instant,
    /// Packet headers, without payload.
    metadata: T,
    /// Packet payload.
    payload: [u8; PAYLOAD_MAX_SIZE],
}

impl<T> Node<T>
where
    T: BufferMeta,
{
    pub const fn payload_max_size() -> usize {
        PAYLOAD_MAX_SIZE
    }

    /// CBF packet identifier inside buffer.
    pub fn cbf_identifier(&self) -> CbfIdentifier {
        self.cbf_identifier
    }

    /// Sender of the packet.
    pub fn sender(&self) -> EthernetAddress {
        self.sender
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
pub struct ContentionBuffer<T, const N: usize, const C: usize>
where
    T: BufferMeta,
{
    /// Buffer underlying storage.
    storage: LinkedList<Node<T>, LinkedIndexUsize, N>,
    /// Buffer total capacity in bytes.
    capacity: usize,
    /// Used length in buffer in bytes.
    len: usize,
    /// Instant at which to poll the buffer.
    poll_at: Option<Instant>,
}

impl<T, const N: usize, const C: usize> ContentionBuffer<T, N, C>
where
    T: BufferMeta,
{
    /// Builds a new `packet buffer`.
    pub fn new() -> ContentionBuffer<T, N, C> {
        ContentionBuffer {
            storage: LinkedList::new_usize(),
            capacity: C,
            len: 0,
            poll_at: None,
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
        cbf_id: CbfIdentifier,
        cbf_timer: Duration,
        timestamp: Instant,
        sender: EthernetAddress,
    ) -> Result<(), PacketBufferError> {
        // Check payload length vs Node payload capacity.
        if payload.len() > Node::<T>::payload_max_size() {
            return Err(PacketBufferError::PayloadTooLong);
        }

        let mut node = Node {
            cbf_identifier: cbf_id,
            cbf_expires_at: timestamp + cbf_timer,
            cbf_counter: 1,
            sender,
            size: meta.size(),
            expires_at: timestamp + meta.lifetime(),
            metadata: meta,
            payload: [0; PAYLOAD_MAX_SIZE],
        };

        // TODO: improve this. We should copy only if the push is ok.
        // Make push return a reference on the pushed element.
        node.payload[0..payload.len()].copy_from_slice(payload);

        self.push(node)
            .map_err(|_| PacketBufferError::PacketTooBig)?;

        self.update_poll();

        Ok(())
    }

    /// Push a new element in the buffer.
    fn push(&mut self, node: Node<T>) -> Result<(), TooBig> {
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

    /// Removes packet identified by `id` from CBF buffer.
    /// Returns `true` if the packet was in the buffer.
    pub fn remove(&mut self, id: CbfIdentifier) -> bool {
        match self.storage.find_mut(|n| n.cbf_identifier == id) {
            Some(p) => {
                p.pop();
                self.update_poll();
                true
            }
            None => false,
        }
    }

    /// Find an element identified by `id` that can be popped.
    /// Returns `true` if an element has been popped.
    pub fn pop_if<F>(&mut self, id: CbfIdentifier, f: F) -> Option<bool>
    where
        F: FnOnce(&mut Node<T>) -> bool,
    {
        let Some(mut fm) = self.storage.find_mut(|n| n.cbf_identifier == id) else {
            return None;
        };

        let rc = if f(fm.deref_mut()) {
            fm.pop();
            Some(true)
        } else {
            Some(false)
        };

        self.update_poll();
        rc
    }

    /// Dequeue one packet whose CBF timer has expired.
    pub fn dequeue_expired<F, E>(&mut self, timestamp: Instant, f: F) -> Option<Result<(), E>>
    where
        F: FnOnce(&mut Node<T>) -> Result<(), E>,
    {
        let Some(mut fm) = self.storage.find_mut(|e| e.cbf_expires_at >= timestamp) else {
            return None;
        };

        let rc = f(fm.deref_mut());
        fm.pop();

        Some(rc)
    }

    /// Update polling Instant of the buffer.
    fn update_poll(&mut self) {
        self.poll_at = self.storage.iter().map(|e| e.cbf_expires_at).min();
    }

    /// Return the Instant the contention buffer should be polled at.
    pub fn poll_at(&self) -> Option<Instant> {
        self.poll_at
    }

    /// Remove all the elements from the buffer.
    pub fn clear(&mut self) {
        self.storage.clear();
        self.len = 0;
        self.poll_at = None;
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
