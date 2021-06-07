use crate::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::position_vector::Long as LongPositionVector;

/// A read/write wrapper around a Geonetworking Beacon Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// See ETSI EN 302 636-4-1 V1.4.1 chapter 9.8.6.2 for details about fields
mod field {
    use crate::wire::field::*;
    // 24-octet Source Position Vector of the Geonetworking Beacon Header.
    pub const SO_PV: Field = 0..24;
}

impl<T: AsRef<[u8]>> Header<T> {
   /// Create a raw octet buffer with a Geonetworking Beacon Header structure.
   pub fn new_unchecked(buffer: T) -> Header<T> {
       Header { buffer }
   }

   /// Shorthand for a combination of [new_unchecked] and [check_len].
   ///
   /// [new_unchecked]: #method.new_unchecked
   /// [check_len]: #method.check_len
   pub fn new_checked(buffer: T) -> Result<Header<T>> {
       let header = Self::new_unchecked(buffer);
       header.check_len()?;
       Ok(header)
   }

   /// Ensure that no accessor method will panic if called.
   /// Returns `Err(Error::Truncated)` if the buffer is too short.
   pub fn check_len(&self) -> Result<()> {
       let data = self.buffer.as_ref();
       let len = data.len();

       if len < field::SO_PV.end {
           Err(Error::Truncated)
       } else {
           Ok(())
       }
   }

   /// Consume the header, returning the underlying buffer.
   pub fn into_inner(self) -> T {
       self.buffer
   }

   /// Return the next header field.
   #[inline]
   pub fn position_vector(&self) -> LongPositionVector {
       let data = self.buffer.as_ref();
       LongPositionVector::new_checked(data)?
   }
}
