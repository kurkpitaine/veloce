use core::ops::Bound;
use core::ops::RangeBounds;

/// Random number generator.
/// Adapted and improved from Smoltcp https://github.com/smoltcp-rs/smoltcp
#[derive(Debug)]
pub struct Rand {
    state: u64,
}

impl Rand {
    /// Build a new random number generator.
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generates a random number within a range.
    pub fn rand_range<R: RangeBounds<u32>>(&mut self, range: R) -> u32 {
        let start = match range.start_bound() {
            Bound::Included(i) => *i,
            Bound::Excluded(i) => *i + 1,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(e) => *e,
            Bound::Excluded(e) => *e + 1,
            Bound::Unbounded => u32::MAX,
        };

        // Normalize number into range.
        let generated = self.rand_u32();
        let factor = u32::MAX / end;
        generated / factor
    }

    /// Generates a random u32 integer.
    pub fn rand_u32(&mut self) -> u32 {
        // sPCG32 from https://www.pcg-random.org/paper.html
        // see also https://nullprogram.com/blog/2017/09/21/
        const M: u64 = 0xbb2efcec3c39611d;
        const A: u64 = 0x7590ef39;

        let s = self.state.wrapping_mul(M).wrapping_add(A);
        self.state = s;

        let shift = 29 - (s >> 61);
        (s >> shift) as u32
    }

    /// Generates a random u16 integer.
    pub fn rand_u16(&mut self) -> u16 {
        let n = self.rand_u32();
        (n ^ (n >> 16)) as u16
    }

    /// Generates a random Mac Address-sized bytes slice.
    pub fn rand_mac_addr(&mut self) -> [u8; 6] {
        let begin = self.rand_u32().to_ne_bytes();
        let end = self.rand_u16().to_ne_bytes();
        let mut addr = [0u8; 6];
        addr[..4].copy_from_slice(&begin);
        addr[4..].copy_from_slice(&end);
        // Clear multicast and locally administered bits.
        addr[0] &= !0x03;
        addr
    }
}
