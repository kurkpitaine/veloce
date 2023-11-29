use super::{Error, Result};

/// A read/write wrapper around a Dynamic Host Configuration Protocol packet buffer.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::geonet::wire::field::*;

    pub const FRAME_CTRL: Field = 0..2;
    pub const DURATION_ID: Field = 2..4;
    pub const ADDR_1: Field = 4..10;
    pub const ADDR_2: Field = 10..16;
    pub const ADDR_3: Field = 16..22;
    pub const SEQ_CTRL: Field = 22..24;
    pub const QOS_CTRL: Field = 24..26;
    pub const LLC_SNAP: Rest = 26..;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with an IEEE 802.11 packet structure.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::SEQ_CTRL.end {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

/* struct ieee80211_hdr {
    __le16 frame_control;
    __le16 duration_id;
    struct_group(addrs,
        u8 addr1[ETH_ALEN];
        u8 addr2[ETH_ALEN];
        u8 addr3[ETH_ALEN];
    );
    __le16 seq_ctrl;
    u8 addr4[ETH_ALEN];
} __packed __aligned(2);

struct ieee80211_hdr_3addr {
    __le16 frame_control;
    __le16 duration_id;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    __le16 seq_ctrl;
} __packed __aligned(2);

struct ieee80211_qos_hdr {
    __le16 frame_control;
    __le16 duration_id;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    __le16 seq_ctrl;
    __le16 qos_ctrl;
} __packed __aligned(2);

struct ieee80211_qos_hdr_4addr {
    __le16 frame_control;
    __le16 duration_id;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    __le16 seq_ctrl;
    u8 addr4[ETH_ALEN];
    __le16 qos_ctrl;
} __packed __aligned(2);

struct ieee80211_trigger {
    __le16 frame_control;
    __le16 duration;
    u8 ra[ETH_ALEN];
    u8 ta[ETH_ALEN];
    __le64 common_info;
    u8 variable[];
} __packed __aligned(2); */
