use core::fmt;

use byteorder::{ByteOrder, LittleEndian};

use super::{Error, EthernetAddress, Result};

/// A two-octet Ieee 802.11 Frame Control.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct FrameControl(pub [u8; 2]);

impl FrameControl {
    /// Construct an Ieee 802.11 Frame Control
    pub const fn new(
        version: u8,
        r#type: u8,
        sub_type: u8,
        to_ds: bool,
        from_ds: bool,
        more_frag: bool,
        retry: bool,
        pwr_mgmt: bool,
        more_data: bool,
        prot_frame: bool,
        htc_or_order: bool,
    ) -> FrameControl {
        let mut fc = [0u8; 2];
        fc[0] |= version & 0x03;
        fc[0] |= (r#type << 2) & 0x0c;
        fc[0] |= sub_type << 4;

        if to_ds {
            fc[1] |= 0x01;
        } else {
            fc[1] &= !0x01;
        }

        if from_ds {
            fc[1] |= 0x02;
        } else {
            fc[1] &= !0x02;
        }

        if more_frag {
            fc[1] |= 0x04;
        } else {
            fc[1] &= !0x04;
        }

        if retry {
            fc[1] |= 0x08;
        } else {
            fc[1] &= !0x08;
        }

        if pwr_mgmt {
            fc[1] |= 0x10;
        } else {
            fc[1] &= !0x10;
        }

        if more_data {
            fc[1] |= 0x20;
        } else {
            fc[1] &= !0x20;
        }

        if prot_frame {
            fc[1] |= 0x40;
        } else {
            fc[1] &= !0x40;
        }

        if htc_or_order {
            fc[1] |= 0x80;
        } else {
            fc[1] &= !0x80;
        }

        FrameControl(fc)
    }

    /// Construct a Ieee 802.11 Frame Control from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not two octets long.
    pub fn from_bytes(data: &[u8]) -> FrameControl {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(data);
        FrameControl(bytes)
    }

    /// Return a Ieee 802.11 Frame Control as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the `protocol version` field.
    pub const fn protocol_version(&self) -> u8 {
        self.0[0] & 0x03
    }

    /// Set the `protocol version` field.
    pub fn set_protocol_version(&mut self, version: u8) {
        self.0[0] |= version & 0x03
    }

    /// Return the `type` field.
    pub const fn r#type(&self) -> u8 {
        (self.0[0] >> 2) & 0x03
    }

    /// Set the `type` field.
    pub fn set_type(&mut self, r#type: u8) {
        let raw = self.0[0] & !0x0c;
        let raw = raw | ((r#type << 2) & 0x0c);
        self.0[0] = raw
    }

    /// Return the `subtype` field.
    pub const fn sub_type(&self) -> u8 {
        self.0[0] >> 4
    }

    /// Set the `subtype` field.
    pub fn set_sub_type(&mut self, sub_type: u8) {
        let raw = self.0[0] & !0xf0;
        let raw = raw | (sub_type << 4);
        self.0[0] = raw
    }

    /// Return the `to DS` flag.
    pub const fn to_ds(&self) -> bool {
        (self.0[1] & 0x01) != 0
    }

    /// Set the `to DS` flag.
    pub fn set_to_ds(&mut self, to_ds: bool) {
        if to_ds {
            self.0[1] |= 0x01;
        } else {
            self.0[1] &= !0x01;
        }
    }

    /// Return the `from DS` flag.
    pub const fn from_ds(&self) -> bool {
        (self.0[1] & 0x02) != 0
    }

    /// Set the `from DS` flag.
    pub fn set_from_ds(&mut self, from_ds: bool) {
        if from_ds {
            self.0[1] |= 0x02;
        } else {
            self.0[1] &= !0x02;
        }
    }

    /// Return the `more fragments` flag.
    pub const fn more_fragments(&self) -> bool {
        (self.0[1] & 0x04) != 0
    }

    /// Set the `more fragments` flag.
    pub fn set_more_fragments(&mut self, more_fragments: bool) {
        if more_fragments {
            self.0[1] |= 0x04;
        } else {
            self.0[1] &= !0x04;
        }
    }

    /// Return the `retry` flag.
    pub const fn retry(&self) -> bool {
        (self.0[1] & 0x08) != 0
    }

    /// Set the `retry` flag.
    pub fn set_retry(&mut self, retry: bool) {
        if retry {
            self.0[1] |= 0x08;
        } else {
            self.0[1] &= !0x08;
        }
    }

    /// Return the `power management` flag.
    pub const fn power_mgmt(&self) -> bool {
        (self.0[1] & 0x10) != 0
    }

    /// Set the `power management` flag.
    pub fn set_power_mgmt(&mut self, power_mgmt: bool) {
        if power_mgmt {
            self.0[1] |= 0x10;
        } else {
            self.0[1] &= !0x10;
        }
    }

    /// Return the `more data` flag.
    pub const fn more_data(&self) -> bool {
        (self.0[1] & 0x20) != 0
    }

    /// Set the `more data` flag.
    pub fn set_more_data(&mut self, more_data: bool) {
        if more_data {
            self.0[1] |= 0x20;
        } else {
            self.0[1] &= !0x20;
        }
    }

    /// Return the `protected frame` flag.
    #[inline]
    pub const fn protected_frame(&self) -> bool {
        (self.0[1] & 0x40) != 0
    }

    /// Set the `protected frame` flag.
    pub fn set_protected_frame(&mut self, protected_frame: bool) {
        if protected_frame {
            self.0[1] |= 0x40;
        } else {
            self.0[1] &= !0x40;
        }
    }

    /// Return the `+HTC/order` flag.
    #[inline]
    pub const fn htc_or_order(&self) -> bool {
        (self.0[1] & 0x80) != 0
    }

    /// Set the `+HTC/order` flag.
    pub fn set_htc_or_order(&mut self, htc_or_order: bool) {
        if htc_or_order {
            self.0[1] |= 0x80;
        } else {
            self.0[1] &= !0x80;
        }
    }
}

impl fmt::Display for FrameControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Frame Control  version={} type={} subtype={} to_ds={} from_ds={} more_frag={} retry={} pwr_mgmt={} more_data={} prot_frame={} htc_or_order={}",
            self.protocol_version(),
            self.r#type(),
            self.sub_type(),
            self.to_ds(),
            self.from_ds(),
            self.more_fragments(),
            self.retry(),
            self.power_mgmt(),
            self.more_data(),
            self.protected_frame(),
            self.htc_or_order()
        )
    }
}

/// A two-octet Ieee 802.11 Sequence Control.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct SequenceControl(pub [u8; 2]);

impl SequenceControl {
    /// Construct an Ieee 802.11 Sequence Control
    pub fn new(frag_num: u8, seq_num: u16) -> SequenceControl {
        let mut sc = [0u8; 2];
        let raw = seq_num << 4;
        let raw = raw | (u16::from(frag_num) & 0x0f);
        LittleEndian::write_u16(&mut sc, raw);

        SequenceControl(sc)
    }

    /// Construct a Ieee 802.11 Sequence Control from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not two octets long.
    pub fn from_bytes(data: &[u8]) -> SequenceControl {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(data);
        SequenceControl(bytes)
    }

    /// Return a Ieee 802.11 Sequence Control as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the `fragment number` field.
    pub fn fragment_number(&self) -> u8 {
        let raw = LittleEndian::read_u16(&self.0) & 0x0f;
        raw as u8
    }

    /// Set the `fragment number` field.
    pub fn set_fragment_number(&mut self, frag_number: u8) {
        let raw = LittleEndian::read_u16(&self.0) & !0x0f;
        let raw = raw | (u16::from(frag_number) & 0x0f);
        LittleEndian::write_u16(&mut self.0, raw);
    }

    /// Return the `sequence number` field.
    pub fn sequence_number(&self) -> u16 {
        LittleEndian::read_u16(&self.0) >> 4
    }

    /// Set the `sequence number` field.
    pub fn set_sequence_number(&mut self, seq_number: u16) {
        let raw = LittleEndian::read_u16(&self.0) & !0xfff0;
        let raw = raw | (seq_number << 4);
        LittleEndian::write_u16(&mut self.0, raw);
    }
}

impl fmt::Display for SequenceControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Sequence Control  fragment_number={} sequence_number={}",
            self.fragment_number(),
            self.sequence_number(),
        )
    }
}

/// A two-octet Ieee 802.11 QoS Control.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct QoSControl(pub [u8; 2]);

impl QoSControl {
    /// Construct an Ieee 802.11 QoS Control
    pub fn new(tc_id: u8, bit_4: bool, ack_policy: u8, bit_7: bool, byte_1: u8) -> QoSControl {
        let mut qc = [0u8; 2];
        qc[0] |= tc_id & 0x0f;

        if bit_4 {
            qc[0] |= 0x10;
        } else {
            qc[0] &= !0x10;
        }

        qc[0] |= (ack_policy & 0x03) << 5;

        if bit_7 {
            qc[0] |= 0x80;
        } else {
            qc[0] &= !0x80;
        }

        qc[1] = byte_1;

        QoSControl(qc)
    }

    /// Construct a Ieee 802.11 QoS Control from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not two octets long.
    pub fn from_bytes(data: &[u8]) -> QoSControl {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(data);
        QoSControl(bytes)
    }

    /// Return a Ieee 802.11 QoS Control as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the QoS `traffic class ID` field.
    pub fn tc_id(&self) -> u8 {
        self.0[0] & 0x0f
    }

    /// Set the QoS `traffic class ID` field.
    pub fn set_tc_id(&mut self, tc_id: u8) {
        let raw = self.0[0] & !0x0f;
        let raw = raw | (tc_id & 0x0f);
        self.0[0] = raw;
    }

    /// Return the QoS `bit 4` flag.
    /// This flag has not the same meaning depending on frame type.
    pub fn bit_4(&self) -> bool {
        (self.0[0] & 0x10) != 0
    }

    /// Set the QoS `bit 4` flag.
    pub fn set_bit_4(&mut self, bit_4: bool) {
        if bit_4 {
            self.0[0] |= 0x10;
        } else {
            self.0[0] &= !0x10;
        }
    }

    /// Return the QoS `Ack policy` field.
    pub fn ack_policy(&self) -> u8 {
        let raw = (self.0[0] >> 5) & 0x03;
        raw as u8
    }

    /// Set the QoS `Ack policy` field.
    pub fn set_ack_policy(&mut self, ack_policy: u8) {
        let raw = self.0[0] & !0x60;
        let raw = raw | ((ack_policy & 0x03) << 5);
        self.0[0] = raw;
    }

    /// Return the QoS `bit 7` flag.
    /// This flag has not the same meaning depending on frame type.
    pub fn bit_7(&self) -> bool {
        self.0[0] & 0x80 != 0
    }

    /// Set the QoS `bit 7` flag.
    pub fn set_bit_7(&mut self, bit_7: bool) {
        if bit_7 {
            self.0[0] |= 0x80;
        } else {
            self.0[0] &= !0x80;
        }
    }

    /// Return the QoS second byte field.
    /// This field has not the same meaning depending on frame type
    /// and `bit_4` value.
    pub fn byte_1(&self) -> u8 {
        self.0[1]
    }

    /// Set the QoS second byte field.
    pub fn set_byte_1(&mut self, byte_1: u8) {
        self.0[1] = byte_1;
    }
}

impl fmt::Display for QoSControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "QoS Control  tc_id={} bit_4={} ack_policy={} bit_7={} byte_1={}",
            self.tc_id(),
            self.bit_4(),
            self.ack_policy(),
            self.bit_7(),
            self.byte_1(),
        )
    }
}

/// A read/write wrapper around an Ieee802.11 frame buffer.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header<T: AsRef<[u8]>> {
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
}

/// Length of an Ieee 802.11 with QoS header.
pub const HEADER_LEN: usize = field::QOS_CTRL.end;

impl<T: AsRef<[u8]>> Header<T> {
    /// Imbue a raw octet buffer with an IEEE 802.11 packet structure.
    pub const fn new_unchecked(buffer: T) -> Header<T> {
        Header { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
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
        if len < field::QOS_CTRL.end {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the `frame control` field.
    #[inline]
    pub fn frame_control(&self) -> FrameControl {
        let data = self.buffer.as_ref();
        FrameControl::from_bytes(&data[field::FRAME_CTRL])
    }

    /// Return the `duration/ID` field.
    #[inline]
    pub fn duration_or_id(&self) -> u16 {
        let data = self.buffer.as_ref();
        LittleEndian::read_u16(&data[field::DURATION_ID])
    }

    /// Return the `address 1` field.
    #[inline]
    pub fn address_1(&self) -> EthernetAddress {
        let data = self.buffer.as_ref();
        EthernetAddress::from_bytes(&data[field::ADDR_1])
    }

    /// Return the `address 2` field.
    #[inline]
    pub fn address_2(&self) -> EthernetAddress {
        let data = self.buffer.as_ref();
        EthernetAddress::from_bytes(&data[field::ADDR_2])
    }

    /// Return the `address 3` field.
    #[inline]
    pub fn address_3(&self) -> EthernetAddress {
        let data = self.buffer.as_ref();
        EthernetAddress::from_bytes(&data[field::ADDR_3])
    }

    /// Return the `sequence control` field.
    #[inline]
    pub fn sequence_control(&self) -> SequenceControl {
        let data = self.buffer.as_ref();
        SequenceControl::from_bytes(&data[field::SEQ_CTRL])
    }

    /// Return the `QoS control` field.
    #[inline]
    pub fn qos_control(&self) -> QoSControl {
        let data = self.buffer.as_ref();
        QoSControl::from_bytes(&data[field::QOS_CTRL])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the `frame control` field.
    #[inline]
    pub fn set_frame_control(&mut self, value: FrameControl) {
        let data = self.buffer.as_mut();
        data[field::FRAME_CTRL].copy_from_slice(value.as_bytes());
    }

    /// Set the `duration/ID` field.
    #[inline]
    pub fn set_duration_or_id(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u16(&mut data[field::DURATION_ID], value);
    }

    /// Set the `address 1` field.
    #[inline]
    pub fn set_address_1(&mut self, value: EthernetAddress) {
        let data = self.buffer.as_mut();
        data[field::ADDR_1].copy_from_slice(value.as_bytes());
    }

    /// Set the `address 2` field.
    #[inline]
    pub fn set_address_2(&mut self, value: EthernetAddress) {
        let data = self.buffer.as_mut();
        data[field::ADDR_2].copy_from_slice(value.as_bytes());
    }

    /// Set the `address 3` field.
    #[inline]
    pub fn set_address_3(&mut self, value: EthernetAddress) {
        let data = self.buffer.as_mut();
        data[field::ADDR_3].copy_from_slice(value.as_bytes());
    }

    /// Set the `sequence control` field.
    #[inline]
    pub fn set_sequence_control(&mut self, value: SequenceControl) {
        let data = self.buffer.as_mut();
        data[field::SEQ_CTRL].copy_from_slice(value.as_bytes());
    }

    /// Set the `qos control` field.
    #[inline]
    pub fn set_qos_control(&mut self, value: QoSControl) {
        let data = self.buffer.as_mut();
        data[field::QOS_CTRL].copy_from_slice(value.as_bytes());
    }
}

/// A high-level representation of an Ieee 802.11 QoS header.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    /// The frame control field.
    pub frame_control: FrameControl,
    /// The duration or id field.
    pub duration_or_id: u16,
    /// The destination address field.
    pub dst_addr: EthernetAddress,
    /// The source address field.
    pub src_addr: EthernetAddress,
    /// The basic subsystem id field.
    pub bss_id: EthernetAddress,
    /// The sequence control field.
    pub sequence_control: SequenceControl,
    /// The QoS control field.
    pub qos_control: QoSControl,
}

impl Repr {
    /// Parse an Ieee 802.11 QoS Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            frame_control: header.frame_control(),
            duration_or_id: header.duration_or_id(),
            dst_addr: header.address_1(),
            src_addr: header.address_2(),
            bss_id: header.address_3(),
            sequence_control: header.sequence_control(),
            qos_control: header.qos_control(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into an Ieee 802.11 QoS header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_frame_control(self.frame_control);
        header.set_duration_or_id(self.duration_or_id);
        header.set_address_1(self.dst_addr);
        header.set_address_2(self.src_addr);
        header.set_address_3(self.bss_id);
        header.set_sequence_control(self.sequence_control);
        header.set_qos_control(self.qos_control);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "802.11 QoS frame_control={} duration_or_id={} dst_addr={} src_addr={} bss_id={} sequence_control={} qos_control={}",
            self.frame_control, self.duration_or_id, self.dst_addr, self.src_addr, self.bss_id, self.sequence_control, self.qos_control,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// An Ieee 802.11 with QoS header bytes.
    static IEEE_80211_QOS_BYTES_HEADER: [u8; 26] = [
        0x88, 0x00, 0x30, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x62, 0xa0, 0x72, 0x0e, 0x30,
        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x90, 0x02, 0x23, 0x00,
    ];

    /// An Ieee 802.11 Frame Control bytes.
    static FRAME_CTRL_BYTES: [u8; 2] = [0x88, 0x00];

    /// An Ieee 802.11 Sequence Control bytes.
    static SEQ_CTRL_BYTES: [u8; 2] = [0x90, 0x02];

    /// An Ieee 802.11 QoS Control bytes.
    static QOS_CTRL_BYTES: [u8; 2] = [0x23, 0x00];

    fn ieee_80211_repr() -> Repr {
        Repr {
            frame_control: FrameControl::new(
                0, 2, 8, false, false, false, false, false, false, false, false,
            ),
            duration_or_id: 48,
            dst_addr: EthernetAddress::BROADCAST,
            src_addr: EthernetAddress::new(0x62, 0xa0, 0x72, 0x0e, 0x30, 0x00),
            bss_id: EthernetAddress::BROADCAST,
            sequence_control: SequenceControl::new(0, 41),
            qos_control: QoSControl::new(3, false, 1, false, 0),
        }
    }

    #[test]
    fn test_frame_ctrl_new() {
        let frame_ctrl = FrameControl::new(
            0, 2, 8, false, false, false, false, false, false, false, false,
        );

        assert_eq!(frame_ctrl.as_bytes(), FRAME_CTRL_BYTES);
    }

    #[test]
    fn test_frame_ctrl_from_bytes() {
        let frame_ctrl = FrameControl::from_bytes(&FRAME_CTRL_BYTES);
        assert_eq!(frame_ctrl.protocol_version(), 0);
        assert_eq!(frame_ctrl.r#type(), 2);
        assert_eq!(frame_ctrl.sub_type(), 8);
        assert_eq!(frame_ctrl.to_ds(), false);
        assert_eq!(frame_ctrl.from_ds(), false);
        assert_eq!(frame_ctrl.more_fragments(), false);
        assert_eq!(frame_ctrl.retry(), false);
        assert_eq!(frame_ctrl.power_mgmt(), false);
        assert_eq!(frame_ctrl.more_data(), false);
        assert_eq!(frame_ctrl.protected_frame(), false);
        assert_eq!(frame_ctrl.htc_or_order(), false);
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_frame_ctrl_from_bytes_too_long() {
        let _ = FrameControl::from_bytes(&[0u8; 4]);
    }

    #[test]
    fn test_sequence_ctrl_new() {
        let seq_ctrl = SequenceControl::new(0, 41);

        assert_eq!(seq_ctrl.as_bytes(), SEQ_CTRL_BYTES);
    }

    #[test]
    fn test_sequence_ctrl_from_bytes() {
        let seq_ctrl = SequenceControl::from_bytes(&SEQ_CTRL_BYTES);
        assert_eq!(seq_ctrl.fragment_number(), 0);
        assert_eq!(seq_ctrl.sequence_number(), 41);
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_sequence_ctrl_from_bytes_too_long() {
        let _ = SequenceControl::from_bytes(&[0u8; 3]);
    }

    #[test]
    fn test_qos_ctrl_new() {
        let qos_ctrl = QoSControl::new(3, false, 1, false, 0);

        assert_eq!(qos_ctrl.as_bytes(), QOS_CTRL_BYTES);
    }

    #[test]
    fn test_qos_ctrl_from_bytes() {
        let seq_ctrl = QoSControl::from_bytes(&QOS_CTRL_BYTES);
        assert_eq!(seq_ctrl.tc_id(), 3);
        assert_eq!(seq_ctrl.bit_4(), false);
        assert_eq!(seq_ctrl.ack_policy(), 1);
        assert_eq!(seq_ctrl.bit_7(), false);
        assert_eq!(seq_ctrl.byte_1(), 0);
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_qos_ctrl_from_bytes_too_long() {
        let _ = QoSControl::from_bytes(&[0u8; 3]);
    }

    #[test]
    fn test_80211_check_len() {
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&IEEE_80211_QOS_BYTES_HEADER[..25]).check_len()
        );

        assert_eq!(
            Ok(()),
            Header::new_unchecked(&IEEE_80211_QOS_BYTES_HEADER).check_len()
        );
    }

    #[test]
    fn test_80211_deconstruct() {
        let header = Header::new_unchecked(&IEEE_80211_QOS_BYTES_HEADER);
        assert_eq!(header.frame_control(), ieee_80211_repr().frame_control);
        assert_eq!(header.duration_or_id(), 48);
        assert_eq!(header.address_1(), EthernetAddress::BROADCAST);
        assert_eq!(
            header.address_2(),
            EthernetAddress::new(0x62, 0xa0, 0x72, 0x0e, 0x30, 0x00)
        );
        assert_eq!(header.address_3(), EthernetAddress::BROADCAST);
        assert_eq!(
            header.sequence_control(),
            ieee_80211_repr().sequence_control
        );
        assert_eq!(header.qos_control(), ieee_80211_repr().qos_control);
    }

    #[test]
    fn test_80211_repr_parse_valid() {
        let header = Header::new_unchecked(&IEEE_80211_QOS_BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr, ieee_80211_repr());
    }

    #[test]
    fn test_80211_repr_emit() {
        let repr = ieee_80211_repr();
        let mut bytes = [0u8; HEADER_LEN];
        let mut hdr = Header::new_unchecked(&mut bytes);
        repr.emit(&mut hdr);
        assert_eq!(hdr.into_inner(), &IEEE_80211_QOS_BYTES_HEADER);
    }

    #[test]
    fn test_80211_buffer_len() {
        let header = Header::new_unchecked(&IEEE_80211_QOS_BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), IEEE_80211_QOS_BYTES_HEADER.len());
    }
}
