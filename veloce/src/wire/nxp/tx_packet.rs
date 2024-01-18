use byteorder::{ByteOrder, LittleEndian};

use super::{field, Antenna, Channel, Header, Message, Radio, Status, TxControl, TxPower, MCS};

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the radio that should be used.
    #[inline]
    pub fn set_tx_radio(&mut self, value: Radio) {
        let data = self.buffer.as_mut();
        data[field::TX_RADIO] = value.into();
    }

    /// Set the channel config for the selected radio.
    #[inline]
    pub fn set_tx_channel(&mut self, value: Channel) {
        let data = self.buffer.as_mut();
        data[field::TX_CHAN] = value.into();
    }

    /// Set the antennas upon which packet should be transmitted.
    #[inline]
    pub fn set_tx_antenna(&mut self, value: Antenna) {
        let data = self.buffer.as_mut();
        data[field::TX_ANT] = value.into();
    }

    /// Set the MCS to be used (may specify default).
    #[inline]
    pub fn set_tx_mcs(&mut self, value: MCS) {
        let data = self.buffer.as_mut();
        data[field::TX_MCS] = value.into();
    }

    /// Set the power to be used (may specify default).
    #[inline]
    pub fn set_tx_pwr(&mut self, value: TxPower) {
        let data = self.buffer.as_mut();
        LittleEndian::write_i16(&mut data[field::TX_PWR], value.into());
    }

    /// Set additional control over the transmitter behaviour.
    #[inline]
    pub fn set_tx_ctrl(&mut self, value: TxControl) {
        let data = self.buffer.as_mut();
        data[field::TX_CTRL] = value.into();
    }

    /// Set the expiry time as an absolute MAC time in microseconds.
    /// (0 means never).
    #[inline]
    pub fn set_tx_expiry(&mut self, value: u64) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u64(&mut data[field::TX_EXPIRY], value);
    }

    /// Set the length of the frame to transmirt
    /// (802.11 Header + Body, not including FCS).
    #[inline]
    pub fn set_tx_length(&mut self, value: usize) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u16(&mut data[field::TX_LEN], value as u16);
    }
}

/// A high-level representation of an NXP LLC TxPacket header.
#[derive(Default, Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxPacketRepr {
    /// Indicate the radio that should be used.
    pub radio: Radio,
    /// Indicate the channel config for the selected radio.
    pub channel: Channel,
    /// Indicate the antennas upon which packet should be transmitted.
    pub antenna: Antenna,
    /// Indicate the MCS to be used.
    pub modulation: MCS,
    /// Indicate the power to be used in 0.5dBm units.
    pub power: TxPower,
    /// Additional control over the transmitter behaviour.
    pub control: TxControl,
    /// Indicate the expiry time as an absolute MAC time in microseconds.
    pub expiry: u64,
}

impl TxPacketRepr {
    /// Return the length of the TxPacket header that will be emitted from a TxPacketRepr.
    pub const fn header_len() -> usize {
        field::TX_PAYLOAD.start
    }

    /// Emit a high-level representation into a NXP LLC TxPacket Header.
    /// `payload_len` is the length of the frame to transmit
    /// (802.11 Header + Body, not including FCS).
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        header: &mut Header<T>,
        seq_num: u16,
        ref_num: u16,
        payload_len: usize,
    ) {
        header.set_msg_type(Message::TxPacket);
        header.set_msg_len(TxPacketRepr::header_len() + payload_len);
        header.set_seq_num(seq_num);
        header.set_ref_num(ref_num);
        header.set_ret(Status::Reserved);
        header.clear_reserved();
        header.set_tx_radio(self.radio);
        header.set_tx_channel(self.channel);
        header.set_tx_antenna(self.antenna);
        header.set_tx_mcs(self.modulation);
        header.set_tx_pwr(self.power);
        header.set_tx_ctrl(self.control);
        header.set_tx_expiry(self.expiry);
        header.set_tx_length(payload_len);
    }
}
