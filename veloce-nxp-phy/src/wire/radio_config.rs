use byteorder::{ByteOrder, LittleEndian};
use uom::si::{f32::Frequency, frequency::megahertz};

use super::{Antenna, Bandwidth, DualTxControl, Header, Message, RadioMode, Status, TxPower, MCS};
use crate::{
    time::Duration,
    wire::{field::Field, EthernetAddress, Result},
};

mod field {
    use crate::wire::field::*;

    // Channel config
    /// Channel centre frequency (in MHz) that should be used e.g. 5000 + (5*172).
    pub const CFG_PHY_CHAN_FREQ: Field = 0..2;
    /// Indicate if channel is 10 MHz or 20 MHz.
    pub const CFG_PHY_BW: usize = 2;
    /// Default Transmit antenna configuration.
    /// Antenna selection used for transmission of ACK/CTS.
    pub const CFG_PHY_TX_ANT: usize = 3;
    /// Receive antenna configuration.
    pub const CFG_PHY_RX_ANT: usize = 4;
    /// Indicate the default data rate that should be used.
    pub const CFG_PHY_MCS: usize = 5;
    /// Indicate the default transmit power that should be used.
    /// Power setting used for Transmission of ACK/CTS.
    pub const CFG_PHY_TX_PWR: Field = 6..8;
    /// Dual Radio transmit control (inactive in single radio configurations).
    pub const CFG_MAC_DUAL_TX_CTRL: usize = 8;
    /// The RSSI power detection threshold for carrier sense [dBm].
    pub const CFG_MAC_CS_THRESHOLD: usize = 9;
    /// The CBR threshold [dBm].
    pub const CFG_MAC_CBR_THRESHOLD: usize = 10;
    /// 32-bit alignment.
    pub const CFG_MAC_PADDING: Field = 11..14;
    /// Slot time/duration, per 802.11-2012.
    pub const CFG_MAC_SLOT_TIME: Field = 14..16;
    /// Distributed interframe space, per 802.11-2012.
    pub const CFG_MAC_DIFS_TIME: Field = 16..18;
    /// Short interframe space, per 802.11-2012.
    pub const CFG_MAC_SIFS_TIME: Field = 18..20;
    /// Duration to wait after an erroneously received frame,
    /// before beginning slot periods.
    /// @note this should be set to EIFS - DIFS.
    pub const CFG_MAC_EIFS_TIME: Field = 20..22;
    /// Threshold at which RTS/CTS is used for unicast packets (bytes).
    pub const CFG_MAC_RTSCTS_THRESHOLD: Field = 22..24;
    /// Retry limit for short unicast transmissions.
    pub const CFG_MAC_SHORT_RETRY_LIM: Field = 24..26;
    /// Retry limit for long unicast transmissions.
    pub const CFG_MAC_LONG_RETRY_LIM: Field = 26..28;
    /// Non QoS (for WSAs etc.) queue configuration.
    pub const CFG_MAC_TXQ_NON_QOS: Field = 28..36;
    /// Voice queue configuration.
    pub const CFG_MAC_TXQ_AC_VO: Field = 36..44;
    /// Video queue configuration.
    pub const CFG_MAC_TXQ_AC_VI: Field = 44..52;
    /// Best effort queue configuration.
    pub const CFG_MAC_TXQ_AC_BE: Field = 52..60;
    /// Background queue configuration.
    pub const CFG_MAC_TXQ_AC_BK: Field = 60..68;
    /// Address matching filters: DA, broadcast, unicast & multicast.
    /// Address matching filter 0.
    pub const CFG_MAC_AMS_TABLE_0: Field = 68..84;
    /// Address matching filter 1.
    pub const CFG_MAC_AMS_TABLE_1: Field = 84..100;
    /// Address matching filter 2.
    pub const CFG_MAC_AMS_TABLE_2: Field = 100..116;
    /// Address matching filter 3.
    pub const CFG_MAC_AMS_TABLE_3: Field = 116..132;
    /// Address matching filter 4.
    pub const CFG_MAC_AMS_TABLE_4: Field = 132..148;
    /// Address matching filter 5.
    pub const CFG_MAC_AMS_TABLE_5: Field = 148..164;
    /// Address matching filter 6.
    pub const CFG_MAC_AMS_TABLE_6: Field = 164..180;
    /// Address matching filter 7.
    pub const CFG_MAC_AMS_TABLE_7: Field = 180..196;
    /// Duration of this channel interval, in microseconds. Zero means forever.
    /// Also sets the interval between stats messages sent.
    pub const CFG_LLC_INTERVAL_DURATION: Field = 196..200;
    /// Duration of guard interval upon entering this channel, in microseconds
    pub const CFG_LLC_GUARD_DURATION: Field = 200..204;

    // Tx Queue configuration.
    /// Arbitration inter-frame-spacing (values of 0 to 16).
    pub const CFG_TXQ_AIFS: usize = 0;
    /// Padding to ensure 32 bit alignment.
    pub const CFG_TXQ_PADDING: usize = 1;
    /// Contention window min.
    pub const CFG_TXQ_CWMIN: Field = 2..4;
    /// Contention window max.
    pub const CFG_TXQ_CWMAX: Field = 4..6;
    /// TXOP duration limit [ms].
    pub const CFG_TXQ_TXOP: Field = 6..8;

    // Address matching.
    /// 48 bit mask to apply to DA before comparing with Addr field.
    pub const CFG_ADDR_MATCH_MASK: Field = 0..6;
    /// Align to 64 bit boundary.
    pub const CFG_ADDR_MATCH_PAD_0: Field = 6..8;
    /// 48 bit MAC address to match after masking.
    pub const CFG_ADDR_MATCH_ADDR: Field = 8..14;
    /// Bitmask. See AddressMatchingCtrl.
    pub const CFG_ADDR_MATCH_CTRL: usize = 14;
    /// Align to 64 bit boundary.
    pub const CFG_ADDR_MATCH_PAD_1: usize = 15;
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Operation mode of the radio.
    #[inline]
    pub fn cfg_radio_mode(&self) -> RadioMode {
        let data = self.buffer.as_ref();
        let data = LittleEndian::read_u16(&data[super::field::CFG_RADIO_MODE]);
        RadioMode::from(data)
    }

    /// System clock tick rate in MHz, a read-only field.
    /// Only when reading config from the radio chip.
    #[inline]
    pub fn cfg_clock_freq(&self) -> Frequency {
        let data = self.buffer.as_ref();
        let data = LittleEndian::read_u16(&data[super::field::CFG_CLOCK_FREQ]);
        Frequency::new::<megahertz>(data as f32)
    }
}

impl<T: AsRef<[u8]> + ?Sized> Header<&T> {
    /// Return a pointer to the Channel 0 configuration.
    #[inline]
    pub fn cfg_channel_0(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[super::field::CFG_CHAN_0]
    }

    /// Return a pointer to the Channel 1 configuration.
    #[inline]
    pub fn cfg_channel_1(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[super::field::CFG_CHAN_1]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the operation mode of the radio.
    #[inline]
    pub fn set_cfg_radio_mode(&mut self, value: RadioMode) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u16(&mut data[super::field::CFG_RADIO_MODE], value.into());
    }

    /// Return a mutable pointer to the Channel 0 configuration.
    #[inline]
    pub fn cfg_channel_0_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[super::field::CFG_CHAN_0]
    }

    /// Return a mutable pointer to the Channel 1 configuration.
    #[inline]
    pub fn cfg_channel_1_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[super::field::CFG_CHAN_1]
    }
}

/// A high-level representation of an NXP LLC RadioConfigData header.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RadioConfigRepr {
    /// Operation mode of the radio.
    pub mode: RadioMode,
    /// System clock tick rate in MHz, a read-only field.
    pub clock_freq: Frequency,
    /// Channel 0 config.
    pub channel0: ChannelConfig,
    /// Channel 1 config.
    pub channel1: ChannelConfig,
}

impl RadioConfigRepr {
    /// Return the length of the RadioXCfg header that will be emitted from a RadioConfigRepr.
    pub const fn header_len() -> usize {
        field::CFG_LLC_GUARD_DURATION.end + super::field::RET.end
    }

    /// Parse an NXP LLC RadioConfig header and return
    /// a high-level representation.
    pub fn parse<T>(llc: &Header<&T>) -> Result<RadioConfigRepr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(RadioConfigRepr {
            mode: llc.cfg_radio_mode(),
            clock_freq: llc.cfg_clock_freq(),
            channel0: ChannelConfig::parse(&ConfigBuf::new_unchecked(llc.cfg_channel_0()))?,
            channel1: ChannelConfig::parse(&ConfigBuf::new_unchecked(llc.cfg_channel_1()))?,
        })
    }

    /// Emit a high-level representation into a
    /// RadioConfig header.
    /// For a RadioACfg message.
    pub fn emit_radio_a<T>(&self, header: &mut Header<&mut T>, seq_num: u16, ref_num: u16)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        header.set_msg_type(Message::RadioACfg);
        self.emit(header, seq_num, ref_num);
    }

    /// Emit a high-level representation into a
    /// RadioConfig header.
    /// For a RadioBCfg message.
    pub fn emit_radio_b<T>(&self, header: &mut Header<&mut T>, seq_num: u16, ref_num: u16)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        header.set_msg_type(Message::RadioBCfg);
        self.emit(header, seq_num, ref_num);
    }

    fn emit<T>(&self, header: &mut Header<&mut T>, seq_num: u16, ref_num: u16)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        header.set_cfg_radio_mode(self.mode.into());
        header.set_msg_len(RadioConfigRepr::header_len());
        header.set_seq_num(seq_num);
        header.set_ref_num(ref_num);
        header.set_ret(Status::Reserved);
        header.clear_reserved();
        header.set_cfg_radio_mode(self.mode);
        self.channel0
            .emit(&mut ConfigBuf::new_unchecked(header.cfg_channel_0_mut()));
        self.channel1
            .emit(&mut ConfigBuf::new_unchecked(header.cfg_channel_1_mut()));
    }
}

/// A generic buffer.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConfigBuf<T: AsRef<[u8]>> {
    /// The underlying buffer.
    buffer: T,
}

impl<T: AsRef<[u8]>> ConfigBuf<T> {
    /// Constructs a new [`ConfigBuf`].
    pub fn new_unchecked(buffer: T) -> ConfigBuf<T> {
        ConfigBuf { buffer }
    }

    /// Read one byte at `idx`.
    #[inline]
    pub fn read_byte(&self, idx: usize) -> u8 {
        let data = self.buffer.as_ref();
        data[idx]
    }

    /// Read a `range` of bytes.
    #[inline]
    pub fn read_field(&self, range: Field) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ConfigBuf<T> {
    /// Write one byte `value` at `idx`.
    #[inline]
    pub fn byte_mut(&mut self, idx: usize) -> &mut u8 {
        let raw = self.buffer.as_mut();
        &mut raw[idx]
    }

    /// Return a mutable pointer on data at `range`.
    #[inline]
    pub fn field_mut(&mut self, range: Field) -> &mut [u8] {
        let raw = self.buffer.as_mut();
        &mut raw[range]
    }
}

/// A high-level representation of an NXP LLC ChanConfig header.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelConfig {
    /// PHY specific config.
    pub phy: PhyConfig,
    /// MAC specific config.
    pub mac: MacConfig,
    /// LLC (WMAC) specific config
    pub llc: LLCConfig,
}

impl ChannelConfig {
    /// Parse a [`ChannelConfig`] from a [`ConfigBuf`].
    pub fn parse<T>(buffer: &ConfigBuf<&T>) -> Result<ChannelConfig>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let channel_freq = Frequency::new::<megahertz>(LittleEndian::read_u16(
            buffer.read_field(field::CFG_PHY_CHAN_FREQ),
        ) as f32);
        let phy = PhyConfig {
            channel_freq,
            bandwidth: Bandwidth::from(buffer.read_byte(field::CFG_PHY_BW)),
            tx_antenna: Antenna::from(buffer.read_byte(field::CFG_PHY_TX_ANT)),
            rx_antenna: Antenna::from(buffer.read_byte(field::CFG_PHY_RX_ANT)),
            mcs: MCS::from(buffer.read_byte(field::CFG_PHY_MCS)),
            tx_pwr: TxPower::from(LittleEndian::read_i16(
                buffer.read_field(field::CFG_PHY_TX_PWR),
            )),
        };

        let txq_non_qos = TxQueueCfg::parse(&ConfigBuf::new_unchecked(
            buffer.read_field(field::CFG_MAC_TXQ_NON_QOS),
        ))?;
        let txq_ac_vo = TxQueueCfg::parse(&ConfigBuf::new_unchecked(
            buffer.read_field(field::CFG_MAC_TXQ_AC_VO),
        ))?;
        let txq_ac_vi = TxQueueCfg::parse(&ConfigBuf::new_unchecked(
            buffer.read_field(field::CFG_MAC_TXQ_AC_VI),
        ))?;
        let txq_ac_be = TxQueueCfg::parse(&ConfigBuf::new_unchecked(
            buffer.read_field(field::CFG_MAC_TXQ_AC_BE),
        ))?;
        let txq_ac_bk = TxQueueCfg::parse(&ConfigBuf::new_unchecked(
            buffer.read_field(field::CFG_MAC_TXQ_AC_BK),
        ))?;

        let amf_tables = [
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_0),
            ))?,
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_1),
            ))?,
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_2),
            ))?,
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_3),
            ))?,
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_4),
            ))?,
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_5),
            ))?,
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_6),
            ))?,
            AddressMatching::parse(&ConfigBuf::new_unchecked(
                buffer.read_field(field::CFG_MAC_AMS_TABLE_7),
            ))?,
        ];

        let mac = MacConfig {
            dual_tx_ctrl: DualTxControl::from(buffer.read_byte(field::CFG_MAC_DUAL_TX_CTRL)),
            cs_threshold: buffer.read_byte(field::CFG_MAC_CS_THRESHOLD) as i8,
            cbr_threshold: buffer.read_byte(field::CFG_MAC_CBR_THRESHOLD) as i8,
            slot_time: LittleEndian::read_u16(buffer.read_field(field::CFG_MAC_SLOT_TIME)),
            difs_time: LittleEndian::read_u16(buffer.read_field(field::CFG_MAC_DIFS_TIME)),
            sifs_time: LittleEndian::read_u16(buffer.read_field(field::CFG_MAC_SIFS_TIME)),
            eifs_time: LittleEndian::read_u16(buffer.read_field(field::CFG_MAC_EIFS_TIME)),
            rts_cts_threshold: LittleEndian::read_u16(
                buffer.read_field(field::CFG_MAC_RTSCTS_THRESHOLD),
            )
            .into(),
            short_retry_limit: LittleEndian::read_u16(
                buffer.read_field(field::CFG_MAC_SHORT_RETRY_LIM),
            ),
            long_retry_limit: LittleEndian::read_u16(
                buffer.read_field(field::CFG_MAC_LONG_RETRY_LIM),
            ),
            txq_non_qos,
            txq_ac_vo,
            txq_ac_vi,
            txq_ac_be,
            txq_ac_bk,
            amf_tables,
        };

        let llc = LLCConfig {
            interval: Duration::from_micros(
                LittleEndian::read_u32(&buffer.read_field(field::CFG_LLC_INTERVAL_DURATION)).into(),
            ),
            guard: Duration::from_micros(
                LittleEndian::read_u32(&buffer.read_field(field::CFG_LLC_GUARD_DURATION)).into(),
            ),
        };

        Ok(ChannelConfig { phy, mac, llc })
    }

    /// Emit a [`ChannelConfig`] into a [`ConfigBuf`].
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: &mut ConfigBuf<T>) {
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_PHY_CHAN_FREQ),
            self.phy.channel_freq.get::<megahertz>() as u16,
        );
        *buffer.byte_mut(field::CFG_PHY_BW) = self.phy.bandwidth.into();
        *buffer.byte_mut(field::CFG_PHY_TX_ANT) = self.phy.tx_antenna.into();
        *buffer.byte_mut(field::CFG_PHY_RX_ANT) = self.phy.rx_antenna.into();
        *buffer.byte_mut(field::CFG_PHY_MCS) = self.phy.mcs.into();
        LittleEndian::write_i16(
            buffer.field_mut(field::CFG_PHY_TX_PWR),
            self.phy.tx_pwr.into(),
        );
        buffer
            .field_mut(field::CFG_MAC_PADDING)
            .copy_from_slice(&[0, 0, 0]);

        *buffer.byte_mut(field::CFG_MAC_DUAL_TX_CTRL) = self.mac.dual_tx_ctrl.into();
        *buffer.byte_mut(field::CFG_MAC_CS_THRESHOLD) = self.mac.cs_threshold as u8;
        *buffer.byte_mut(field::CFG_MAC_CBR_THRESHOLD) = self.mac.cbr_threshold as u8;
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_MAC_SLOT_TIME),
            self.mac.slot_time,
        );
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_MAC_DIFS_TIME),
            self.mac.difs_time,
        );
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_MAC_SIFS_TIME),
            self.mac.sifs_time,
        );
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_MAC_EIFS_TIME),
            self.mac.eifs_time,
        );
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_MAC_RTSCTS_THRESHOLD),
            self.mac.rts_cts_threshold as u16,
        );
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_MAC_SHORT_RETRY_LIM),
            self.mac.short_retry_limit,
        );
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_MAC_LONG_RETRY_LIM),
            self.mac.long_retry_limit,
        );

        self.mac.txq_non_qos.emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_TXQ_NON_QOS),
        ));
        self.mac.txq_ac_vo.emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_TXQ_AC_VO),
        ));
        self.mac.txq_ac_vi.emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_TXQ_AC_VI),
        ));
        self.mac.txq_ac_be.emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_TXQ_AC_BE),
        ));
        self.mac.txq_ac_bk.emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_TXQ_AC_BK),
        ));

        self.mac.amf_tables[0].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_0),
        ));
        self.mac.amf_tables[1].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_1),
        ));
        self.mac.amf_tables[2].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_2),
        ));
        self.mac.amf_tables[3].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_3),
        ));
        self.mac.amf_tables[4].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_4),
        ));
        self.mac.amf_tables[5].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_5),
        ));
        self.mac.amf_tables[6].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_6),
        ));
        self.mac.amf_tables[7].emit(&mut ConfigBuf::new_unchecked(
            buffer.field_mut(field::CFG_MAC_AMS_TABLE_7),
        ));

        LittleEndian::write_u32(
            buffer.field_mut(field::CFG_LLC_INTERVAL_DURATION),
            self.llc.interval.micros() as u32,
        );
        LittleEndian::write_u32(
            buffer.field_mut(field::CFG_LLC_GUARD_DURATION),
            self.llc.guard.micros() as u32,
        );
    }
}

/// A representation of a PhyCfg.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PhyConfig {
    /// Channel centre frequency (in MHz) that should be used e.g. 5000 + (5*172)
    pub channel_freq: Frequency,
    /// Indicate if channel is 10 MHz or 20 MHz.
    pub bandwidth: Bandwidth,
    /// Default Transmit antenna configuration
    /// (can be overridden in @ref tMKxTxPacket).
    /// Antenna selection used for transmission of ACK/CTS.
    pub tx_antenna: Antenna,
    /// Receive antenna configuration.
    pub rx_antenna: Antenna,
    /// Indicate the default data rate that should be used.
    pub mcs: MCS,
    /// Indicate the default transmit power that should be used.
    /// Power setting used for Transmission of ACK/CTS.
    pub tx_pwr: TxPower,
}

/// A representation of a MacConfig.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MacConfig {
    /// Dual Radio transmit control (inactive in single radio configurations)
    pub dual_tx_ctrl: DualTxControl,
    /// The RSSI power detection threshold for carrier sense [dBm]
    pub cs_threshold: i8,
    /// The CBR threshold [dBm]
    pub cbr_threshold: i8,
    /// Slot time/duration, per 802.11-2012
    pub slot_time: u16,
    /// Distributed interframe space, per 802.11-2012
    pub difs_time: u16,
    /// Short interframe space, per 802.11-2012
    pub sifs_time: u16,
    /// Duration to wait after an erroneously received frame,
    /// before beginning slot periods
    /// This should be set to EIFS - DIFS
    pub eifs_time: u16,
    /// Threshold at which RTS/CTS is used for unicast packets (bytes).
    pub rts_cts_threshold: usize,
    /// Retry limit for short unicast transmissions
    pub short_retry_limit: u16,
    /// Retry limit for long unicast transmissions
    pub long_retry_limit: u16,
    /// Non QoS (for WSAs etc.) queue configuration.
    pub txq_non_qos: TxQueueCfg,
    /// Voice queue configuration.
    pub txq_ac_vo: TxQueueCfg,
    /// Video queue configuration.
    pub txq_ac_vi: TxQueueCfg,
    /// Best effort queue configuration.
    pub txq_ac_be: TxQueueCfg,
    /// Background queue configuration.
    pub txq_ac_bk: TxQueueCfg,
    /// Address matching filters: DA, broadcast, unicast & multicast
    pub amf_tables: [AddressMatching; 8],
}

/// A representation of a LLCConfig.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LLCConfig {
    /// Duration of this channel interval. Zero means forever.
    /// Also sets the interval between stats messages sent.
    interval: Duration,
    /// Duration of guard interval upon entering this channel.
    guard: Duration,
}

/// A representation of a TxQueueConfig.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxQueueCfg {
    /// Arbitration inter-frame-spacing (values of 0 to 16).
    pub aifs: u8,
    /// Contention window min.
    pub cw_min: u16,
    /// Contention window max.
    pub cw_max: u16,
    /// TXOP duration limit.
    pub tx_op: Duration,
}

impl TxQueueCfg {
    /// Parse a [`TxQueueCfg`] from a [`ConfigBuf`].
    pub fn parse<T: AsRef<[u8]> + ?Sized>(buffer: &ConfigBuf<&T>) -> Result<TxQueueCfg> {
        Ok(TxQueueCfg {
            aifs: buffer.read_byte(field::CFG_TXQ_AIFS),
            cw_min: LittleEndian::read_u16(buffer.read_field(field::CFG_TXQ_CWMIN)),
            cw_max: LittleEndian::read_u16(buffer.read_field(field::CFG_TXQ_CWMAX)),
            tx_op: Duration::from_millis(
                LittleEndian::read_u16(buffer.read_field(field::CFG_TXQ_TXOP)).into(),
            ),
        })
    }

    /// Emit a [`TxQueueCfg`] into a [`ConfigBuf`].
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: &mut ConfigBuf<T>) {
        *buffer.byte_mut(field::CFG_TXQ_PADDING) = 0;
        *buffer.byte_mut(field::CFG_TXQ_AIFS) = self.aifs;
        LittleEndian::write_u16(buffer.field_mut(field::CFG_TXQ_CWMIN), self.cw_min);
        LittleEndian::write_u16(buffer.field_mut(field::CFG_TXQ_CWMAX), self.cw_max);
        LittleEndian::write_u16(
            buffer.field_mut(field::CFG_TXQ_TXOP),
            self.tx_op.millis() as u16,
        );
    }
}

///
/// Receive frame address matching structure
///
/// General operation of the MKx on receive frame:
/// - bitwise AND of 'Mask' and the incoming frame's DA (DA not modified)
/// - equality check between 'Addr' and the masked DA
/// - If equal: continue
///  - If 'ResponseEnable' is set: Send 'ACK'
///  - If 'BufferEnableCtrl' is set: Copy into internal buffer
///                                  & deliver via RxInd() if FCS check passes
///  - If 'BufferEnableBadFCS' is set: Deliver via RxInd() even if FCS check
///    fails
///
/// To receive broadcast frames:
/// - Addr = 0XFFFFFFFFFFFFULL
/// - Mask = 0XFFFFFFFFFFFFULL
/// - MatchCtrl = 0x0000
/// To receive anonymous IEEE1609 heartbeat (multicast) frames:
/// - Addr = 0X000000000000ULL
/// - Mask = 0XFFFFFFFFFFFFULL
/// - MatchCtrl = 0x0000
/// To receive valid unicast frames for 01:23:45:67:89:AB (our MAC address)
/// - Addr = 0XAB8967452301ULL
/// - Mask = 0XFFFFFFFFFFFFULL
/// - MatchCtrl = 0x0001
/// To monitor the channel in promiscuous mode (including failed FCS frames,
/// and all duplicates):
/// - Addr = 0X000000000000ULL
/// - Mask = 0X000000000000ULL
/// - MatchCtrl = 0x0016
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddressMatching {
    /// 48 bit mask to apply to DA before comparing with Addr field.
    pub mask: EthernetAddress,
    /// 48 bit MAC address to match after masking.
    pub addr: EthernetAddress,
    /// Matching control.
    pub ctrl: AddressMatchingCtrl,
}

impl AddressMatching {
    /// Parse a [`AddressMatching`] from a [`ConfigBuf`].
    pub fn parse<T: AsRef<[u8]> + ?Sized>(buffer: &ConfigBuf<&T>) -> Result<AddressMatching> {
        Ok(AddressMatching {
            mask: EthernetAddress::from_bytes(buffer.read_field(field::CFG_ADDR_MATCH_MASK)),
            addr: EthernetAddress::from_bytes(buffer.read_field(field::CFG_ADDR_MATCH_ADDR)),
            ctrl: AddressMatchingCtrl(buffer.read_byte(field::CFG_ADDR_MATCH_CTRL)),
        })
    }

    /// Emit a [`AddressMatching`] into a [`ConfigBuf`].
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: &mut ConfigBuf<T>) {
        buffer
            .field_mut(field::CFG_ADDR_MATCH_PAD_0)
            .copy_from_slice(&[0, 0]);
        *buffer.byte_mut(field::CFG_ADDR_MATCH_PAD_1) = 0;

        buffer
            .field_mut(field::CFG_ADDR_MATCH_MASK)
            .copy_from_slice(self.mask.as_bytes());
        buffer
            .field_mut(field::CFG_ADDR_MATCH_ADDR)
            .copy_from_slice(self.addr.as_bytes());
        *buffer.byte_mut(field::CFG_ADDR_MATCH_CTRL) = self.ctrl.0;
    }
}

/// A representation of a AddressMatchingCtrl.
/// Address matching control bits
/// - (bit 0) = ResponseEnable
/// - (bit 1) = BufferEnableCtrl
/// - (bit 2) = BufferEnableBadFCS
/// - (bit 3) = LastEntry
/// - (bit 4) = BufferDuplicate
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddressMatchingCtrl(u8);

impl AddressMatchingCtrl {
    /// Return wether ResponseEnable flag is set,
    /// ie: Respond with ACK when a DATA frame is matched.
    pub fn response_enable(&self) -> bool {
        let bit = self.0 & 0x01;
        if bit == 1 {
            true
        } else {
            false
        }
    }

    /// Return wether BufferEnableCtrl flag is set,
    /// ie: Buffer control frames that match.
    pub fn buffer_enable_ctrl(&self) -> bool {
        let bit: u8 = self.0 & 0x02;

        if bit > 1 {
            true
        } else {
            false
        }
    }

    /// Return wether BufferEnableBadFCS flag is set,
    /// ie: Buffer frames even if FCS error was detected.
    pub fn bad_fcs(&self) -> bool {
        let bit: u8 = self.0 & 0x04;
        if bit > 1 {
            true
        } else {
            false
        }
    }

    /// Return wether LastEntry flag is set,
    /// ie: Indicates this is the last entry in the table.
    pub fn last_entry(&self) -> bool {
        let bit: u8 = self.0 & 0x08;
        if bit > 1 {
            true
        } else {
            false
        }
    }

    /// Return wether BufferDuplicate flag is set,
    /// ie: Buffer duplicate frames.
    pub fn buffer_duplicate(&self) -> bool {
        let bit: u8 = self.0 & 0x10;
        if bit > 1 {
            true
        } else {
            false
        }
    }

    /// Set the ResponseEnable flag,
    /// ie: Respond with ACK when a DATA frame is matched.
    pub fn set_response_enable(&mut self, value: bool) {
        if value {
            self.0 | 0x01
        } else {
            self.0 & !0x01
        };
    }

    /// Set the BufferEnableCtrl flag,
    /// ie: Buffer control frames that match.
    pub fn set_buffer_enable_ctrl(&mut self, value: bool) {
        if value {
            self.0 | 0x02
        } else {
            self.0 & !0x02
        };
    }

    /// Set the BufferEnableBadFCS flag,
    /// ie: Buffer frames even if FCS error was detected.
    pub fn set_bad_fcs(&mut self, value: bool) {
        if value {
            self.0 | 0x04
        } else {
            self.0 & !0x04
        };
    }

    /// Set the LastEntry flag,
    /// ie: Indicates this is the last entry in the table.
    pub fn set_last_entry(&mut self, value: bool) {
        if value {
            self.0 | 0x08
        } else {
            self.0 & !0x08
        };
    }

    /// Set the BufferDuplicate flag,
    /// ie: Buffer duplicate frames.
    pub fn set_buffer_duplicate(&self, value: bool) {
        if value {
            self.0 | 0x10
        } else {
            self.0 & !0x10
        };
    }
}
