use byteorder::{ByteOrder, LittleEndian};
use uom::si::{f32::Frequency, frequency::hertz};

use super::{field, Channel, Header, Message, Radio, RxPower, MCS};
use crate::wire::{Error, Result};

impl<T: AsRef<[u8]>> Header<T> {
    /// Return the radio channel which received the packet.
    #[inline]
    pub fn rx_channel(&self) -> Channel {
        let data = self.buffer.as_ref();
        Channel::from(data[field::RX_CHAN])
    }

    /// Return the radio which received the packet.
    #[inline]
    pub fn rx_radio(&self) -> Radio {
        let data = self.buffer.as_ref();
        Radio::from(data[field::RX_RADIO])
    }

    /// Return the data rate that was used.
    #[inline]
    pub fn rx_mcs(&self) -> MCS {
        let data = self.buffer.as_ref();
        MCS::from(data[field::RX_MCS])
    }

    /// Return if the frame passed the checksum verification.
    #[inline]
    pub fn rx_fcs_pass(&self) -> bool {
        let data = self.buffer.as_ref();
        if data[field::RX_FCS_PASS] > 1 {
            true
        } else {
            false
        }
    }

    /// Return the received power on Antenna 1 in 0.5dBm units.
    #[inline]
    pub fn rx_pwr_ant_1(&self) -> RxPower {
        let data = self.buffer.as_ref();
        let data = LittleEndian::read_i16(&data[field::RX_PWR_ANT1]);
        RxPower::from(data)
    }

    /// Return the received power on Antenna 2 in 0.5dBm units.
    #[inline]
    pub fn rx_pwr_ant_2(&self) -> RxPower {
        let data = self.buffer.as_ref();
        let data = LittleEndian::read_i16(&data[field::RX_PWR_ANT2]);
        RxPower::from(data)
    }

    /// Return the receiver noise on Antenna 1 in 0.5dBm units.
    #[inline]
    pub fn rx_noise_ant_1(&self) -> RxPower {
        let data = self.buffer.as_ref();
        let data = LittleEndian::read_i16(&data[field::RX_NOI_ANT1]);
        RxPower::from(data)
    }

    /// Return the receiver noise on Antenna 2 in 0.5dBm units.
    #[inline]
    pub fn rx_noise_ant_2(&self) -> RxPower {
        let data = self.buffer.as_ref();
        let data = LittleEndian::read_i16(&data[field::RX_NOI_ANT2]);
        RxPower::from(data)
    }

    /// Return the estimated frequency offset of rx frame in Hz
    /// (with respect to local freq).
    #[inline]
    pub fn rx_freq_offset(&self) -> i32 {
        let data = self.buffer.as_ref();
        LittleEndian::read_i32(&data[field::RX_FREQ_OFFSET])
    }

    /// Return the MAC Rx Timestamp, local MAC TSF time at which
    /// the packet was received.
    #[inline]
    pub fn rx_tst(&self) -> u64 {
        let data = self.buffer.as_ref();
        LittleEndian::read_u64(&data[field::RX_TST])
    }

    /// Return the Length of the Frame (802.11 Header + Body, including FCS).
    #[inline]
    pub fn rx_frame_len(&self) -> usize {
        let data = self.buffer.as_ref();
        LittleEndian::read_u16(&data[field::RX_FRAME_LEN]).into()
    }

    /// Return the Channel centre frequency on which the packet was received.
    #[inline]
    pub fn rx_channel_freq(&self) -> u16 {
        let data = self.buffer.as_ref();
        LittleEndian::read_u16(&data[field::RX_CHAN_FREQ])
    }
}

/// A high-level representation of an NXP LLC RxPacket header.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxPacketRepr {
    /// Indicate the radio where the packet was received.
    pub radio: Radio,
    /// Indicate the channel config for the selected radio.
    pub channel: Channel,
    /// Indicate the data rate that was used.
    pub modulation: MCS,
    /// Indicates FCS passed for received frame, ie: if the
    /// frame is correct.
    pub correct: bool,
    /// Indicate the received power on Antenna 1 in 0.5dBm units.
    pub power_ant_1: RxPower,
    /// Indicate the received power on Antenna 2 in 0.5dBm units.
    pub power_ant_2: RxPower,
    /// Indicate the receiver noise on Antenna 1 in 0.5dBm units.
    pub noise_ant_1: RxPower,
    /// Indicate the receiver noise on Antenna 2 in 0.5dBm units.
    pub noise_ant_2: RxPower,
    /// Channel centre frequency on which this packet was received.
    pub frequency: Frequency,
    /// Estimated frequency offset of rx frame (with respect to local freq).
    pub frequency_offset: Frequency,
    /// MAC Rx Timestamp, local MAC TSF time at which packet was received.
    pub mac_timestamp: u64,
}

impl RxPacketRepr {
    /// Parse an NXP LLC header RxPacket and return
    /// a high-level representation.
    pub fn parse<T>(llc: &Header<&T>) -> Result<RxPacketRepr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        llc.check_len()?;

        match llc.msg_type() {
            Message::RxPacket => Ok(RxPacketRepr {
                radio: llc.rx_radio(),
                channel: llc.rx_channel(),
                modulation: llc.rx_mcs(),
                correct: llc.rx_fcs_pass(),
                power_ant_1: llc.rx_pwr_ant_1(),
                power_ant_2: llc.rx_pwr_ant_2(),
                noise_ant_1: llc.rx_noise_ant_1(),
                noise_ant_2: llc.rx_noise_ant_2(),
                frequency: Frequency::new::<hertz>(llc.rx_channel_freq().into()),
                frequency_offset: Frequency::new::<hertz>(llc.rx_freq_offset() as f32),
                mac_timestamp: llc.rx_tst(),
            }),
            _ => Err(Error),
        }
    }
}
