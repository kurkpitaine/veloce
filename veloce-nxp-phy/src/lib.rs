#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use core::fmt;

pub mod llc;
pub mod usb;
//pub mod usb2;
pub mod usb_phy;
//pub mod usb_phy2;

pub use self::{Channel as NxpChannel, Config as NxpConfig, Radio as NxpRadio, WirelessChannel as NxpWirelessChannel};
pub use llc::NxpLlcDevice;
pub use usb::NxpUsbDevice;
use veloce::{types::Power, wire::EthernetAddress};

/// Max raw frame array size.
pub const RAW_FRAME_LENGTH_MAX: usize = 1518;
/// NXP LLC Tx/Rx buffer length.
pub const LLC_BUFFER_LEN: usize = 4096;

#[derive(Debug)]
pub enum Error {
    /// Operation has expired.
    Timeout,
    /// No Rx packet in buffer.
    NoRxPacket,
    /// An error occured during USB operation.
    USB, /* (UsbError) */
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Timeout => f.write_str("timeout"),
            Error::NoRxPacket => f.write_str("no rx packet in buffer"),
            Error::USB => f.write_str("USB error"),
            //Error::USB(e) => write!(f, "USB: {}", e),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// NXP LLC PHY configuration. Used to define which physical radio and
/// which logical channel Veloce uses for transmission and reception of
/// packets.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Config {
    /// Radio used for Tx and Rx.
    radio: Radio,
    /// Radio logical channel used for Tx and Rx.
    channel: Channel,
    /// Wireless channel frequency.
    frequency: WirelessChannel,
    /// Transmission power.
    tx_power: Power,
    /// MAC Address,
    mac_address: EthernetAddress,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            radio: Radio::A,
            channel: Channel::Zero,
            frequency: WirelessChannel::Chan_180,
            tx_power: Power::from_dbm_i32(32),
            mac_address: EthernetAddress::from_bytes(&[0x04, 0xe5, 0x48, 0x00, 0x00, 0x00]),
        }
    }
}

impl Config {
    /// Build a [Config] using provided parameters.
    /// - `radio`: physical radio to set and use.
    /// - `channel`: logical channel configuration to set and use.
    /// - `frequency`: wireless channel frequency to set and use.
    /// - `tx_power`: transmission power to set and use as default value.
    /// - `mac_address`: hardware address to accept in the LLC PHY internal rx filters.
    pub fn new(
        radio: Radio,
        channel: Channel,
        frequency: WirelessChannel,
        tx_power: Power,
        mac_address: EthernetAddress,
    ) -> Self {
        Config {
            radio,
            channel,
            frequency,
            tx_power,
            mac_address,
        }
    }

    /// Set the mac address.
    pub fn set_mac_address(&mut self, addr: EthernetAddress) {
        self.mac_address = addr;
    }

    /// Emit config data into a [tMKxRadioConfig].
    pub(crate) fn emit(&self, cfg: &mut tMKxRadioConfig) {
        let channel_idx = self.channel;
        let chan_cfg = &mut cfg.RadioConfigData.ChanConfig[channel_idx as usize];

        cfg.Hdr.Type = self.radio as u16;
        cfg.RadioConfigData.Mode = channel_idx as u16;
        chan_cfg.PHY.ChannelFreq = self.frequency as u16;
        chan_cfg.PHY.DefaultTxPower = self.tx_power.as_half_dbm_i16();

        for table in &mut chan_cfg.MAC.AMSTable {
            // Device Mac Address is always the last entry in our implem.
            if table.MatchCtrl & eMKxAddressMatchingCtrl_MKX_ADDRMATCH_LAST_ENTRY as u16 > 0 {
                table.Addr.copy_from_slice(self.mac_address.as_bytes());
                break;
            }
        }
    }
}

/// NXP LLC PHY Radio identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Radio {
    /// Radio A.
    A = 0,
    /// Radio B.
    B = 1,
}

/// NXP LLC PHY radio config logical channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Channel 0.
    Zero = 0,
    /// Channel 1.
    One = 1,
}

/// Wireless channel number, associated with its center frequency in MHz.
/// Those channels are 10MHz bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirelessChannel {
    Chan_172 = 5860,
    Chan_174 = 5870,
    Chan_176 = 5880,
    Chan_178 = 5890,
    Chan_180 = 5900,
    Chan_182 = 5910,
    Chan_184 = 5920,
}

impl Default for tMKxRadioConfig {
    fn default() -> Self {
        Self {
            Hdr: MKxIFMsg {
                Type: eMKxIFMsgType_MKXIF_RADIOACFG as u16,
                Len: core::mem::size_of::<tMKxRadioConfig>() as u16,
                Seq: 0,
                Ref: 0,
                Reserved: 0,
                Ret: eMKxStatus_MKXSTATUS_RESERVED as i16,
            },
            RadioConfigData: MKxRadioConfigData {
                Mode: eRadioMode_MKX_MODE_OFF as u16,
                SystemTickRateMHz: 0,
                ChanConfig: [chan_config(), chan_config()],
            },
        }
    }
}

#[allow(unused)]
fn chan_config() -> MKxChanConfig {
    MKxChanConfig {
        PHY: MKxChanConfigPHY {
            ChannelFreq: 0,
            Bandwidth: eMKxBandwidth_MKXBW_10MHz as u8,
            TxAntenna: eMKxAntenna_MKX_ANT_1AND2 as u8,
            RxAntenna: eMKxAntenna_MKX_ANT_1AND2 as u8,
            DefaultMCS: eMKxMCS_MKXMCS_R12QPSK as u8,
            DefaultTxPower: 64,
        },
        MAC: MKxChanConfigMAC {
            DualTxControl: eMKxDualTxControl_MKX_TXC_TXRX as u8,
            CSThreshold: -65,
            CBRThreshold: -85,
            Padding: [0u8; 3],
            SlotTime: 13,
            DIFSTime: 32 + (2 * 13),
            SIFSTime: 32,
            EIFSTime: 178,
            RTSCTSThreshold: i16::MAX as u16,
            ShortRetryLimit: 4,
            LongRetryLimit: 7,
            TxQueue: [
                // MKX_TXQ_NON_QOS
                MKxTxQConfig {
                    AIFS: 2,
                    Pad: 0,
                    CWMIN: (1 << 4) - 1,
                    CWMAX: (1 << 10) - 1,
                    TXOP: 0,
                },
                // MKX_TXQ_AC_VO
                MKxTxQConfig {
                    AIFS: 2,
                    Pad: 0,
                    CWMIN: (1 << 2) - 1,
                    CWMAX: (1 << 3) - 1,
                    TXOP: 0,
                },
                // MKX_TXQ_AC_VI
                MKxTxQConfig {
                    AIFS: 3,
                    Pad: 0,
                    CWMIN: (1 << 3) - 1,
                    CWMAX: (1 << 4) - 1,
                    TXOP: 0,
                },
                // MKX_TXQ_AC_BE
                MKxTxQConfig {
                    AIFS: 6,
                    Pad: 0,
                    CWMIN: (1 << 4) - 1,
                    CWMAX: (1 << 10) - 1,
                    TXOP: 0,
                },
                // MKX_TXQ_AC_BK
                MKxTxQConfig {
                    AIFS: 9,
                    Pad: 0,
                    CWMIN: (1 << 4) - 1,
                    CWMAX: (1 << 10) - 1,
                    TXOP: 0,
                },
            ],
            AMSTable: [
                // Accept broadcast frames, but do not respond
                MKxAddressMatching {
                    Mask: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    Reserved0: 0,
                    Addr: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    MatchCtrl: 0,
                },
                // Accept anonymous frames, but do not respond
                MKxAddressMatching {
                    Mask: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    Reserved0: 0,
                    Addr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    MatchCtrl: 0,
                },
                // Accept IPv6 multicast frames addressed to 33:33:xx:xx:xx:xx
                MKxAddressMatching {
                    Mask: [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                    Reserved0: 0,
                    Addr: [0x33, 0x33, 0x00, 0x00, 0x00, 0x00],
                    MatchCtrl: 0,
                },
                // Accept frames addressed to our 1st MAC address (04:E5:48:00:00:00)
                MKxAddressMatching {
                    Mask: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    Reserved0: 0,
                    Addr: [0x04, 0xe5, 0x48, 0x00, 0x00, 0x00],
                    MatchCtrl: (eMKxAddressMatchingCtrl_MKX_ADDRMATCH_RESPONSE_ENABLE
                        | eMKxAddressMatchingCtrl_MKX_ADDRMATCH_LAST_ENTRY)
                        as u16,
                },
                MKxAddressMatching {
                    Mask: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    Reserved0: 0,
                    Addr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    MatchCtrl: 0,
                },
                MKxAddressMatching {
                    Mask: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    Reserved0: 0,
                    Addr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    MatchCtrl: 0,
                },
                MKxAddressMatching {
                    Mask: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    Reserved0: 0,
                    Addr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    MatchCtrl: 0,
                },
                MKxAddressMatching {
                    Mask: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    Reserved0: 0,
                    Addr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    MatchCtrl: 0,
                },
            ],
        },
        LLC: MKxChanConfigLLC {
            IntervalDuration: 50 * 1000,
            GuardDuration: 0,
        },
    }
}
