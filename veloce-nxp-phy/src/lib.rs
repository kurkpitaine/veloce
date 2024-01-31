#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use core::fmt;

pub mod llc;
pub mod usb;
pub mod usb_phy;

pub use usb::NxpUsbDevice;
pub use llc::NxpLlcDevice;

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
    USB,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match *self {
            Error::Timeout => "timeout",
            Error::NoRxPacket => "no rx packet in buffer",
            Error::USB => "USB related error",
        };

        f.write_str(str)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[allow(unused)]
fn cfg_mk5() -> tMKxRadioConfig {
    tMKxRadioConfig {
        Hdr: MKxIFMsg {
            Type: eMKxIFMsgType_MKXIF_RADIOACFG as u16,
            Len: core::mem::size_of::<tMKxRadioConfig>() as u16,
            Seq: 0,
            Ref: 0,
            Reserved: 0,
            Ret: eMKxStatus_MKXSTATUS_RESERVED as i16,
        },
        RadioConfigData: MKxRadioConfigData {
            Mode: eRadioMode_MKX_MODE_CHANNEL_0 as u16,
            SystemTickRateMHz: 0,
            ChanConfig: [chan1_config(), chan2_config()],
        },
    }
}

#[allow(unused)]
fn cfg_mk5_off() -> tMKxRadioConfig {
    tMKxRadioConfig {
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
            ChanConfig: [chan1_config(), chan2_config()],
        },
    }
}

#[allow(unused)]
fn chan1_config() -> MKxChanConfig {
    let mut cfg = chan_config();
    cfg.PHY.ChannelFreq = 5900;

    cfg
}

#[allow(unused)]
fn chan2_config() -> MKxChanConfig {
    chan_config()
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
