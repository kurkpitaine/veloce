use core::mem::{size_of, transmute};
use std::{cell::RefCell, os::fd::RawFd, rc::Rc, time::SystemTime};

use heapless::HistoryBuffer;
use log::{error, trace};
use veloce::{
    phy::{
        ChannelBusyRatio, Device, DeviceCapabilities, MacFilterCapabilities, Medium, PacketMeta,
        RxToken, TxToken,
    },
    time::{Duration, Instant},
    types::Power,
    wire::HardwareAddress,
};

use crate::{
    ffi::*, usb_phy::USB, Error, NxpConfig, NxpRadio, Result, LLC_BUFFER_LEN, RAW_FRAME_LENGTH_MAX,
};

/// An NXP USB SAF 5X00 device.
#[derive(Debug)]
pub struct NxpUsbDevice {
    lower: Rc<RefCell<USB>>,
    /// Reference number for sent packets that receives confirmation.
    ref_num: Rc<RefCell<u16>>,
    /// Sequence number of messages being received.
    tx_seq_num: Rc<RefCell<u16>>,
    /// Sequence number of messages being sent.
    rx_seq_num: u16,
    /// Device configuration
    config: NxpConfig,
    /// Channel busy ratio. Measurement should be made over a period of 100ms,
    /// NXP phy gives us a measurement each 50ms, so store 2 values of it.
    cbr_values: HistoryBuffer<ChannelBusyRatio, 2>,
}

impl NxpUsbDevice {
    /// Constructs a new NxpDevice using `config`.
    pub fn new(config: NxpConfig) -> Result<NxpUsbDevice> {
        let lower = USB::new().map_err(|_| Error::USB)?;

        Ok(NxpUsbDevice {
            lower: Rc::new(RefCell::new(lower)),
            ref_num: Rc::new(RefCell::new(0)),
            tx_seq_num: Rc::new(RefCell::new(0)),
            rx_seq_num: 0,
            config,
            cbr_values: HistoryBuffer::new(),
        })
    }

    /// Apply the configuration on the NXP device.
    #[must_use = "Configuration should be applied to enable communication."]
    pub fn commit_config(&self) -> Result<()> {
        let mut radio_cfg = tMKxRadioConfig::default();
        self.config.emit(&mut radio_cfg);
        let w_buf: [u8; size_of::<tMKxRadioConfig>()] = unsafe { transmute(radio_cfg) };

        self.lower.borrow_mut().send(&w_buf).map(|_| ())
    }

    /// Wait until the device has rx data, but no longer than given timeout.
    /// Any timeout value under 1 millisecond will be set to 1 millisecond.
    /// If timeout is None, this function call will block.
    /// Returns the number of bytes available to read, if any, or an Error
    /// on timeout or other.
    pub fn poll_wait(&self, timeout: Option<Duration>) -> Result<usize> {
        let before = SystemTime::now();
        let rc = self.lower.borrow_mut().poll_wait(timeout);
        println!(
            "Recv elapsed: {:?}, timeout: {:?}",
            SystemTime::elapsed(&before).unwrap(),
            timeout
        );

        rc
    }

    /// Return the file descriptor list to poll for USB operation.
    pub fn pollfds(&self) -> Vec<RawFd> {
        self.lower.borrow().get_pollfds()
    }
}

impl Device for NxpUsbDevice {
    type RxToken<'a> = NxpRxToken
    where
        Self: 'a;

    type TxToken<'a> = NxpTxToken
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = RAW_FRAME_LENGTH_MAX;
        caps.medium = Medium::Ieee80211p;
        caps.radio.mac_filter = MacFilterCapabilities::Rx;
        caps.radio.tx_power = self.config.tx_power;
        caps
    }

    fn filter_addr(&self) -> Option<HardwareAddress> {
        Some(self.config.filter_addr.into())
    }

    fn set_filter_addr(&mut self, addr: Option<HardwareAddress>) {
        let Some(addr) = addr else {
            return;
        };

        self.config.filter_addr = addr.ethernet_or_panic();
        match self.commit_config() {
            Ok(_) => {
                trace!("Filter {} Mac address set", self.config.filter_addr);
            }
            Err(e) => {
                error!("Failed to set filter Mac address: {}", e);
            }
        }
    }

    fn channel_busy_ratio(&self) -> ChannelBusyRatio {
        let sum: f32 = self
            .cbr_values
            .iter()
            .fold(0.0, |acc, e| acc + e.as_ratio());
        let count = self.cbr_values.len() as f32;
        ChannelBusyRatio::from_ratio(sum / count)
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; LLC_BUFFER_LEN];

        match lower.recv(&mut buffer) {
            Ok(size) => {
                buffer.resize(size, 0);

                // Sanity check 1.
                if size < size_of::<tMKxIFMsg>() {
                    return None;
                }

                // Unpack Nxp header.
                let hdr: &tMKxIFMsg = unsafe { &*buffer.as_ptr().cast() };

                // Sanity check 2.
                if hdr.Len < size as u16 {
                    return None;
                }

                if hdr.Seq == 0 && hdr.Type == eMKxIFMsgType_MKXIF_ERROR as u16 {
                    // Do not trigger a warning and do not increment the expected seq number.
                    return None;
                } else if hdr.Seq != self.rx_seq_num {
                    // Mismatched Seq number (Radio to Host).
                    // sync up to the received message.
                    self.rx_seq_num = hdr.Seq.wrapping_add(1);
                } else {
                    // Seq number was as expected, increment the expected Seq number.
                    self.rx_seq_num = self.rx_seq_num.wrapping_add(1);
                }

                // Sanity check 3.
                let len = hdr.Len as usize - size_of::<tMKxIFMsg>();
                if len < size_of::<tMKxRxPacket>() {
                    return None;
                };

                let cfg_channel = self.config.channel;

                match (hdr.Type as u32, self.config.radio) {
                    (eMKxIFMsgType_MKXIF_RADIOASTATS, NxpRadio::A)
                    | (eMKxIFMsgType_MKXIF_RADIOBSTATS, NxpRadio::B)
                        if hdr.Ref == cfg_channel as u16 =>
                    {
                        let stats_pkt: &tMKxRadioStats = unsafe { &*buffer.as_ptr().cast() };
                        let stats = stats_pkt.RadioStatsData.Chan[cfg_channel as usize];
                        let cbr =
                            ChannelBusyRatio::from_ratio(stats.ChannelBusyRatio as f32 / 255.0);
                        self.cbr_values.write(cbr);

                        None
                    }
                    (eMKxIFMsgType_MKXIF_RXPACKET, radio) => {
                        // Unpack NxpRxPacketData header.
                        let rx_pkt: &tMKxRxPacket = unsafe { &*buffer.as_ptr().cast() };

                        // Sanity check 4.
                        let frame_len = rx_pkt.RxPacketData.RxFrameLength;
                        if frame_len < (hdr.Len as usize - size_of::<tMKxRxPacket>()) as u16 {
                            return None;
                        }

                        if rx_pkt.RxPacketData.RadioID == radio as u8
                            && rx_pkt.RxPacketData.ChannelID == cfg_channel as u8
                        {
                            let mut meta = PacketMeta::default();
                            meta.power = Some(Power::from_half_dbm_i32(
                                rx_pkt
                                    .RxPacketData
                                    .RxPowerAnt1
                                    .max(rx_pkt.RxPacketData.RxPowerAnt2)
                                    .into(),
                            ));

                            // Strip packet header.
                            buffer.drain(..size_of::<tMKxRxPacket>());

                            let rx = NxpRxToken { buffer, meta };
                            let tx = NxpTxToken {
                                lower: self.lower.clone(),
                                ref_num: self.ref_num.clone(),
                                tx_seq_num: self.tx_seq_num.clone(),
                            };
                            return Some((rx, tx));
                        }

                        None
                    }
                    _ => None,
                }
            }
            Err(Error::Timeout) => None,
            Err(e) => panic!("{}", e),
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(NxpTxToken {
            lower: self.lower.clone(),
            ref_num: self.ref_num.clone(),
            tx_seq_num: self.tx_seq_num.clone(),
        })
    }
}

#[doc(hidden)]
pub struct NxpRxToken {
    buffer: Vec<u8>,
    meta: PacketMeta,
}

impl RxToken for NxpRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
    }

    fn meta(&self) -> PacketMeta {
        self.meta
    }
}

#[doc(hidden)]
pub struct NxpTxToken {
    lower: Rc<RefCell<USB>>,
    ref_num: Rc<RefCell<u16>>,
    tx_seq_num: Rc<RefCell<u16>>,
}

impl TxToken for NxpTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut ref_num = self.ref_num.borrow_mut();
        *ref_num = ref_num.wrapping_add(1);

        let mut tx_seq = self.tx_seq_num.borrow_mut();
        *tx_seq = tx_seq.wrapping_add(1);

        let hdr_len = size_of::<tMKxTxPacket>();
        let mut buffer = vec![0; len + hdr_len];

        // Insert tMkxTxPacket prefix.
        let tx_pkt: &mut tMKxTxPacket = unsafe { &mut *buffer.as_mut_ptr().cast() };
        tx_pkt.Hdr.Type = eMKxIFMsgType_MKXIF_TXPACKET as u16;
        tx_pkt.Hdr.Len = (len + hdr_len) as u16;
        tx_pkt.Hdr.Seq = *tx_seq;
        tx_pkt.Hdr.Ref = *ref_num;
        tx_pkt.Hdr.Ret = eMKxStatus_MKXSTATUS_RESERVED as i16;

        tx_pkt.TxPacketData.RadioID = eMKxRadio_MKX_RADIO_A as u8;
        tx_pkt.TxPacketData.ChannelID = eMKxChannel_MKX_CHANNEL_0 as u8;
        tx_pkt.TxPacketData.TxAntenna = eMKxAntenna_MKX_ANT_DEFAULT as u8;
        tx_pkt.TxPacketData.MCS = eMKxMCS_MKXMCS_DEFAULT as u8;
        tx_pkt.TxPacketData.TxPower = eMKxPower_MKX_POWER_TX_DEFAULT as i16;
        tx_pkt.TxPacketData.TxCtrlFlags = eMKxTxCtrlFlags_MKX_REGULAR_TRANSMISSION as u8;
        tx_pkt.TxPacketData.Expiry = 0;
        tx_pkt.TxPacketData.TxFrameLength = len as u16;

        let result = f(&mut buffer[hdr_len..]);

        /* let ieee_hdr: &IEEE80211QoSHeader = unsafe { &mut *buffer[hdr_len..].as_mut_ptr().cast() };
        let durationId = ieee_hdr.DurationId;

        println!("FrameCtrl: {}", unsafe {ieee_hdr.FrameControl.FrameCtrl});
        println!("durationId: {}", durationId);
        println!("Address1: {:?}", ieee_hdr.Address1);
        println!("Address2: {:?}", ieee_hdr.Address2);
        println!("Address3: {:?}", ieee_hdr.Address3);
        println!("SeqCtrl: {}", unsafe {ieee_hdr.SeqControl.SeqCtrl});
        println!("QoSCtrl {}", unsafe {ieee_hdr.QoSControl.QoSCtrl});

        let snap_hdr: &SNAPHeader = unsafe { &mut *buffer[hdr_len + size_of::<IEEE80211QoSHeader>()..].as_mut_ptr().cast() };
        let ty = snap_hdr.Type;
        println!("{}", ty);
        println!("{}", unsafe {snap_hdr.__bindgen_anon_1.__bindgen_anon_1.SSAP});
        println!("{}", unsafe {snap_hdr.__bindgen_anon_1.__bindgen_anon_1.DSAP}); */

        match self.lower.borrow_mut().send(&buffer[..]) {
            Ok(_) => {}
            Err(Error::Timeout) => {
                println!("Timeout while TX");
            }
            Err(e) => panic!("{}", e),
        }
        result
    }
}
