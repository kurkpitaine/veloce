use core::mem::{size_of, transmute};
use std::{cell::RefCell, rc::Rc};

use veloce::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::{Duration, Instant},
};

use crate::{
    cfg_mk5, eMKxAntenna_MKX_ANT_DEFAULT, eMKxChannel_MKX_CHANNEL_0, eMKxIFMsgType_MKXIF_ERROR,
    eMKxIFMsgType_MKXIF_RXPACKET, eMKxIFMsgType_MKXIF_TXPACKET, eMKxMCS_MKXMCS_DEFAULT,
    eMKxPower_MKX_POWER_TX_DEFAULT, eMKxRadio_MKX_RADIO_A, eMKxStatus_MKXSTATUS_RESERVED,
    eMKxTxCtrlFlags_MKX_REGULAR_TRANSMISSION, tMKxIFMsg, tMKxRadioConfig, tMKxRxPacket,
    tMKxTxPacket, usb_phy::USB, Error, Result, LLC_BUFFER_LEN, RAW_FRAME_LENGTH_MAX,
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
}

impl NxpUsbDevice {
    /// Constructs a new NxpDevice.
    pub fn new() -> Result<NxpUsbDevice> {
        let lower = USB::new().map_err(|_| Error::USB)?;

        Ok(NxpUsbDevice {
            lower: Rc::new(RefCell::new(lower)),
            ref_num: Rc::new(RefCell::new(0)),
            tx_seq_num: Rc::new(RefCell::new(0)),
            rx_seq_num: 0,
        })
    }

    /// Apply the default configuration on the NXP device.
    #[must_use = "Default configuration should be applied to enable communication."]
    pub fn configure(&self) -> Result<()> {
        let cfg = cfg_mk5();
        let w_buf: [u8; size_of::<tMKxRadioConfig>()] = unsafe { transmute(cfg) };

        self.lower.borrow_mut().send(&w_buf).map(|_| ())
    }

    /// Wait until the device has rx data, but no longer than given timeout.
    /// Any timeout value under 1 millisecond will be set to 1 millisecond.
    /// If timeout is None, this function call will block.
    /// Returns the number of bytes available to read, if any, or an Error
    /// on timeout or other.
    pub fn poll_wait(&self, timeout: Option<Duration>) -> Result<usize> {
        self.lower.borrow_mut().poll_wait(timeout)
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
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; LLC_BUFFER_LEN];

        // Fail early if we have nothing to receive.
        if !lower.can_recv() {
            return None;
        }

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

                // Silently ignore non RXPACKET types.
                if hdr.Type != eMKxIFMsgType_MKXIF_RXPACKET as u16 {
                    return None;
                }

                // Sanity check 3.
                let len = hdr.Len as usize - size_of::<tMKxIFMsg>();
                if len < size_of::<tMKxRxPacket>() {
                    return None;
                };

                // Unpack NxpRxPacketData header.
                let rx_pkt: &tMKxRxPacket = unsafe { &*buffer.as_ptr().cast() };

                // Sanity check 4.
                let frame_len = rx_pkt.RxPacketData.RxFrameLength;
                if frame_len < (hdr.Len as usize - size_of::<tMKxRxPacket>()) as u16 {
                    return None;
                }

                // Strip packet header.
                buffer.drain(..size_of::<tMKxRxPacket>());

                let rx = NxpRxToken { buffer };
                let tx = NxpTxToken {
                    lower: self.lower.clone(),
                    ref_num: self.ref_num.clone(),
                    tx_seq_num: self.tx_seq_num.clone(),
                };
                Some((rx, tx))
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
}

impl RxToken for NxpRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
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
