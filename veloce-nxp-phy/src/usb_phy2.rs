use std::io;
use std::thread;
use std::thread::JoinHandle;

use crossbeam::channel::{unbounded, Receiver, RecvTimeoutError, Select, Sender, TryRecvError};
use futures_lite::future::block_on;
use nusb::Interface;
use nusb::{
    transfer::{Direction, EndpointType, RequestBuffer},
    Device,
};
use veloce::time::Duration;

use crate::LLC_BUFFER_LEN;

/// NXP SAF 5100 USB Vendor ID.
pub const VID: u16 = 0x1fc9;
/// NXP SAF 5100 USB Product ID when in DFU mode.
pub const PID_DFU: u16 = 0x0102;
/// NXP SAF 5100 USB Product ID when in SDR mode.
pub const PID_SDR: u16 = 0x0103;

/// The USB device.
#[allow(unused)]
pub struct USB {
    /// Handle on the USB device.
    handle: Device,
    /// Interface of the USB device.
    interface: Interface,
    /// Channel for receiving data.
    rx_channel: Receiver<Vec<u8>>,
    /// Channel for transmitting data.
    tx_channel: Sender<Vec<u8>>,
    /// Rx thread join handle.
    rx_thread_handle: JoinHandle<()>,
    /// Tx thread join handle.
    tx_thread_handle: JoinHandle<()>,
}

impl USB {
    pub fn new() -> io::Result<USB> {
        let dev_info = nusb::list_devices()?
            .find(|d| d.vendor_id() == VID && d.product_id() == PID_SDR)
            .ok_or_else(|| io::ErrorKind::NotConnected)?;

        let dev = dev_info.open()?;

        let (Some(iface), Some(r), Some(w)) = USB::find_readable_and_writeable_endpoint_addr(&dev)
        else {
            return Err(io::ErrorKind::NotFound.into());
        };

        println!("read: {}, write: {}", r, w);

        let interface = dev.claim_interface(iface)?;

        // Channels
        let (rx_thread_tx_chan, rx_thread_rx_chan) = unbounded();
        let (tx_thread_tx_chan, tx_thread_rx_chan) = unbounded();

        // Spawn rx thread
        let rx_interface = interface.clone();
        let rx_thread = thread::spawn(move || {
            let mut queue = rx_interface.bulk_in_queue(r);

            loop {
                // Allocate a buffer for rx.
                if queue.pending() == 0 {
                    queue.submit(RequestBuffer::new(LLC_BUFFER_LEN));
                }

                let res = block_on(queue.next_complete());

                // Ignore errors (for now).
                if res.status.is_err() {
                    continue;
                }

                if rx_thread_tx_chan.send(res.data).is_err() {
                    break;
                }
            }
        });

        let tx_interface = interface.clone();
        let tx_thread = thread::spawn(move || {
            let mut queue = tx_interface.bulk_out_queue(w);

            loop {
                let Ok(data) = tx_thread_rx_chan.recv() else {
                    break;
                };

                queue.submit(data);

                let res = block_on(queue.next_complete());

                // Ignore errors (for now).
                if res.status.is_err() {
                    continue;
                }
            }
        });

        Ok(USB {
            handle: dev,
            interface,
            rx_channel: rx_thread_rx_chan,
            tx_channel: tx_thread_tx_chan,
            rx_thread_handle: rx_thread,
            tx_thread_handle: tx_thread,
        })
    }

    /// Wait until the USB device becomes readable, but no longer than given timeout.
    pub fn wait(&self, timeout: Option<Duration>) -> io::Result<()> {
        let mut sel = Select::new();
        let _op = sel.recv(&self.rx_channel);

        if let Some(t) = timeout {
            match sel.ready_timeout(core::time::Duration::from_micros(t.micros())) {
                Ok(_) => return Ok(()),
                Err(_) => Err(io::ErrorKind::TimedOut.into()),
            }
        } else {
            let _ = sel.ready();
            Ok(())
        }
    }

    /// Attempts to receive data from the device, without blocking.
    pub fn try_recv(&self) -> io::Result<Vec<u8>> {
        self.rx_channel.try_recv().map_err(|e| match e {
            TryRecvError::Empty => io::ErrorKind::WouldBlock.into(),
            TryRecvError::Disconnected => io::ErrorKind::ConnectionAborted.into(),
        })
    }

    /// Wait until the USB device has rx data, but no longer than given timeout.
    /// If timeout is None, this function call will block until data .
    /// Returns the available bytes to read, if any.
    pub fn recv(&self, timeout: Option<Duration>) -> io::Result<Vec<u8>> {
        if let Some(t) = timeout {
            match self
                .rx_channel
                .recv_timeout(core::time::Duration::from_micros(t.micros()))
            {
                Ok(d) => return Ok(d),
                Err(RecvTimeoutError::Timeout) => return Err(io::ErrorKind::TimedOut.into()),
                Err(_) => return Err(io::ErrorKind::ConnectionAborted.into()),
            }
        } else {
            match self.rx_channel.recv() {
                Ok(d) => return Ok(d),
                Err(_) => return Err(io::ErrorKind::ConnectionAborted.into()),
            }
        }
    }

    /// Send buffer to the device.
    pub fn send(&self, buffer: Vec<u8>) -> Result<(), io::Error> {
        match self.tx_channel.send(buffer) {
            Ok(_) => Ok(()),
            Err(_) => Err(io::ErrorKind::ConnectionAborted.into()),
        }
    }

    fn find_readable_and_writeable_endpoint_addr(
        device: &Device,
    ) -> (Option<u8>, Option<u8>, Option<u8>) {
        let mut iface = None;
        let mut readable = None;
        let mut writeable = None;

        'outer: for config in device.configurations() {
            for alt_setting in config.interface_alt_settings() {
                for endpoint in alt_setting.endpoints() {
                    if endpoint.direction() == Direction::In
                        && endpoint.transfer_type() == EndpointType::Bulk
                        && readable.is_none()
                    {
                        readable = Some(endpoint.address());
                    }
                    if endpoint.direction() == Direction::Out
                        && endpoint.transfer_type() == EndpointType::Bulk
                        && writeable.is_none()
                    {
                        writeable = Some(endpoint.address());
                    }
                }

                // This is the good endpoint iface.
                if readable.is_some() && writeable.is_some() {
                    iface = Some(alt_setting.interface_number());
                    break 'outer;
                }
            }
        }

        (iface, readable, writeable)
    }
}
