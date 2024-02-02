use veloce::time::Duration;

use rusb::{Context, Device, DeviceDescriptor, DeviceHandle, Direction, TransferType, UsbContext};

use crate::{Error, Result, LLC_BUFFER_LEN};

/// NXP SAF 5100 USB Vendor ID.
pub const VID: u16 = 0x1fc9;
/// NXP SAF 5100 USB Product ID when in DFU mode.
pub const PID_DFU: u16 = 0x0102;
/// NXP SAF 5100 USB Product ID when in SDR mode.
pub const PID_SDR: u16 = 0x0103;

/// The USB device.
#[derive(Debug)]
pub struct USB {
    /// `rusb` context.
    _ctx: Context,
    /// Handle on the USB device.
    handle: DeviceHandle<Context>,
    /// Read address.
    read_addr: u8,
    /// Write address.
    write_addr: u8,
    /// Rx buffer
    rx_buffer: Vec<u8>,
    /// Number of readable bytes in `rx_buffer`.
    rx_len: usize,
}

impl USB {
    pub fn new() -> Result<USB> {
        let mut ctx = Context::new().map_err(|_| Error::USB)?;

        let (mut dev, desc, mut handle) = Self::open_device(&mut ctx, VID, PID_SDR)?;
        let (iface, read_addr, write_addr) =
            Self::find_interface_readable_and_writeable_endpoint(&mut dev, &desc)?;
        Self::configure_endpoint(&mut handle, iface)?;

        let rx_buffer = vec![0; LLC_BUFFER_LEN];

        Ok(USB {
            _ctx: ctx,
            handle,
            read_addr,
            write_addr,
            rx_buffer,
            rx_len: 0,
        })
    }

    /// Wait until the USB device has rx data, but no longer than given timeout.
    /// Any timeout value under 1 millisecond will be set to 1 millisecond.
    /// If timeout is None, this function call will block.
    /// Returns the number of bytes available to read, if any.
    pub fn poll_wait(&mut self, timeout: Option<Duration>) -> Result<usize> {
        let timeout = match timeout {
            Some(t) if t < Duration::from_millis(1) => core::time::Duration::from_millis(1),
            Some(t) => core::time::Duration::from_micros(t.micros()),
            None => core::time::Duration::from_millis(0),
        };

        self.handle
            .read_bulk(self.read_addr, &mut self.rx_buffer, timeout)
            .and_then(|s| {
                self.rx_len = s;
                Ok(s)
            })
            .map_err(|e| {
                match e {
                    rusb::Error::Timeout => Error::Timeout,
                    _ => Error::USB,
                }
            })
    }

    /// Return wether the USB device has received something.
    pub fn can_recv(&self) -> bool {
        self.rx_len > 0
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if self.rx_len == 0 {
            return Err(Error::NoRxPacket);
        }

        let size = self.rx_len;
        buffer[..size].copy_from_slice(&self.rx_buffer[..size]);

        // Reset internal buffer for further rx.
        self.rx_len = 0;

        Ok(size)
    }

    pub fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let timeout = core::time::Duration::from_millis(1);
        self.handle
            .write_bulk(self.write_addr, buffer, timeout)
            .map_err(|e| match e {
                rusb::Error::Timeout => Error::Timeout,
                _ => Error::USB,
            })
    }

    /// Finds and open the USB device.
    fn open_device<T: UsbContext>(
        context: &mut T,
        vid: u16,
        pid: u16,
    ) -> Result<(Device<T>, DeviceDescriptor, DeviceHandle<T>)> {
        let devices = context.devices().map_err(|_| Error::USB)?;

        for device in devices.iter() {
            let Ok(descriptor) = device.device_descriptor() else {
                continue;
            };

            if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
                let handle = device.open().map_err(|_| Error::USB)?;

                return Ok((device, descriptor, handle));
            }
        }

        Err(Error::USB)
    }

    /// Finds the readable and the writeable endpoint of the USB device.
    fn find_interface_readable_and_writeable_endpoint<T: UsbContext>(
        device: &mut Device<T>,
        device_desc: &DeviceDescriptor,
    ) -> Result<(u8, u8, u8)> {
        let mut iface = None;
        let mut readable = None;
        let mut writeable = None;
        for n in 0..device_desc.num_configurations() {
            let Ok(config_desc) = device.config_descriptor(n) else {
                continue;
            };

            'outer: for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    for endpoint_desc in interface_desc.endpoint_descriptors() {
                        if endpoint_desc.direction() == Direction::In
                            && endpoint_desc.transfer_type() == TransferType::Bulk
                            && readable.is_none()
                        {
                            readable = Some(endpoint_desc.address());
                        }

                        if endpoint_desc.direction() == Direction::Out
                            && endpoint_desc.transfer_type() == TransferType::Bulk
                            && writeable.is_none()
                        {
                            writeable = Some(endpoint_desc.address());
                        }

                        // This is the good endpoint iface.
                        if readable.is_some() && writeable.is_some() {
                            iface = Some(interface_desc.interface_number());
                            break 'outer;
                        }
                    }
                }
            }
        }

        match (iface, readable, writeable) {
            (Some(i), Some(r), Some(w)) => Ok((i, r, w)),
            _ => Err(Error::USB),
        }
    }

    /// Claim the endpoint interface.
    fn configure_endpoint<T: UsbContext>(handle: &mut DeviceHandle<T>, iface: u8) -> Result<()> {
        handle.claim_interface(iface).map_err(|_| Error::USB)
    }
}
