use veloce_ipc::IpcEvent;

#[cfg(any(feature = "socket-cam", feature = "socket-denm"))]
use veloce_ipc::IpcEventType;

use crate::{
    iface::{SocketHandle, SocketSet},
    network::GnCore,
};

#[cfg(feature = "socket-denm")]
pub mod denm;

pub enum IpcError {
    Malformed,
}

/// IpcDispatcher interfaces the sockets with the IPC requests.
#[derive(Debug)]
pub struct IpcDispatcher {
    /// DENM socket handle.
    pub denm_socket_handle: SocketHandle,
}

impl IpcDispatcher {
    #[allow(unused)]
    pub fn dispatch(
        &self,
        event: IpcEvent,
        router: &GnCore,
        sockets: &mut SocketSet<'_>,
    ) -> Result<Option<IpcEvent>, IpcError> {
        let res = match event.event_type.ok_or(IpcError::Malformed)? {
            #[cfg(feature = "socket-denm")]
            IpcEventType::DenmTrigger(trigger) => {
                IpcEventType::DenmResult(self.denm_trigger(trigger, router, sockets))
            }
            #[cfg(feature = "socket-denm")]
            IpcEventType::DenmUpdate(update) => {
                IpcEventType::DenmResult(self.denm_update(update, router, sockets))
            }
            #[cfg(feature = "socket-denm")]
            IpcEventType::DenmCancel(cancel) => {
                IpcEventType::DenmResult(self.denm_cancel(cancel, router, sockets))
            }
            #[cfg(feature = "socket-denm")]
            IpcEventType::DenmNegate(negate) => {
                IpcEventType::DenmResult(self.denm_negate(negate, router, sockets))
            }
            _ => return Ok(None),
        };

        Ok(Some(IpcEvent::new(res)))
    }
}
