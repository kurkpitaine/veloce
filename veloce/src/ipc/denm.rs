use veloce_ipc::denm::{ApiCancel, ApiNegate, ApiResult, ApiResultCode, ApiTrigger, ApiUpdate};

use crate::{
    iface::SocketSet,
    network::GnCore,
    socket::{self},
};

use super::IpcDispatcher;

impl IpcDispatcher {
    /// Process a DENM trigger request.
    /// Returns an [ApiResult] with the result code and optional message.
    pub fn denm_trigger(
        &self,
        req: ApiTrigger,
        router: &GnCore,
        sockets: &mut SocketSet<'_>,
    ) -> ApiResult {
        let mut res = ApiResult {
            id: req.id,
            result: ApiResultCode::Ok.into(),
            message: None,
            handle: None,
        };

        let event = match Self::extract_field(req.parameters) {
            Ok(e) => e,
            Err(e) => {
                res.result = e.into();
                return res;
            }
        };

        let denm_socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);
        match denm_socket.trigger(router, event) {
            Ok(handle) => {
                res.handle = Some(handle.into());
            }
            Err(err) => {
                let (rc, message) = Self::denm_err_to_ipc_result(err);
                res.result = rc.into();
                res.message = message;
            }
        }

        res
    }

    /// Process a DENM update request.
    /// Returns an [ApiResult] with the result code and optional message.
    pub fn denm_update(
        &self,
        req: ApiUpdate,
        router: &GnCore,
        sockets: &mut SocketSet<'_>,
    ) -> ApiResult {
        let mut res = ApiResult {
            id: req.id,
            result: ApiResultCode::Ok.into(),
            message: None,
            handle: None,
        };

        let event = match Self::extract_field(req.parameters) {
            Ok(e) => e,
            Err(e) => {
                res.result = e.into();
                return res;
            }
        };

        let handle = match Self::extract_field(req.handle) {
            Ok(e) => e,
            Err(e) => {
                res.result = e.into();
                return res;
            }
        };

        let denm_socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);
        match denm_socket.update(router, handle, event) {
            Ok(handle) => {
                res.handle = Some(handle.into());
            }
            Err(err) => {
                let (rc, message) = Self::denm_err_to_ipc_result(err);
                res.result = rc.into();
                res.message = message;
            }
        }

        res
    }

    /// Process a DENM cancel request.
    /// Returns an [ApiResult] with the result code and optional message.
    pub fn denm_cancel(
        &self,
        req: ApiCancel,
        router: &GnCore,
        sockets: &mut SocketSet<'_>,
    ) -> ApiResult {
        let mut res = ApiResult {
            id: req.id,
            result: ApiResultCode::Ok.into(),
            message: None,
            handle: None,
        };

        let event = match Self::extract_field(req.parameters) {
            Ok(e) => e,
            Err(e) => {
                res.result = e.into();
                return res;
            }
        };

        let handle = match Self::extract_field(req.handle) {
            Ok(e) => e,
            Err(e) => {
                res.result = e.into();
                return res;
            }
        };

        let denm_socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);
        match denm_socket.cancel(router, handle, event) {
            Ok(handle) => {
                res.handle = Some(handle.into());
            }
            Err(err) => {
                let (rc, message) = Self::denm_err_to_ipc_result(err);
                res.result = rc.into();
                res.message = message;
            }
        }

        res
    }

    /// Process a DENM negate request.
    /// Returns an [ApiResult] with the result code and optional message.
    pub fn denm_negate(
        &self,
        req: ApiNegate,
        router: &GnCore,
        sockets: &mut SocketSet<'_>,
    ) -> ApiResult {
        let mut res = ApiResult {
            id: req.id,
            result: ApiResultCode::Ok.into(),
            message: None,
            handle: None,
        };

        let event = match Self::extract_field(req.parameters) {
            Ok(e) => e,
            Err(e) => {
                res.result = e.into();
                return res;
            }
        };

        let action_id = match Self::extract_field(req.action_id) {
            Ok(e) => e,
            Err(e) => {
                res.result = e.into();
                return res;
            }
        };

        let denm_socket = sockets.get_mut::<socket::denm::Socket>(self.denm_socket_handle);
        match denm_socket.negate(router, action_id, event) {
            Ok(handle) => {
                res.handle = Some(handle.into());
            }
            Err(err) => {
                let (rc, message) = Self::denm_err_to_ipc_result(err);
                res.result = rc.into();
                res.message = message;
            }
        }

        res
    }

    #[inline]
    fn extract_field<F, T>(field: Option<F>) -> Result<T, ApiResultCode>
    where
        T: TryFrom<F, Error = ApiResultCode>,
    {
        let Some(f) = field else {
            return Err(ApiResultCode::Malformed);
        };

        T::try_from(f)
    }

    #[inline]
    fn denm_err_to_ipc_result(err: socket::denm::ApiError) -> (ApiResultCode, Option<String>) {
        match err {
            socket::denm::ApiError::NoFreeSlot => (ApiResultCode::NoFreeSlot, None),
            socket::denm::ApiError::Expired => (ApiResultCode::Expired, None),
            socket::denm::ApiError::InvalidDetectionTime => {
                (ApiResultCode::InvalidDetectionTime, None)
            }
            socket::denm::ApiError::InvalidValidityDuration => {
                (ApiResultCode::InvalidValidityDuration, None)
            }
            socket::denm::ApiError::InvalidRepetitionDuration => {
                (ApiResultCode::InvalidRepetitionDuration, None)
            }
            socket::denm::ApiError::InvalidRepetitionInterval => {
                (ApiResultCode::InvalidRepetitionInterval, None)
            }
            socket::denm::ApiError::InvalidKeepAliveTransmissionInterval => {
                (ApiResultCode::InvalidKeepAliveTransmissionInterval, None)
            }
            socket::denm::ApiError::InvalidContent(s) => {
                (ApiResultCode::InvalidContent, Some(s.to_string()))
            }
            socket::denm::ApiError::NotFound => (ApiResultCode::NotFound, None),
            socket::denm::ApiError::ActionIdInOrigMsgtable => {
                (ApiResultCode::ActionIdInOrigMsgtable, None)
            }
            socket::denm::ApiError::Unauthorized => (ApiResultCode::Unauthorized, None),
        }
    }
}
