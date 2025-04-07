use core::fmt::{self, Formatter};

use crate::security::backend::BackendError;

use super::{asn1_wrapper::Asn1WrapperError, message::{
    authorization::{AuthorizationRequestError, AuthorizationResponseError},
    enrollment::{EnrollmentRequestError, EnrollmentResponseError},
}};

pub mod client;
pub mod server;

pub use client::PkiClientService;

pub type PkiServiceResult<T> = core::result::Result<T, PkiServiceError>;

#[derive(Debug)]
pub enum PkiServiceError {
    /// Pki message has invalid content.
    InvalidContent(Asn1WrapperError),
    /// Backend error.
    Backend(BackendError),
    /// Enrollment request error.
    EnrollmentRequest(EnrollmentRequestError),
    /// Enrollment request error.
    EnrollmentResponse(EnrollmentResponseError),
    /// Authorization request error.
    AuthorizationRequest(AuthorizationRequestError),
    /// Authorization response error.
    AuthorizationResponse(AuthorizationResponseError),
}

impl fmt::Display for PkiServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PkiServiceError::InvalidContent(e) => {
                write!(f, "invalid content: {}", e)
            }
            PkiServiceError::Backend(e) => {
                write!(f, "backend: {}", e)
            }
            PkiServiceError::EnrollmentRequest(e) => {
                write!(f, "enrollment request: {}", e)
            }
            PkiServiceError::EnrollmentResponse(e) => {
                write!(f, "enrollment response: {}", e)
            }
            PkiServiceError::AuthorizationRequest(e) => {
                write!(f, "authorization request: {}", e)
            }
            PkiServiceError::AuthorizationResponse(e) => {
                write!(f, "authorization response: {}", e)
            }
        }
    }
}
