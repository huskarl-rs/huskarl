//! Error types for token introspection validation.

use snafu::prelude::*;

use crate::error::Rfc6750ErrorCode;
use crate::introspection::IntrospectionCallError;
use crate::validator::error::TokenBindingError;
use crate::validator::extract::TokenExtractError;

/// Error returned by [`super::IntrospectionValidator::validate_request`].
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum IntrospectionValidateError<
    AuthErr: crate::core::Error,
    HttpErr: crate::core::Error,
    HttpRespErr: crate::core::Error,
> {
    /// Failed to extract the access token from the request headers.
    #[snafu(display("Token presentation error"))]
    Extract { source: TokenExtractError },
    /// Sender-constraint binding check failed.
    #[snafu(display("Token binding error"))]
    Binding { source: TokenBindingError },
    /// The introspection call failed.
    #[snafu(display("Introspection call error"))]
    Call {
        source: IntrospectionCallError<AuthErr, HttpErr, HttpRespErr>,
    },
}

impl<AuthErr: crate::core::Error, HttpErr: crate::core::Error, HttpRespErr: crate::core::Error>
    IntrospectionValidateError<AuthErr, HttpErr, HttpRespErr>
{
    /// Returns the RFC 6750 §3.1 error code for this error, if applicable.
    ///
    /// Returns `None` for server-side failures where the resource server should respond
    /// with HTTP 5xx and omit the error code from `WWW-Authenticate`. See
    /// [`IntrospectionCallError::rfc6750_error_code`] for details.
    pub fn rfc6750_error_code(&self) -> Option<Rfc6750ErrorCode> {
        match self {
            Self::Extract { source } => Some(source.rfc6750_error_code()),
            Self::Binding { source } => Some(source.rfc6750_error_code()),
            Self::Call { source } => source.rfc6750_error_code(),
        }
    }
}
