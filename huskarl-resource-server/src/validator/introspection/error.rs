//! Error types for token introspection validation.

use snafu::prelude::*;

use crate::{
    TokenType,
    error::{ToRfc6750Error, TokenValidationError},
    introspection::IntrospectionCallError,
    validator::error::TokenBindingError,
    validator::extract::TokenExtractError,
};

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
    Binding {
        token_type: TokenType,
        source: TokenBindingError,
    },
    /// The introspection call failed.
    #[snafu(display("Introspection call error"))]
    Call {
        token_type: TokenType,
        source: IntrospectionCallError<AuthErr, HttpErr, HttpRespErr>,
    },
}

impl<AuthErr: crate::core::Error, HttpErr: crate::core::Error, HttpRespErr: crate::core::Error>
    ToRfc6750Error for IntrospectionValidateError<AuthErr, HttpErr, HttpRespErr>
{
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Binding { token_type, .. } => Some(*token_type),
            Self::Call { token_type, .. } => Some(*token_type),
        }
    }

    fn token_error(&self) -> TokenValidationError {
        match self {
            Self::Extract { source } => source.token_error(),
            Self::Binding { source, .. } => source.token_error(),
            Self::Call { source, .. } => source.token_error(),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::Extract { source } => source.error_description(),
            Self::Binding { source, .. } => source.error_description(),
            Self::Call { source, .. } => source.error_description(),
        }
    }
}
