//! Error types for token introspection validation.

use snafu::prelude::*;

use crate::{
    TokenType,
    error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
    introspection::IntrospectionCallError,
    validator::{error::TokenBindingError, extract::TokenExtractError},
};

/// Error returned by [`super::IntrospectionValidator::validate_request`].
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum IntrospectionValidateError {
    /// Failed to extract the access token from the request headers.
    #[snafu(display("Token presentation error"))]
    Extract {
        /// The underlying token extraction error.
        source: TokenExtractError,
    },
    /// Sender-constraint binding check failed.
    #[snafu(display("Token binding error"))]
    Binding {
        /// The token type that was presented.
        token_type: TokenType,
        /// The underlying binding error.
        source: TokenBindingError,
    },
    /// The introspection call failed.
    #[snafu(display("Introspection call error"))]
    Call {
        /// The token type that was presented.
        token_type: TokenType,
        /// The underlying introspection call error.
        source: IntrospectionCallError,
    },
    /// The introspected token's audience did not satisfy the configured check
    /// (RFC 7662 §4).
    #[snafu(display(
        "Token audience mismatch: expected {expected}, got [{}]",
        actual.join(", ")
    ))]
    Audience {
        /// The token type that was presented.
        token_type: TokenType,
        /// A description of the expected audience.
        expected: String,
        /// The audience values from the introspection response.
        actual: Vec<String>,
    },
}

impl ToRfc6750Error for IntrospectionValidateError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Binding { token_type, .. } => Some(*token_type),
            Self::Call { token_type, .. } => Some(*token_type),
            Self::Audience { token_type, .. } => Some(*token_type),
        }
    }

    fn token_error(&self) -> TokenValidationError {
        match self {
            Self::Extract { source } => source.token_error(),
            Self::Binding { source, .. } => source.token_error(),
            Self::Call { source, .. } => source.token_error(),
            Self::Audience { .. } => TokenValidationError::Client(TokenErrorCode::InvalidToken),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::Extract { source } => source.error_description(),
            Self::Binding { source, .. } => source.error_description(),
            Self::Call { source, .. } => source.error_description(),
            Self::Audience { .. } => {
                Some("The access token is not intended for this resource".to_string())
            }
        }
    }
}
