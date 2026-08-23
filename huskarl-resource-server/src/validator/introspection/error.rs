//! Error types for token introspection validation.

use snafu::prelude::*;

use crate::{
    TokenType,
    error::{Challenge, ToRfc6750Error, TokenErrorCode, TokenValidationError},
    introspection::IntrospectionCallError,
    validator::{error::TokenBindingError, extract::TokenExtractError, observe::ValidationOutcome},
};

/// Error returned by [`super::IntrospectionValidator::validate_request`].
///
/// Extraction, binding, and endpoint-call variants preserve the underlying
/// challenge. An audience mismatch produces an `invalid_token` challenge. The
/// recorded token type selects which supported authentication scheme receives
/// client error details.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum IntrospectionValidateError {
    /// Failed to extract the access token from the request headers.
    #[snafu(display("token presentation error"))]
    Extract {
        /// The underlying token extraction error.
        source: TokenExtractError,
    },
    /// Sender-constraint binding check failed.
    #[snafu(display("token binding error"))]
    Binding {
        /// The token type that was presented, used to select the challenge that
        /// receives error details.
        token_type: TokenType,
        /// The underlying binding error.
        source: TokenBindingError,
    },
    /// The introspection call failed.
    #[snafu(display("introspection call error"))]
    Call {
        /// The token type that was presented, used to select the challenge that
        /// receives error details.
        token_type: TokenType,
        /// The underlying introspection call error.
        source: IntrospectionCallError,
    },
    /// The introspected token's audience did not satisfy the configured check
    /// (RFC 7662 §4).
    #[snafu(display(
        "token audience mismatch: expected {expected}, got [{}]",
        actual.join(", ")
    ))]
    Audience {
        /// The token type that was presented, used to select the challenge that
        /// receives error details.
        token_type: TokenType,
        /// A description of the expected audience.
        expected: String,
        /// The audience values from the introspection response.
        actual: Vec<String>,
    },
}

impl ToRfc6750Error for IntrospectionValidateError {
    fn challenge(&self) -> Challenge {
        match self {
            Self::Extract { source } => source.challenge(),
            Self::Binding { source, .. } => source.challenge(),
            Self::Call { source, .. } => source.challenge(),
            Self::Audience { .. } => {
                Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                    .with_description("The access token is not intended for this resource")
            }
        }
    }

    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Binding { token_type, .. }
            | Self::Call { token_type, .. }
            | Self::Audience { token_type, .. } => Some(*token_type),
        }
    }

    fn validation_outcome(&self, challenge: &Challenge) -> ValidationOutcome {
        match challenge.error {
            // Metrics must agree with the wire: a 5xx (a failed endpoint call,
            // or a nonce checker down) is our failure, whichever check tripped
            // it, and a nonce challenge is routine churn, not a binding failure.
            TokenValidationError::Server { .. } => return ValidationOutcome::CallError,
            TokenValidationError::Client(TokenErrorCode::UseDPoPNonce) => {
                return ValidationOutcome::NonceRequired;
            }
            TokenValidationError::Client(_) => {}
        }
        match self {
            Self::Extract { .. } => ValidationOutcome::ExtractError,
            Self::Binding { .. } => ValidationOutcome::BindingError,
            // Post-triage, the only client-classified call failure is an
            // inactive token — a bad token, like a bad audience.
            Self::Audience { .. } | Self::Call { .. } => ValidationOutcome::InvalidToken,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::binding::MtlsBindingError;

    crate::forwarding_table! {
        /// Every variant with an inner challenge preserves it unchanged.
        introspection_validate_error_forwards {
            || TokenExtractError::InvalidTokenHeaderFormat
                => |source| IntrospectionValidateError::Extract { source },
            || TokenBindingError::MtlsBinding {
                source: MtlsBindingError::CertBoundTokenWithoutCert,
            } => |source| IntrospectionValidateError::Binding {
                token_type: TokenType::Bearer,
                source,
            },
            || IntrospectionCallError::TokenInactive
                => |source| IntrospectionValidateError::Call {
                    token_type: TokenType::Bearer,
                    source,
                },
            || IntrospectionCallError::UnexpectedJwtResponse
                => |source| IntrospectionValidateError::Call {
                    token_type: TokenType::DPoP,
                    source,
                },
        }
    }
}
