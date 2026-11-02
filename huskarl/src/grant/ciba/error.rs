use snafu::Snafu;

use crate::{
    core::{Error, RetryAdvice},
    token::id_token::IdTokenValidationError,
};

#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[snafu(visibility(pub(super)))]
pub(super) enum CibaError {
    #[snafu(display("CIBA requires client authentication"))]
    #[classify(no)]
    ClientAuthenticationRequired,
    #[snafu(display("the provider does not advertise CIBA poll mode"))]
    #[classify(no)]
    PollModeUnsupported,
    #[snafu(display(
        "the provider does not support the configured CIBA request signing algorithm"
    ))]
    #[classify(no)]
    RequestSigningUnsupported,
    #[snafu(display("the provider does not support CIBA user codes"))]
    #[classify(no)]
    UserCodeUnsupported,
    #[snafu(display("the CIBA acknowledgement contains an empty authentication request ID"))]
    #[classify(no)]
    InvalidAcknowledgement,
    #[cfg(feature = "experimental-oidc-key-binding")]
    #[snafu(display("CIBA does not support the bound_key scope"))]
    #[classify(no)]
    BoundKeyUnsupported,
}

/// Errors from CIBA polling and authentication completion.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum PollError {
    /// The user or provider denied the authentication request.
    #[snafu(display("the user or provider denied the authentication request"))]
    AccessDenied,
    /// The authentication request expired.
    #[snafu(display("the authentication request expired before the user finished"))]
    TokenExpired,
    /// The token exchange failed. Inspect retry advice before polling again.
    #[snafu(display("polling the token endpoint"))]
    Exchange {
        /// Underlying exchange error, including any provider verdict.
        source: Error,
    },
    /// The provider returned tokens without the required ID token.
    #[snafu(display("the CIBA token response has no ID token"))]
    MissingIdToken {
        /// Issued response; it must not be treated as a validated identity.
        token_response: Box<crate::grant::core::TokenResponse>,
    },
    /// The validated subject differs from the application's expected user.
    #[snafu(display("the CIBA ID-token subject does not match the expected user"))]
    SubjectMismatch {
        /// Issued response; it must not be treated as a validated identity.
        token_response: Box<crate::grant::core::TokenResponse>,
    },
    /// The returned ID token could not be validated.
    #[snafu(display("validating the CIBA ID token"))]
    ValidatingIdToken {
        /// Underlying ID-token validation error.
        source: IdTokenValidationError,
        /// Issued response retained for independent validation retries.
        token_response: Box<crate::grant::core::TokenResponse>,
    },
}

impl PollError {
    /// Recovers issued tokens after a completion failure. These tokens do not
    /// establish a validated identity. Retry validation with `CibaPollGrant::complete`.
    /// Exchange, denial, and expiry errors have no issued response to recover.
    #[must_use]
    pub fn into_token_response(self) -> Option<crate::grant::core::TokenResponse> {
        match self {
            Self::MissingIdToken { token_response }
            | Self::SubjectMismatch { token_response }
            | Self::ValidatingIdToken { token_response, .. } => Some(*token_response),
            Self::AccessDenied | Self::TokenExpired | Self::Exchange { .. } => None,
        }
    }

    /// Returns whether another token request may help and any minimum delay.
    ///
    /// Exchange errors retain their retry advice. Denial, expiry, and
    /// completion errors are terminal: completion has already redeemed the ID.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            Self::Exchange { source } => source.retry_advice(),
            Self::AccessDenied
            | Self::TokenExpired
            | Self::MissingIdToken { .. }
            | Self::SubjectMismatch { .. }
            | Self::ValidatingIdToken { .. } => RetryAdvice::No,
        }
    }
}
