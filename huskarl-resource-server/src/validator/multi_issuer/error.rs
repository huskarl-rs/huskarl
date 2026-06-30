//! Error type for [`MultiIssuerValidator`](super::MultiIssuerValidator).

use snafu::Snafu;

use crate::{
    TokenType,
    error::{ChallengeParam, ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::extract::TokenExtractError,
};

/// A failure of a [`MultiIssuerValidator`](super::MultiIssuerValidator).
///
/// Distinct from the inner validators' errors because routing has a failure mode
/// they do not: a token whose issuer cannot be determined or is not registered.
/// Inner-validator failures are wrapped in [`MultiIssuerError::Validation`] and
/// their RFC 6750 classification is forwarded unchanged.
///
/// `Debug`, `Display`, and [`std::error::Error`] are derived; the RFC 6750
/// classification is provided by the [`ToRfc6750Error`] impl below.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum MultiIssuerError {
    /// The access token could not be extracted from the request headers.
    #[snafu(display("token presentation error"), context(false))]
    Extract {
        /// The underlying extraction error.
        source: TokenExtractError,
    },
    /// A token was present, but its `iss` claim was missing, unparseable, or did
    /// not match any registered issuer. Treated as `invalid_token`.
    #[snafu(display("unrecognized token issuer"))]
    UnrecognizedIssuer,
    /// The validator selected for the token's issuer rejected it; its RFC 6750
    /// classification is forwarded unchanged.
    #[snafu(display("token validation error"))]
    Validation {
        /// The inner validator's error. Not named `source` because it is a
        /// [`ToRfc6750Error`], not a [`std::error::Error`], so it does not chain.
        error: Box<dyn ToRfc6750Error>,
    },
}

impl ToRfc6750Error for MultiIssuerError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::UnrecognizedIssuer => None,
            Self::Validation { error } => error.attempted_scheme(),
        }
    }

    fn token_error(&self) -> TokenValidationError {
        match self {
            Self::Extract { source } => source.token_error(),
            Self::UnrecognizedIssuer => TokenValidationError::Client(TokenErrorCode::InvalidToken),
            Self::Validation { error } => error.token_error(),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::Extract { source } => source.error_description(),
            Self::UnrecognizedIssuer => Some("unrecognized token issuer".to_owned()),
            Self::Validation { error } => error.error_description(),
        }
    }

    fn extra_params(&self) -> Vec<ChallengeParam> {
        match self {
            Self::Extract { source } => source.extra_params(),
            Self::UnrecognizedIssuer => Vec::new(),
            Self::Validation { error } => error.extra_params(),
        }
    }
}
