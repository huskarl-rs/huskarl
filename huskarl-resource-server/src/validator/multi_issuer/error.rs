//! Error type for [`MultiIssuerValidator`](super::MultiIssuerValidator).

use snafu::Snafu;

use crate::{
    TokenType,
    error::{ChallengeParam, ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{extract::TokenExtractError, observe::ValidationOutcome},
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
    // Debug-quoted: the peeked value is attacker-controlled, so escape any
    // control characters before it reaches a log line.
    #[snafu(display(
        "unrecognized token issuer{}",
        iss.as_ref().map_or_else(String::new, |i| format!(": {i:?}"))
    ))]
    UnrecognizedIssuer {
        /// The token's `iss` claim as peeked from the **unverified** payload,
        /// when one could be read. Diagnostic only — an attacker controls it,
        /// so never use it as a metrics label.
        iss: Option<String>,
    },
    /// The validator selected for the token's issuer rejected it; its RFC 6750
    /// classification is forwarded unchanged.
    #[snafu(display("token validation error (issuer {issuer})"))]
    Validation {
        /// The registered issuer the token routed to.
        issuer: String,
        /// The inner validator's error. Not named `source` because it is a
        /// [`ToRfc6750Error`], not a [`std::error::Error`], so it does not chain.
        error: Box<dyn ToRfc6750Error>,
    },
}

impl ToRfc6750Error for MultiIssuerError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::UnrecognizedIssuer { .. } => None,
            Self::Validation { error, .. } => error.attempted_scheme(),
        }
    }

    fn token_error(&self) -> TokenValidationError {
        match self {
            Self::Extract { source } => source.token_error(),
            Self::UnrecognizedIssuer { .. } => {
                TokenValidationError::Client(TokenErrorCode::InvalidToken)
            }
            Self::Validation { error, .. } => error.token_error(),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::Extract { source } => source.error_description(),
            Self::UnrecognizedIssuer { .. } => Some("unrecognized token issuer".to_owned()),
            Self::Validation { error, .. } => error.error_description(),
        }
    }

    fn extra_params(&self) -> Vec<ChallengeParam> {
        match self {
            Self::Extract { source } => source.extra_params(),
            Self::UnrecognizedIssuer { .. } => Vec::new(),
            Self::Validation { error, .. } => error.extra_params(),
        }
    }

    fn validation_outcome(&self) -> ValidationOutcome {
        match self {
            Self::Extract { .. } => ValidationOutcome::ExtractError,
            Self::UnrecognizedIssuer { .. } => ValidationOutcome::UnrecognizedIssuer,
            Self::Validation { error, .. } => error.validation_outcome(),
        }
    }

    fn issuer(&self) -> Option<&str> {
        match self {
            // Only the registered issuer is a trusted, bounded label; the
            // peeked `iss` of an unrecognized issuer is attacker-controlled.
            Self::Validation { issuer, .. } => Some(issuer),
            Self::Extract { .. } | Self::UnrecognizedIssuer { .. } => None,
        }
    }
}
