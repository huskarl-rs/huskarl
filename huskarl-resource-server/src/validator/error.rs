//! Internal token validation error types.

use http::header::ToStrError;
use snafu::prelude::*;
use strum::EnumMessage as _;

use crate::{
    TokenType,
    core::jwt::validator::JwtValidationError,
    error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{
        binding::{DPoPBindingError, MtlsBindingError},
        extract::TokenExtractError,
    },
};

/// Errors that can occur during token binding validation.
// `#[strum(message)]` on each variant carries the client-facing RFC 6750
// `error_description`; the `#[snafu(display)]` / doc comment is the
// operator-facing `Display`. Variants that delegate to a `source` carry no
// message and are handled explicitly in `ToRfc6750Error::error_description`.
#[derive(Debug, Snafu, strum::EnumMessage)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum TokenBindingError {
    /// The `DPoP` header is required but missing from the request.
    #[strum(message = "The DPoP header is missing")]
    MissingDPoPHeader,
    /// The `DPoP` header is present but is not valid UTF-8.
    #[strum(message = "The DPoP header value is invalid")]
    DPoPHeaderNotString {
        /// The underlying string conversion error.
        source: ToStrError,
    },
    /// More than one `DPoP` header was present (RFC 9449 §4.3 requires exactly one).
    #[snafu(display("Request has more than one DPoP header"))]
    #[strum(message = "The request has more than one DPoP header")]
    MultipleDPoPHeaders,
    /// The token has a `DPoP` key binding (`cnf.jkt`) but was presented as a Bearer token.
    ///
    /// Per RFC 9449 §7.1, DPoP-bound tokens MUST be presented using the `DPoP`
    /// token type, not `Bearer`. Accepting a bound token as Bearer would allow an
    /// attacker who stole the token to use it without possessing the private key.
    #[snafu(display("Token is DPoP-bound but was presented as Bearer"))]
    #[strum(message = "The access token is DPoP-bound")]
    DPoPRequiredForBoundToken,
    /// `DPoP` is required by this resource server but the token was presented as Bearer.
    #[snafu(display("DPoP-bound tokens are required"))]
    #[strum(message = "DPoP is required to access this resource")]
    DPoPRequired,
    /// The token `cnf` claim contains a confirmation method that is not supported.
    /// Only `jkt` (`DPoP`) and `x5t#S256` (mTLS) are checked; `jwe` and `jku` are rejected
    /// rather than silently ignored, per RFC 7800's requirement that applications ensure
    /// confirmation members they require are understood and processed.
    #[snafu(display("Unsupported cnf confirmation method: {method}"))]
    #[strum(message = "The access token confirmation method is not supported")]
    UnsupportedCnfMethod {
        /// The name of the unsupported confirmation method.
        method: &'static str,
    },
    /// The `DPoP` binding is invalid.
    DPoPBinding {
        /// The underlying `DPoP` binding error.
        source: DPoPBindingError,
    },
    /// The mTLS binding is invalid.
    MtlsBinding {
        /// The underlying mTLS binding error.
        source: MtlsBindingError,
    },
}

impl ToRfc6750Error for TokenBindingError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::MissingDPoPHeader
            | Self::DPoPHeaderNotString { .. }
            | Self::MultipleDPoPHeaders
            | Self::DPoPBinding { .. } => Some(TokenType::DPoP),
            Self::DPoPRequiredForBoundToken
            | Self::DPoPRequired
            | Self::UnsupportedCnfMethod { .. }
            | Self::MtlsBinding { .. } => None,
        }
    }

    fn token_error(&self) -> TokenValidationError {
        match self {
            Self::MissingDPoPHeader
            | Self::DPoPHeaderNotString { .. }
            | Self::MultipleDPoPHeaders => {
                TokenValidationError::Client(TokenErrorCode::InvalidRequest)
            }
            Self::DPoPRequiredForBoundToken
            | Self::DPoPRequired
            | Self::UnsupportedCnfMethod { .. }
            | Self::MtlsBinding { .. } => {
                TokenValidationError::Client(TokenErrorCode::InvalidToken)
            }
            Self::DPoPBinding { source } => source.token_error(),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            // These delegate to their inner source; the rest carry a static
            // `#[strum(message)]` returned via `get_message()`.
            Self::DPoPBinding { source } => source.error_description(),
            Self::MtlsBinding { source } => source.error_description(),
            other => other.get_message().map(str::to_string),
        }
    }
}

/// Errors that can occur while extracting and binding-checking an access token from request headers.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum ValidateHeadersError {
    /// The access token could not be extracted from the request headers.
    #[snafu(display("Token presentation error"))]
    Extract {
        /// The underlying extraction error.
        source: TokenExtractError,
    },
    /// The token sender-constraint binding check failed.
    #[snafu(display("Token binding error"))]
    Binding {
        /// The token type that was presented.
        token_type: TokenType,
        /// The underlying binding error.
        source: TokenBindingError,
    },
    /// The token is not a valid JWT.
    InvalidJwt {
        /// The token type that was presented.
        token_type: TokenType,
        /// The underlying JWT validation error.
        source: JwtValidationError,
    },
}

impl ToRfc6750Error for ValidateHeadersError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Binding { token_type, .. } | Self::InvalidJwt { token_type, .. } => {
                Some(*token_type)
            }
        }
    }

    fn token_error(&self) -> TokenValidationError {
        match self {
            Self::Extract { source } => source.token_error(),
            Self::Binding { source, .. } => source.token_error(),
            Self::InvalidJwt { source, .. } => source.token_error(),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::Extract { source } => source.error_description(),
            Self::Binding { source, .. } => source.error_description(),
            Self::InvalidJwt { source, .. } => source.error_description(),
        }
    }
}
