use http::header::ToStrError;
use huskarl_core::token::validator::JwtValidationError;
use snafu::prelude::*;

use crate::{
    error::Rfc6750ErrorCode,
    validator::{
        binding::{DPoPBindingError, MtlsBindingError},
        extract::TokenExtractError,
    },
};

/// Errors that can occur during token binding validation.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum TokenBindingError {
    /// The DPoP header is required but missing from the request.
    MissingDPoPHeader,
    /// The DPoP header is present but is not valid UTF-8.
    DPoPHeaderNotString { source: ToStrError },
    /// The token has a DPoP key binding (`cnf.jkt`) but was presented as a Bearer token.
    ///
    /// Per RFC 9449 §7.1, DPoP-bound tokens MUST be presented using the `DPoP`
    /// token type, not `Bearer`. Accepting a bound token as Bearer would allow an
    /// attacker who stole the token to use it without possessing the private key.
    #[snafu(display("Token is DPoP-bound but was presented as Bearer"))]
    DpopRequiredForBoundToken,
    /// DPoP is required by this resource server but the token was presented as Bearer.
    #[snafu(display("DPoP-bound tokens are required"))]
    DpopRequired,
    /// The token `cnf` claim contains a confirmation method that is not supported.
    /// Only `jkt` (DPoP) and `x5t#S256` (mTLS) are checked; `jwe` and `jku` are rejected
    /// rather than silently ignored, per RFC 7800's requirement that applications ensure
    /// confirmation members they require are understood and processed.
    #[snafu(display("Unsupported cnf confirmation method: {method}"))]
    UnsupportedCnfMethod { method: &'static str },
    /// The DPoP binding is invalid.
    DPoPBinding { source: DPoPBindingError },
    /// The mTLS binding is invalid.
    MtlsBinding { source: MtlsBindingError },
}

impl TokenBindingError {
    /// Returns the RFC 6750 §3.1 error code for this error.
    pub fn rfc6750_error_code(&self) -> Rfc6750ErrorCode {
        match self {
            Self::MissingDPoPHeader | Self::DPoPHeaderNotString { .. } => {
                Rfc6750ErrorCode::InvalidRequest
            }
            Self::DpopRequiredForBoundToken
            | Self::DpopRequired
            | Self::UnsupportedCnfMethod { .. }
            | Self::DPoPBinding { .. }
            | Self::MtlsBinding { .. } => Rfc6750ErrorCode::InvalidToken,
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum ValidateHeadersError {
    /// Errors in extracting or binding-checking the access token from the request.
    #[snafu(display("Token presentation error"))]
    Extract { source: TokenExtractError },
    #[snafu(display("Token binding error"))]
    Binding { source: TokenBindingError },
    /// The token is not a valid JWT.
    InvalidJwt { source: JwtValidationError },
}

impl ValidateHeadersError {
    /// Returns the RFC 6750 §3.1 error code for this error.
    ///
    /// If `validate_request` returns `Ok(None)`, the client provided no
    /// authentication. Per RFC 6750, respond with HTTP 401 and
    /// `WWW-Authenticate: Bearer` but without an error code.
    pub fn rfc6750_error_code(&self) -> Rfc6750ErrorCode {
        match self {
            Self::Extract { source } => source.rfc6750_error_code(),
            Self::Binding { source } => source.rfc6750_error_code(),
            Self::InvalidJwt { .. } => Rfc6750ErrorCode::InvalidToken,
        }
    }
}
