use http::header::ToStrError;
use huskarl_core::jwt::validator::JwtValidationError;
use snafu::prelude::*;

use crate::{
    TokenType,
    error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
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

impl ToRfc6750Error for TokenBindingError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::MissingDPoPHeader
            | Self::DPoPHeaderNotString { .. }
            | Self::DPoPBinding { .. } => Some(TokenType::DPoP),
            Self::DpopRequiredForBoundToken
            | Self::DpopRequired
            | Self::UnsupportedCnfMethod { .. }
            | Self::MtlsBinding { .. } => None,
        }
    }

    fn token_error(&self) -> TokenValidationError {
        match self {
            Self::MissingDPoPHeader | Self::DPoPHeaderNotString { .. } => {
                TokenValidationError::Client(TokenErrorCode::InvalidRequest)
            }
            Self::DpopRequiredForBoundToken
            | Self::DpopRequired
            | Self::UnsupportedCnfMethod { .. }
            | Self::MtlsBinding { .. } => {
                TokenValidationError::Client(TokenErrorCode::InvalidToken)
            }
            Self::DPoPBinding { source } => source.token_error(),
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            Self::MissingDPoPHeader => Some("The DPoP header is missing".to_string()),
            Self::DPoPHeaderNotString { .. } => {
                Some("The DPoP header value is invalid".to_string())
            }
            Self::DpopRequiredForBoundToken => Some("The access token is DPoP-bound".to_string()),
            Self::DpopRequired => Some("DPoP is required to access this resource".to_string()),
            Self::UnsupportedCnfMethod { .. } => {
                Some("The access token confirmation method is not supported".to_string())
            }
            Self::DPoPBinding { source } => source.error_description(),
            Self::MtlsBinding { source } => source.error_description(),
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
    Binding {
        token_type: TokenType,
        source: TokenBindingError,
    },
    /// The token is not a valid JWT.
    InvalidJwt {
        token_type: TokenType,
        source: JwtValidationError,
    },
}

impl ToRfc6750Error for ValidateHeadersError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Binding { token_type, .. } => Some(*token_type),
            Self::InvalidJwt { token_type, .. } => Some(*token_type),
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
