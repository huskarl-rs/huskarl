//! Access token extraction from HTTP headers.

use http::{HeaderMap, HeaderName, header::ToStrError};
use snafu::prelude::*;
use strum::EnumMessage as _;

use crate::{
    core::secrets::SecretString,
    error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
};

/// The scheme used to present an access token in an HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// A Bearer token (`Authorization: Bearer <token>`), as defined in RFC 6750.
    Bearer,
    /// A DPoP-bound token (`Authorization: DPoP <token>`), as defined in RFC 9449.
    DPoP,
}

/// Extracts the access token type and value from an HTTP header.
///
/// Returns `None` if the header is absent, or an error if the header is malformed
/// or uses an unsupported scheme.
pub fn extract_token(
    headers: &HeaderMap,
    token_header: &HeaderName,
) -> Result<Option<(TokenType, SecretString)>, TokenExtractError> {
    // 1. Extract token string from the configured header
    let Some(token_header) = headers
        .get(token_header)
        .map(|hv| hv.to_str().context(TokenNotStringSnafu))
        .transpose()?
    else {
        return Ok(None);
    };

    let token_header_fields = token_header.split_whitespace().take(3).collect::<Vec<_>>();
    if token_header_fields.len() != 2 {
        InvalidTokenHeaderFormatSnafu.fail()?;
    }

    let (token_type, token_value) = (token_header_fields[0], token_header_fields[1]);

    let token_type = if token_type.eq_ignore_ascii_case("bearer") {
        TokenType::Bearer
    } else if token_type.eq_ignore_ascii_case("dpop") {
        TokenType::DPoP
    } else {
        UnsupportedTokenTypeSnafu { token_type }.fail()?
    };

    let access_token = SecretString::new(token_value);
    Ok(Some((token_type, access_token)))
}

/// Errors that can occur when validating the token string and type.
// `#[strum(message)]` on each variant carries the client-facing RFC 6750
// `error_description`; the doc comment is the operator-facing `Display`.
#[derive(Debug, Snafu, strum::EnumMessage)]
pub enum TokenExtractError {
    /// The token header value is not valid UTF-8.
    #[strum(message = "The access token header value is not a valid string")]
    TokenNotString {
        /// The underlying string conversion error.
        source: ToStrError,
    },
    /// The token header is not in `<scheme> <token>` format.
    #[strum(message = "The access token header format is invalid")]
    InvalidTokenHeaderFormat,
    /// The token scheme is not supported.
    ///
    /// Currently `Bearer` and `DPoP` are supported.
    #[strum(message = "The access token type is unsupported")]
    UnsupportedTokenType {
        /// The unrecognised token type scheme.
        token_type: String,
    },
}

impl ToRfc6750Error for TokenExtractError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            TokenExtractError::UnsupportedTokenType { token_type } => {
                if token_type.eq_ignore_ascii_case("dpop") {
                    Some(TokenType::DPoP)
                } else if token_type.eq_ignore_ascii_case("bearer") {
                    Some(TokenType::Bearer)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InvalidRequest)
    }

    fn error_description(&self) -> Option<String> {
        self.get_message().map(str::to_string)
    }
}
