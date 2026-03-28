use http::{HeaderMap, HeaderName, header::ToStrError};
use huskarl_core::secrets::SecretString;
use snafu::prelude::*;

use crate::error::Rfc6750ErrorCode;

#[derive(Debug, Clone, Copy)]
pub enum TokenType {
    Bearer,
    DPoP,
}

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

    let access_token = SecretString::new(token_value.to_string());
    Ok(Some((token_type, access_token)))
}

/// Errors that can occur when validating the token string and type.
#[derive(Debug, Snafu)]
pub enum TokenExtractError {
    /// The token header value is not valid UTF-8.
    TokenNotString { source: ToStrError },
    /// The token header is not in `<scheme> <token>` format.
    InvalidTokenHeaderFormat,
    /// The token scheme is not supported.
    ///
    /// Currently `Bearer` and `DPoP` are supported.
    UnsupportedTokenType { token_type: String },
}

impl TokenExtractError {
    /// Returns the RFC 6750 §3.1 error code for this error.
    pub fn rfc6750_error_code(&self) -> Rfc6750ErrorCode {
        Rfc6750ErrorCode::InvalidRequest
    }
}
