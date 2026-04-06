use http::{HeaderMap, HeaderName, header::ToStrError};
use huskarl_core::secrets::SecretString;
use snafu::prelude::*;

use crate::error::{ToRfc6750Error, TokenErrorCode, TokenValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    let access_token = SecretString::new(token_value);
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
        match self {
            TokenExtractError::TokenNotString { .. } => {
                Some("The access token header value is not a valid string".to_string())
            }
            TokenExtractError::InvalidTokenHeaderFormat => {
                Some("The access token header format is invalid".to_string())
            }
            TokenExtractError::UnsupportedTokenType { .. } => {
                Some("The access token type is unsupported".to_string())
            }
        }
    }
}
