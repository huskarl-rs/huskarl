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
/// Returns `None` if the header is absent.
///
/// # Errors
///
/// Returns a [`TokenExtractError`] if the header value is not valid UTF-8, does
/// not consist of exactly a scheme and a token value, or uses an unsupported
/// scheme.
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
#[non_exhaustive]
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

#[cfg(test)]
mod tests {
    use http::{HeaderValue, header::AUTHORIZATION};
    use rstest::rstest;

    use super::*;

    /// Builds a `HeaderMap` carrying `value` under the `Authorization` header.
    fn auth_headers(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static(value));
        headers
    }

    /// Runs `extract_token` against the default `Authorization` header.
    fn extract(
        value: &'static str,
    ) -> Result<Option<(TokenType, SecretString)>, TokenExtractError> {
        extract_token(&auth_headers(value), &AUTHORIZATION)
    }

    #[rstest]
    #[case::bearer("Bearer mF_9.B5f-4.1JqM", TokenType::Bearer, "mF_9.B5f-4.1JqM")]
    #[case::dpop("DPoP mF_9.B5f-4.1JqM", TokenType::DPoP, "mF_9.B5f-4.1JqM")]
    // Scheme matching is case-insensitive (RFC 7235 §2.1).
    #[case::lower_bearer("bearer tok", TokenType::Bearer, "tok")]
    #[case::upper_bearer("BEARER tok", TokenType::Bearer, "tok")]
    #[case::lower_dpop("dpop tok", TokenType::DPoP, "tok")]
    #[case::upper_dpop("DPOP tok", TokenType::DPoP, "tok")]
    // Leading/trailing whitespace and collapsed separators still leave exactly
    // two fields: the scheme and the token.
    #[case::whitespace("  Bearer   the-token  ", TokenType::Bearer, "the-token")]
    fn valid_token_is_extracted(
        #[case] header: &'static str,
        #[case] expected_type: TokenType,
        #[case] expected_token: &str,
    ) {
        let (token_type, token) = extract(header).unwrap().unwrap();
        assert_eq!(token_type, expected_type);
        assert_eq!(token.expose_secret(), expected_token);
    }

    #[rstest]
    #[case::scheme_only("Bearer")]
    #[case::empty("   ")]
    // A token value must not contain whitespace; a third field is rejected
    // rather than silently truncated.
    #[case::three_fields("Bearer tok extra")]
    fn invalid_format_is_rejected(#[case] header: &'static str) {
        assert!(
            matches!(
                extract(header),
                Err(TokenExtractError::InvalidTokenHeaderFormat)
            ),
            "expected InvalidTokenHeaderFormat for {header:?}"
        );
    }

    #[test]
    fn absent_header_is_none() {
        let headers = HeaderMap::new();
        assert!(matches!(extract_token(&headers, &AUTHORIZATION), Ok(None)));
    }

    #[test]
    fn unsupported_scheme_is_rejected() {
        let err = extract("Basic dXNlcjpwYXNz").unwrap_err();
        assert!(
            matches!(err, TokenExtractError::UnsupportedTokenType { ref token_type } if token_type == "Basic"),
            "got {err:?}"
        );
    }

    #[test]
    fn non_utf8_header_value_is_rejected() {
        let mut headers = HeaderMap::new();
        // 0xFF is never valid UTF-8, so `to_str` fails before any parsing.
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );
        assert!(matches!(
            extract_token(&headers, &AUTHORIZATION),
            Err(TokenExtractError::TokenNotString { .. })
        ));
    }

    #[test]
    fn token_is_read_from_the_configured_header() {
        let header = HeaderName::from_static("x-access-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            &header,
            HeaderValue::from_static("Bearer custom-header-token"),
        );

        // The configured header is used...
        let (token_type, token) = extract_token(&headers, &header).unwrap().unwrap();
        assert_eq!(token_type, TokenType::Bearer);
        assert_eq!(token.expose_secret(), "custom-header-token");

        // ...and the default `Authorization` header is not consulted.
        assert!(matches!(extract_token(&headers, &AUTHORIZATION), Ok(None)));
    }
}
