use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::Deserialize;
use snafu::prelude::*;

use crate::jwt::structure::{JwtClaims, JwtHeader};

/// An error that occurred while parsing a compact JWS token.
#[derive(Debug, Snafu)]
pub enum JwsParseError {
    /// Wrong number of `.`-separated parts
    InvalidFormat,
    /// A JWS part could not be decoded as `Base64URL`.
    Base64 {
        /// The underlying error.
        source: base64::DecodeError,
    },
    /// The header could not be parsed.
    Header {
        /// The underlying error.
        source: serde_json::Error,
    },
    /// The claims could not be parsed.
    Claims {
        /// The underlying error.
        source: serde_json::Error,
    },
}

/// A compact JWS split into its parts, as produced by [`parse_compact_jws`].
///
/// The header and claims are deserialized, but the signature is **not** verified
/// at this stage — pass it to
/// [`JwtValidator::validate_parsed_jws`](crate::jwt::validator::JwtValidator::validate_parsed_jws)
/// to verify and validate. `signing_input` is the byte range the signature covers.
pub struct ParsedJws<H: Clone + 'static, C: Clone + 'static> {
    /// The header of the JWS token.
    pub header: JwtHeader<'static, H>,
    /// The claims of the JWS token.
    pub claims: JwtClaims<'static, C>,
    /// The signing input of the JWS token.
    pub signing_input: Vec<u8>,
    /// The signature of the JWS token.
    pub signature: Vec<u8>,
}

/// Parses a compact JWS token into a [`ParsedJws`].
///
/// # Errors
///
/// Returns an error if the token is not a valid compact JWS token.
pub fn parse_compact_jws<
    H: Clone + for<'de> Deserialize<'de>,
    C: Clone + for<'de> Deserialize<'de>,
>(
    token: &str,
) -> Result<ParsedJws<H, C>, JwsParseError> {
    // `splitn(4, ..)` bounds the work done on hostile input: a token of N
    // dots is rejected after at most four iterator steps, with no
    // proportional allocation.
    let mut parts = token.splitn(4, '.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return InvalidFormatSnafu.fail();
    };

    let signing_input = format!("{header_b64}.{claims_b64}").into_bytes();
    let header = BASE64_URL_SAFE_NO_PAD
        .decode(header_b64)
        .context(Base64Snafu)?;
    let claims = BASE64_URL_SAFE_NO_PAD
        .decode(claims_b64)
        .context(Base64Snafu)?;
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(signature_b64)
        .context(Base64Snafu)?;

    Ok(ParsedJws {
        header: serde_json::from_slice(&header).context(HeaderSnafu)?,
        claims: serde_json::from_slice(&claims).context(ClaimsSnafu)?,
        signing_input,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use serde::Deserialize;

    use crate::{
        jwt::{ParsedJws, parse_compact_jws},
        platform::{Duration, SystemTime},
    };

    /// Tests the example values from RFC 7519 §3.1.
    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "RFC 7519 §3.1 example value"
    )]
    fn test_rfc_7519_example() {
        #[derive(Debug, Clone, Deserialize, PartialEq)]
        struct TestClaims {
            #[serde(rename = "http://example.com/is_root")]
            is_root: bool,
        }

        let token_str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let jws: ParsedJws<(), TestClaims> = parse_compact_jws(token_str).unwrap();

        assert_eq!(jws.header.alg, "HS256".to_string());
        assert_eq!(jws.header.typ, Some("JWT".to_string().into()));

        assert_eq!(jws.claims.iss, Some("joe".to_string().into()));
        assert_eq!(jws.claims.sub, None);
        assert_eq!(jws.claims.aud, Vec::<String>::new());
        assert_eq!(jws.claims.iat, None);
        assert_eq!(
            jws.claims.exp,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_300_819_380))
        );
        assert_eq!(jws.claims.nbf, None);
        assert_eq!(jws.claims.jti, None);
        assert_eq!(jws.claims.claims, Cow::Owned(TestClaims { is_root: true }));
    }

    fn parse_err(token: &str) -> super::JwsParseError {
        match parse_compact_jws::<(), ()>(token) {
            Ok(_) => unreachable!("expected parse failure"),
            Err(e) => e,
        }
    }

    #[test]
    fn rejects_wrong_part_counts() {
        assert!(matches!(
            parse_err("a.b"),
            super::JwsParseError::InvalidFormat
        ));
        assert!(matches!(
            parse_err("a.b.c.d"),
            super::JwsParseError::InvalidFormat
        ));
        assert!(matches!(parse_err(""), super::JwsParseError::InvalidFormat));
    }

    #[test]
    fn rejects_dot_flood_without_amplification() {
        // A hostile token of only separators must be rejected up front; with
        // splitn the parser inspects at most four parts regardless of length.
        let hostile = ".".repeat(1_000_000);
        assert!(matches!(
            parse_err(&hostile),
            super::JwsParseError::InvalidFormat
        ));
    }
}
