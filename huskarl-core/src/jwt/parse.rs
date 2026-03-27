use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::Deserialize;
use snafu::{ensure, prelude::*};

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

/// A parsed compact JWS token.
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
    let parts = token.split('.').collect::<Vec<_>>();

    ensure!(parts.len() == 3, InvalidFormatSnafu);
    let signing_input = format!("{}.{}", parts[0], parts[1]).as_bytes().to_vec();
    let header = BASE64_URL_SAFE_NO_PAD
        .decode(parts[0])
        .context(Base64Snafu)?;
    let claims = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .context(Base64Snafu)?;
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(parts[2])
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

    use crate::jwt::{ParsedJws, parse_compact_jws};

    /// Tests example from
    #[test]
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
        assert_eq!(jws.claims.exp, Some(1_300_819_380));
        assert_eq!(jws.claims.nbf, None);
        assert_eq!(jws.claims.jti, None);
        assert_eq!(
            jws.claims.extra_claims,
            Some(Cow::Owned(TestClaims { is_root: true }))
        );
    }
}
