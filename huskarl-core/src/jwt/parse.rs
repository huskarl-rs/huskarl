use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::Deserialize;
use snafu::prelude::*;

use crate::jwt::structure::{JwtClaims, JwtHeader};

/// An error that occurred while parsing a compact JWS token.
#[derive(Debug, Snafu)]
pub enum JwsParseError {
    /// Wrong number of `.`-separated parts.
    #[snafu(display("a compact JWS has three '.'-separated parts"))]
    InvalidFormat,
    /// A JWS part could not be decoded as `Base64URL`.
    #[snafu(display("decoding a base64url JWS part"))]
    Base64 {
        /// The underlying error.
        source: base64::DecodeError,
    },
    /// The header could not be parsed.
    #[snafu(display("parsing the JWS header"))]
    Header {
        /// The underlying error.
        source: serde_json::Error,
    },
    /// The claims could not be parsed.
    #[snafu(display("parsing the JWS claims"))]
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
    parse_with_payload(token, |_| Ok(())).map(|(parsed, ())| parsed)
}

/// Parses a compact JWS and its `cnf` claim into a caller-selected type.
///
/// Use this for confirmation methods not represented by [`crate::jwt::ConfirmationClaim`].
/// The returned JWS retains the usual registered claims and can be passed to
/// [`JwtValidator::validate_parsed_jws`](crate::jwt::validator::JwtValidator::validate_parsed_jws).
/// Neither the token nor the separately returned confirmation is authenticated
/// until that validation succeeds. Missing or null `cnf` returns `None`.
///
/// This experimental compatibility bridge may be removed when the shared
/// confirmation type supports these methods in a future breaking release.
///
/// # Errors
///
/// Returns an error for malformed compact JWS data or claims, including a `cnf`
/// value that cannot be deserialized as `Confirmation`.
pub fn parse_compact_jws_with_confirmation<
    H: Clone + for<'de> Deserialize<'de>,
    C: Clone + for<'de> Deserialize<'de>,
    Confirmation: for<'de> Deserialize<'de>,
>(
    token: &str,
) -> Result<(ParsedJws<H, C>, Option<Confirmation>), JwsParseError> {
    #[derive(Deserialize)]
    struct Payload<T> {
        cnf: Option<T>,
    }

    parse_with_payload(token, |payload| {
        let payload: Payload<Confirmation> =
            serde_json::from_slice(payload).context(ClaimsSnafu)?;
        Ok(payload.cnf)
    })
}

fn parse_with_payload<
    H: Clone + for<'de> Deserialize<'de>,
    C: Clone + for<'de> Deserialize<'de>,
    T,
>(
    token: &str,
    extract: impl FnOnce(&[u8]) -> Result<T, JwsParseError>,
) -> Result<(ParsedJws<H, C>, T), JwsParseError> {
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

    let extra = extract(&claims)?;
    Ok((
        ParsedJws {
            header: serde_json::from_slice(&header).context(HeaderSnafu)?,
            claims: serde_json::from_slice(&claims).context(ClaimsSnafu)?,
            signing_input,
            signature,
        },
        extra,
    ))
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
            // The RFC's example `exp` is 1300819380 seconds.
            Some(SystemTime::UNIX_EPOCH + Duration::from_mins(21_680_323))
        );
        assert_eq!(jws.claims.nbf, None);
        assert_eq!(jws.claims.jti, None);
        assert_eq!(jws.claims.claims, Cow::Owned(TestClaims { is_root: true }));
    }

    fn parse_err(token: &str) -> super::JwsParseError {
        match parse_compact_jws::<(), ()>(token) {
            Ok(_) => panic!("expected parse failure"),
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

#[cfg(test)]
mod confirmation_tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::jwt::JwkConfirmationClaim;

    fn token(payload: &str) -> String {
        format!(
            "{}.{}.AA",
            BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#),
            BASE64_URL_SAFE_NO_PAD.encode(payload)
        )
    }

    fn jwk() -> Value {
        json!({"kty":"EC", "crv":"P-256",
            "x":"f83OJ3D2xF4Oyv7l-lkyU-iLN6v2Rn5SQkCRUgvAJMY",
            "y":"x_FEzRu9m36HLN_tue659lnhW8b2b7bZwzkHBJGi8z0"})
    }

    #[test]
    fn parses_confirmation_without_losing_registered_or_extra_claims() {
        let payload = json!({"iss":"issuer", "aud":"client", "sub":"user",
            "custom":42, "cnf":{"jwk":jwk(), "jkt":"thumbprint"}});
        let compact = token(&payload.to_string());
        let (parsed, confirmation) =
            parse_compact_jws_with_confirmation::<(), Value, Value>(&compact).unwrap();
        let ordinary = parse_compact_jws::<(), Value>(&compact).unwrap();
        assert_eq!(parsed.signing_input, ordinary.signing_input);
        assert_eq!(parsed.signature, ordinary.signature);
        assert_eq!(parsed.header.alg, ordinary.header.alg);
        assert_eq!(
            serde_json::to_value(&parsed.claims).unwrap(),
            serde_json::to_value(&ordinary.claims).unwrap()
        );
        assert_eq!(
            parsed.claims.cnf.unwrap().jkt.as_deref(),
            Some("thumbprint")
        );
        assert_eq!(confirmation.unwrap(), payload["cnf"]);
    }

    #[test]
    fn shared_jwk_confirmation_is_typed_and_strict() {
        let payload = json!({"cnf":{"jwk":jwk()}});
        let compact = token(&payload.to_string());
        let (_, confirmation) =
            parse_compact_jws_with_confirmation::<(), (), JwkConfirmationClaim>(&compact).unwrap();
        let expected: crate::jwk::PublicJwk = serde_json::from_value(jwk()).unwrap();
        assert_eq!(confirmation.unwrap().jwk, expected);

        for cnf in [
            json!({"jwk":jwk(), "jkt":"other"}),
            json!({"jwk":jwk(), "unknown":null}),
            json!({}),
            json!({"jwk":"malformed"}),
        ] {
            let compact = token(&json!({"cnf":cnf}).to_string());
            // Preserve the existing parser's handling of unrecognized jwk data.
            assert!(parse_compact_jws::<(), ()>(&compact).is_ok());
            assert!(matches!(
                parse_compact_jws_with_confirmation::<(), (), JwkConfirmationClaim>(&compact),
                Err(JwsParseError::Claims { .. })
            ));
        }
    }

    #[test]
    fn absent_confirmation_and_duplicate_members_are_handled() {
        for payload in ["{}", r#"{"cnf":null}"#] {
            let (_, confirmation) =
                parse_compact_jws_with_confirmation::<(), (), JwkConfirmationClaim>(&token(
                    payload,
                ))
                .unwrap();
            assert!(confirmation.is_none());
        }
        let duplicate = format!(r#"{{"cnf":{{"jwk":{0}}},"cnf":{{"jwk":{0}}}}}"#, jwk());
        assert!(matches!(
            parse_compact_jws_with_confirmation::<(), (), JwkConfirmationClaim>(&token(&duplicate)),
            Err(JwsParseError::Claims { .. })
        ));
    }

    #[test]
    fn confirmation_parser_uses_compact_jws_format_checks() {
        for compact in [
            "a.b".to_owned(),
            "a.b.c.d".to_owned(),
            ".".repeat(1_000_000),
        ] {
            assert!(matches!(
                parse_compact_jws_with_confirmation::<(), (), JwkConfirmationClaim>(&compact),
                Err(JwsParseError::InvalidFormat)
            ));
        }
    }
}
