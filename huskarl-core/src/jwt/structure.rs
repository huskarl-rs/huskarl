use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::{jwk::PublicJwk, platform::SystemTime};

/// The `cnf` (confirmation) claim, used to bind a JWT to a key (RFC 7800).
///
/// Only `jkt` (`DPoP` key thumbprint, RFC 9449) and `x5t#S256` (mTLS certificate
/// thumbprint, RFC 8705 §4) are the well-known members. `jwe` and `jku` are
/// captured to allow callers to detect and reject them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    /// The JWK thumbprint of the `DPoP` key bound to this token (RFC 9449 §4.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    /// The SHA-256 thumbprint of the client certificate bound to this token (RFC 8705 §4).
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    /// Encrypted key confirmation (RFC 7800 §3.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwe: Option<serde_json::Value>,
    /// JWK Set URL confirmation (RFC 7800 §3.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<serde_json::Value>,
}

/// A JOSE header (RFC 7515 §4) with the registered parameters huskarl
/// processes, plus type-safe extra parameters via `ExtraHeaders`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "ExtraHeaders: serde::de::Deserialize<'de>"))]
pub struct JwtHeader<'a, ExtraHeaders: Clone> {
    /// The JWS algorithm (RFC 7515 §4.1.1), e.g. `ES256`.
    pub alg: Cow<'a, str>,
    /// The media type of the token (RFC 7515 §4.1.9), e.g. `at+jwt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<Cow<'a, str>>,
    /// The identifier of the key used to sign the token (RFC 7515 §4.1.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<Cow<'a, str>>,
    /// RFC 7515 §4.1.11: critical header parameters. Any non-empty value means the
    /// verifier MUST understand all listed parameters or reject the JWS entirely.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crit: Vec<String>,
    /// Embedded public key — present only in `DPoP` proofs (RFC 9449 §4.2).
    /// Must not appear in ordinary JWTs; validators should reject tokens that include
    /// it unless they are specifically processing a `DPoP` proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<PublicJwk>,
    /// Additional header parameters beyond the registered set, captured
    /// type-safely via the `ExtraHeaders` type parameter.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_headers: Option<Cow<'a, ExtraHeaders>>,
}

/// The registered JWT claims (RFC 7519 §4.1), with additional claims captured
/// type-safely via the `Claims` type parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Claims: serde::de::Deserialize<'de>"))]
pub struct JwtClaims<'a, Claims: Clone> {
    /// The issuer of the token (RFC 7519 §4.1.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<Cow<'a, str>>,
    /// The subject of the token (RFC 7519 §4.1.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<Cow<'a, str>>,
    /// The audiences of the token (RFC 7519 §4.1.3). A bare-string `aud`
    /// deserializes as a single-element vector; an absent claim as empty.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::serde_utils::string::string_or_vec"
    )]
    pub aud: Vec<String>,
    /// When the token was issued (RFC 7519 §4.1.6).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::time::option_unix_secs"
    )]
    pub iat: Option<SystemTime>,
    /// When the token expires (RFC 7519 §4.1.4).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::time::option_unix_secs"
    )]
    pub exp: Option<SystemTime>,
    /// The time before which the token must not be accepted (RFC 7519 §4.1.5).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::time::option_unix_secs"
    )]
    pub nbf: Option<SystemTime>,
    /// The unique identifier of the token (RFC 7519 §4.1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<Cow<'a, str>>,
    /// Key confirmation claim (RFC 7800). Binds the token to a `DPoP` key or mTLS certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
    /// Additional claims beyond the registered JWT claim set.
    #[serde(flatten)]
    pub claims: Cow<'a, Claims>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // --- aud serialization ---

    #[test]
    fn aud_serialize_empty() {
        let claims = JwtClaims::<'static, ()> {
            iss: None,
            sub: None,
            aud: vec![],
            iat: None,
            exp: None,
            nbf: None,
            jti: None,
            cnf: None,
            claims: Cow::Owned(()),
        };
        let v = serde_json::to_value(&claims).unwrap();
        assert!(v.get("aud").is_none());
    }

    #[test]
    fn aud_serialize_single() {
        let claims = JwtClaims::<'static, ()> {
            iss: None,
            sub: None,
            aud: vec!["https://example.com".into()],
            iat: None,
            exp: None,
            nbf: None,
            jti: None,
            cnf: None,
            claims: Cow::Owned(()),
        };
        let v = serde_json::to_value(&claims).unwrap();
        assert_eq!(v["aud"], json!("https://example.com"));
    }

    #[test]
    fn aud_serialize_multiple() {
        let claims = JwtClaims::<'static, ()> {
            iss: None,
            sub: None,
            aud: vec!["a".into(), "b".into()],
            iat: None,
            exp: None,
            nbf: None,
            jti: None,
            cnf: None,
            claims: Cow::Owned(()),
        };
        let v = serde_json::to_value(&claims).unwrap();
        assert_eq!(v["aud"], json!(["a", "b"]));
    }

    // --- aud deserialization ---

    #[test]
    fn aud_deserialize_string() {
        let j = r#"{"aud":"x"}"#;
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert_eq!(c.aud, vec!["x"]);
    }

    #[test]
    fn aud_deserialize_array() {
        let j = r#"{"aud":["a","b"]}"#;
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert_eq!(c.aud, vec!["a", "b"]);
    }

    #[test]
    fn aud_deserialize_null() {
        let j = r#"{"aud":null}"#;
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert!(c.aud.is_empty());
    }

    #[test]
    fn aud_deserialize_absent() {
        let j = r"{}";
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert!(c.aud.is_empty());
    }

    // --- Timestamp deserialization ---

    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + crate::platform::Duration::from_secs(secs)
    }

    #[test]
    fn timestamp_integer() {
        let j = r#"{"iat":1234}"#;
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert_eq!(c.iat, Some(epoch_plus(1234)));
    }

    #[test]
    fn timestamp_float_truncates() {
        let j = r#"{"iat":1234.5}"#;
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert_eq!(c.iat, Some(epoch_plus(1234)));
    }

    #[test]
    fn timestamp_negative_errors() {
        let j = r#"{"iat":-1}"#;
        let result = serde_json::from_str::<JwtClaims<'_, ()>>(j);
        assert!(result.is_err());
    }

    #[test]
    fn timestamp_overflowing_system_time_errors() {
        // u64::MAX seconds is past the platform's representable SystemTime range;
        // this must be a deserialization error, never a later panic in validation.
        for claim in ["iat", "exp", "nbf"] {
            let j = format!(r#"{{"{claim}":18446744073709551615}}"#);
            let result = serde_json::from_str::<JwtClaims<'_, ()>>(&j);
            assert!(result.is_err(), "{claim} should be rejected");
        }
    }

    #[test]
    fn timestamp_null() {
        let j = r#"{"iat":null}"#;
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert_eq!(c.iat, None);
    }

    #[test]
    fn timestamp_absent() {
        let j = r"{}";
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert_eq!(c.iat, None);
        assert_eq!(c.exp, None);
        assert_eq!(c.nbf, None);
    }

    #[test]
    fn all_timestamps() {
        let j = r#"{"iat":100,"exp":200,"nbf":50}"#;
        let c: JwtClaims<'_, ()> = serde_json::from_str(j).unwrap();
        assert_eq!(c.iat, Some(epoch_plus(100)));
        assert_eq!(c.exp, Some(epoch_plus(200)));
        assert_eq!(c.nbf, Some(epoch_plus(50)));
    }

    // --- ConfirmationClaim roundtrip ---

    #[test]
    fn confirmation_claim_roundtrip() {
        let cnf = ConfirmationClaim {
            jkt: Some("thumbprint-value".into()),
            x5t_s256: Some("cert-thumbprint".into()),
            jwe: None,
            jku: None,
        };
        let json = serde_json::to_string(&cnf).unwrap();
        assert!(json.contains("\"jkt\""));
        assert!(json.contains("\"x5t#S256\""));

        let roundtripped: ConfirmationClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.jkt.as_deref(), Some("thumbprint-value"));
        assert_eq!(roundtripped.x5t_s256.as_deref(), Some("cert-thumbprint"));
    }

    #[test]
    fn confirmation_claim_skips_none() {
        let cnf = ConfirmationClaim {
            jkt: None,
            x5t_s256: None,
            jwe: None,
            jku: None,
        };
        let json = serde_json::to_string(&cnf).unwrap();
        assert_eq!(json, "{}");
    }
}
