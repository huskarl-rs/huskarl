use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::jwk::PublicJwk;

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

fn serialize_string_or_vec<S>(values: &'_ Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeSeq as _;

    match values.len() {
        0 => serializer.serialize_none(),
        1 => serializer.serialize_str(values[0].as_ref()),
        n => {
            let mut seq = serializer.serialize_seq(Some(n))?;
            for element in values {
                seq.serialize_element(element)?;
            }
            seq.end()
        }
    }
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or array of strings")
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![v])
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![v.to_owned()])
        }

        fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![v.to_owned()])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(1));
            while let Some(value) = seq.next_element()? {
                vec.push(value);
            }
            Ok(vec)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

fn deserialize_whole_or_fractional<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct WholeOrFractionalOrNull;

    impl<'de> de::Visitor<'de> for WholeOrFractionalOrNull {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a positive numeric value, or null")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(v))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v < 0 {
                return Err(E::custom("cannot have a negative value"));
            }

            Ok(Some(v.cast_unsigned()))
        }

        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_precision_loss)]
        #[allow(clippy::cast_sign_loss)]
        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.is_nan() {
                return Err(E::custom("cannot be NaN"));
            }

            if v < 0.0 || v > u64::MAX as f64 {
                return Err(E::custom("outside u64 range"));
            }

            Ok(Some(v as u64))
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(WholeOrFractionalOrNull)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "ExtraHeaders: serde::de::Deserialize<'de>"))]
pub struct JwtHeader<'a, ExtraHeaders: Clone> {
    pub alg: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<Cow<'a, str>>,
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
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_headers: Option<Cow<'a, ExtraHeaders>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "ExtraClaims: serde::de::Deserialize<'de>"))]
pub struct JwtClaims<'a, ExtraClaims: Clone> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<Cow<'a, str>>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_string_or_vec",
        serialize_with = "serialize_string_or_vec"
    )]
    pub aud: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_whole_or_fractional"
    )]
    pub iat: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_whole_or_fractional"
    )]
    pub exp: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_whole_or_fractional"
    )]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<Cow<'a, str>>,
    /// Key confirmation claim (RFC 7800). Binds the token to a `DPoP` key or mTLS certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaim>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<Cow<'a, ExtraClaims>>,
}
