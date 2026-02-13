//! JSON Web Key (JWK) types per RFC 7517/7518/8037.
//!
//! This module provides wire format types for creating and parsing JWK/JWKS.
//!
//! Some values here are sourced from the above RFCs, also with reference to
//! <https://www.iana.org/assignments/jose/jose.xhtml>.

mod serde_utils;

use crate::jwk::serde_utils::{base64url, base64url_uint};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bon::Builder;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A JSON Web Key Set (RFC 7517 §5).
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PublicJwks {
    /// List of keys
    pub keys: Vec<PublicJwk>,
}

/// A JSON Web Key (RFC 7517 §4).
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into), builder_type(
    doc {
        /// Builder for creating a [`PublicJwk`] value (call `build()` or `into()` to finish).
    }
))]
pub struct PublicJwk {
    /// The key details.
    #[builder(into)]
    #[serde(flatten)]
    pub key: PublicKey,
    /// The key use for this key.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,
    /// The key operations for this key.
    #[builder(default, with = <_>::from_iter)]
    #[serde(rename = "key_ops", default, skip_serializing_if = "Vec::is_empty")]
    pub key_operations: Vec<KeyOperation>,
    /// The algorithm of this key.
    #[builder(into)]
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// The key ID of this key.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl PublicJwk {
    #[must_use]
    pub fn thumbprint(&self) -> Option<String> {
        let canonical_form = match &self.key {
            PublicKey::Rsa(rsa_public_key) => Some(rsa_public_key.canonical_form()),
            PublicKey::Ec(ec_public_key) => Some(ec_public_key.canonical_form()),
            PublicKey::Okp(okp_public_key) => Some(okp_public_key.canonical_form()),
            PublicKey::UnknownOrPrivate => None,
        };

        canonical_form.map(|canonical| {
            let mut hasher = Sha256::new();
            hasher.update(canonical.as_bytes());
            let hash = hasher.finalize();
            URL_SAFE_NO_PAD.encode(hash)
        })
    }
}

/// Key use parameter (RFC 7517 §4.2).
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum KeyUse {
    /// Digital signature or MAC.
    #[serde(rename = "sig")]
    Sign,
    /// Encryption.
    #[serde(rename = "enc")]
    Encrypt,
    /// Unknown key use value.
    #[serde(skip, other)]
    Unknown,
}

/// Key operations parameter (RFC 7517 §4.3).
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum KeyOperation {
    /// Compute digital signature or MAC.
    Sign,
    /// Verify digital signature or MAC.
    Verify,
    /// Encrypt content.
    Encrypt,
    /// Decrypt content and validate decryption.
    Decrypt,
    /// Encrypt key.
    WrapKey,
    /// Decrypt key and validate decryption.
    UnwrapKey,
    /// Derive key.
    DeriveKey,
    /// Derive bits not to be used as a key.
    DeriveBits,
    /// Unknown key operation.
    #[serde(skip, other)]
    Unknown,
}

/// The parts of a public key that vary structurally between types (RFC 7517 §4).
///
/// The list of values for `kty` come from
/// <https://www.iana.org/assignments/jose/jose.xhtml#web-key-types>.
/// It doesn't include `AKP` which is an RFC draft at this time.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(tag = "kty")] //
pub enum PublicKey {
    /// An RSA public key.
    #[serde(rename = "RSA")]
    Rsa(RsaPublicKey),
    /// An Elliptic Curve public key.
    #[serde(rename = "EC")]
    Ec(EcPublicKey),
    /// An Octet Key Pair public key.
    #[serde(rename = "OKP")]
    Okp(OkpPublicKey),
    /// Unknown or private key.
    #[serde(skip, other)]
    UnknownOrPrivate,
}

/// An RSA public key.
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into), builder_type(
    doc {
        /// Builder for creating an [`RsaPublicKey`] value (call `build()` or `into()` to finish).
    }
))]
pub struct RsaPublicKey {
    /// The n coordinate of the key.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url_uint")]
    pub n: Vec<u8>,
    /// The exponent of the key.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url_uint")]
    pub e: Vec<u8>,
}

impl RsaPublicKey {
    pub(super) fn canonical_form(&self) -> String {
        let e = URL_SAFE_NO_PAD.encode(&self.e);
        let n = URL_SAFE_NO_PAD.encode(&self.n);

        format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
    }
}

impl From<RsaPublicKey> for PublicKey {
    fn from(value: RsaPublicKey) -> Self {
        Self::Rsa(value)
    }
}

impl<S: rsa_public_key_builder::State> From<RsaPublicKeyBuilder<S>> for PublicKey
where
    S: rsa_public_key_builder::IsComplete,
{
    fn from(value: RsaPublicKeyBuilder<S>) -> Self {
        Self::Rsa(value.build())
    }
}

/// An Elliptic Curve public key.
///
/// Parameters are defined in RFC 7518 §6.2.
/// Technically, the `y` field is optional, but all currently defined `EC`-type keys require a value.
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into), builder_type(
    doc {
        /// Builder for creating a [`EcPublicKey`] value (call `build()` or `into()` to finish).
    }
))]
pub struct EcPublicKey {
    /// The curve type.
    #[builder(into)]
    pub crv: String,
    /// The x coordinate of the curve.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url")]
    pub x: Vec<u8>,
    /// The y coordinate of the curve.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url")]
    pub y: Vec<u8>,
}

impl EcPublicKey {
    pub(super) fn canonical_form(&self) -> String {
        let crv = &self.crv;
        let x = URL_SAFE_NO_PAD.encode(&self.x);
        let y = URL_SAFE_NO_PAD.encode(&self.y);

        format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
    }
}

impl From<EcPublicKey> for PublicKey {
    fn from(value: EcPublicKey) -> Self {
        Self::Ec(value)
    }
}

impl<S: ec_public_key_builder::State> From<EcPublicKeyBuilder<S>> for PublicKey
where
    S: ec_public_key_builder::IsComplete,
{
    fn from(value: EcPublicKeyBuilder<S>) -> Self {
        Self::Ec(value.build())
    }
}

/// An Octet Key Pair public key.
///
/// Parameters are defined in RFC 8037 §2.
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into), builder_type(
    doc {
        /// Builder for creating a [`OkpPublicKey`] value (call `build()` or `into()` to finish).
    }
))]
pub struct OkpPublicKey {
    /// The curve type.
    #[builder(into)]
    pub crv: String,
    /// The x coordinate of the curve.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url")]
    pub x: Vec<u8>,
}

impl OkpPublicKey {
    pub(super) fn canonical_form(&self) -> String {
        let crv = &self.crv;
        let x = URL_SAFE_NO_PAD.encode(&self.x);

        format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
    }
}

impl From<OkpPublicKey> for PublicKey {
    fn from(value: OkpPublicKey) -> Self {
        Self::Okp(value)
    }
}

impl<S: okp_public_key_builder::State> From<OkpPublicKeyBuilder<S>> for PublicKey
where
    S: okp_public_key_builder::IsComplete,
{
    fn from(value: OkpPublicKeyBuilder<S>) -> Self {
        Self::Okp(value.build())
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    use super::*;

    // Example public key from https://www.rfc-editor.org/rfc/rfc7517.html#appendix-A.1
    #[test]
    fn test_parse_jwks_appendix_a1() {
        let jwks_json = r#"{"keys":[
            {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"},
            {"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}
        ]}"#;

        let jwks: PublicJwks = serde_json::from_str(jwks_json).unwrap();

        let key1 = PublicJwk::builder()
            .key(
                EcPublicKey::builder()
                    .crv("P-256")
                    .x(BASE64_URL_SAFE_NO_PAD
                        .decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
                        .unwrap())
                    .y(BASE64_URL_SAFE_NO_PAD
                        .decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
                        .unwrap()),
            )
            .key_use(KeyUse::Encrypt)
            .kid("1")
            .build();

        let key2 = PublicJwk::builder().key(
            RsaPublicKey::builder()
                .n(BASE64_URL_SAFE_NO_PAD.decode(
                    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
                ).unwrap())
                .e(BASE64_URL_SAFE_NO_PAD.decode("AQAB").unwrap())
        )
        .algorithm("RS256")
        .kid("2011-04-29")
        .build();

        assert_eq!(jwks.keys, vec![key1, key2]);
    }

    #[test]
    fn test_unknown_curve_parses() {
        // Unknown curve should parse successfully
        let unknown_curve = r#"{"kty":"EC","crv":"brainpoolP256r1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
        let _: PublicJwk = serde_json::from_str(unknown_curve).unwrap();
    }
}
