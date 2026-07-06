//! JSON Web Key (JWK) types per RFC 7517/7518/8037.
//!
//! This module provides wire format types for creating and parsing JWK/JWKS.
//!
//! Some values here are sourced from the above RFCs, also with reference to
//! <https://www.iana.org/assignments/jose/jose.xhtml>.
//!
//! The X.509 parameters (`x5c`, `x5t`, `x5t#S256`, `x5u`) are handled
//! conservatively: `x5u` is **rejected** when it arrives from an untrusted
//! source, and the others are ignored. See [handling untrusted
//! keys](crate::_docs::explanation::untrusted_keys) for the rationale.

mod serde_utils;
mod source;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bon::Builder;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
pub use source::JwksSource;
use zeroize::Zeroize;

use crate::jwk::serde_utils::{
    base64url, base64url_uint, option_base64url, option_base64url_uint, trim_leading_zeros,
};

mod decode;
mod key;
mod private;
mod public;

pub use decode::*;
pub use key::*;
pub use private::*;
pub use public::*;

/// A JSON Web Key containing private key material (RFC 7517 §4).
///
/// Mirrors [`PublicJwk`] but holds a [`Key`] (which may contain private
/// parameters). Use [`Jwk::public_jwk`] to strip private material.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct Jwk {
    /// The key details (includes private material).
    #[builder(into)]
    #[serde(flatten)]
    pub key: Key,
    /// The key use for this key.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,
    /// The key operations for this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(with = <_>::from_iter)]
    #[serde(rename = "key_ops")]
    pub key_operations: Option<Vec<KeyOperation>>,
    /// The algorithm of this key.
    #[builder(into)]
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// The key ID of this key.
    #[builder(into)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// X.509 URL (RFC 7517 §4.6).
    ///
    /// See [`PublicJwk::x5u`] for rationale.
    #[builder(skip)]
    #[serde(rename = "x5u", default, skip_serializing)]
    pub x5u: Option<String>,
}

impl Jwk {
    /// Converts to a [`PublicJwk`] by stripping private key material.
    ///
    /// Returns `None` for symmetric (`Oct`) keys, which have no public
    /// representation.
    #[must_use]
    pub fn public_jwk(&self) -> Option<PublicJwk> {
        self.key.public_key().map(|key| PublicJwk {
            key,
            key_use: self.key_use,
            key_operations: self.key_operations.clone(),
            algorithm: self.algorithm.clone(),
            kid: self.kid.clone(),
            x5u: self.x5u.clone(),
            has_private_parameters: false,
        })
    }

    /// Returns a validated [`PrivateKey`] if the underlying key has private
    /// material present.
    #[must_use]
    pub fn private_key(&self) -> Option<PrivateKey> {
        self.key.private_key()
    }

    /// Returns a [`PrivateJwk`] if the underlying key has private material
    /// present, or `None` for public-only, symmetric (`Oct`), or unknown keys.
    #[must_use]
    pub fn private_jwk(&self) -> Option<PrivateJwk> {
        self.key.private_key().map(|key| PrivateJwk {
            key,
            key_use: self.key_use,
            key_operations: self.key_operations.clone(),
            algorithm: self.algorithm.clone(),
            kid: self.kid.clone(),
            x5u: self.x5u.clone(),
        })
    }
}

/// A JSON Web Key with guaranteed private material (RFC 7517 §4).
///
/// Like [`Jwk`], but the key is a [`PrivateKey`] — the private exponent `d` is
/// guaranteed present. Obtained via [`Jwk::private_jwk()`]; to
/// serialize/deserialize, convert to/from [`Jwk`].
#[non_exhaustive]
#[derive(Debug, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct PrivateJwk {
    /// The private key (guaranteed to contain private material).
    #[builder(into)]
    pub key: PrivateKey,
    /// The key use for this key.
    pub key_use: Option<KeyUse>,
    /// The key operations for this key.
    #[builder(with = <_>::from_iter)]
    pub key_operations: Option<Vec<KeyOperation>>,
    /// The algorithm of this key.
    #[builder(into)]
    pub algorithm: Option<String>,
    /// The key ID of this key.
    #[builder(into)]
    pub kid: Option<String>,
    /// X.509 URL (RFC 7517 §4.6).
    ///
    /// See [`PublicJwk::x5u`] for rationale.
    #[builder(skip)]
    pub x5u: Option<String>,
}

impl PrivateJwk {
    /// Converts to a [`PublicJwk`] by stripping private key material.
    #[must_use]
    pub fn public_jwk(&self) -> PublicJwk {
        PublicJwk {
            key: self.key.public_key(),
            key_use: self.key_use,
            key_operations: self.key_operations.clone(),
            algorithm: self.algorithm.clone(),
            kid: self.kid.clone(),
            x5u: self.x5u.clone(),
            has_private_parameters: false,
        }
    }

    /// Returns the JWK thumbprint (RFC 7638) for the key.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        self.public_jwk().thumbprint()
    }
}

impl From<PrivateJwk> for Jwk {
    fn from(pjwk: PrivateJwk) -> Self {
        Self {
            key: pjwk.key.into(),
            key_use: pjwk.key_use,
            key_operations: pjwk.key_operations,
            algorithm: pjwk.algorithm,
            kid: pjwk.kid,
            x5u: pjwk.x5u,
        }
    }
}

impl From<PrivateJwk> for PublicJwk {
    fn from(pjwk: PrivateJwk) -> Self {
        pjwk.public_jwk()
    }
}

/// A JSON Web Key Set containing private key material (RFC 7517 §5).
///
/// Mirrors [`PublicJwks`]. Convert to `PublicJwks` via `From` to strip private
/// material (symmetric keys are filtered out).
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Jwks {
    /// List of keys.
    ///
    /// Deserialization is lenient per entry: an entry that is not a valid JWK
    /// is skipped rather than failing the whole set — one malformed key in an
    /// `IdP`'s JWKS must not take down verification for its good keys. Unknown
    /// `kty` values are absorbed as [`Key::Unknown`]; this extends the same
    /// policy to malformed known-`kty` entries.
    #[serde(deserialize_with = "deserialize_keys_lenient")]
    pub keys: Vec<Jwk>,
}

/// Deserializes each `keys` entry independently, skipping invalid ones. A
/// non-array `keys` value still fails the parse.
fn deserialize_keys_lenient<'de, D>(deserializer: D) -> Result<Vec<Jwk>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let entries = Vec::<serde_json::Value>::deserialize(deserializer)?;
    Ok(entries
        .into_iter()
        .filter_map(|entry| serde_json::from_value(entry).ok())
        .collect())
}

impl Jwks {
    /// Creates a new `Jwks` from the given keys.
    #[must_use]
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }
}

impl From<Jwks> for PublicJwks {
    fn from(jwks: Jwks) -> Self {
        PublicJwks::new(jwks.keys.iter().filter_map(Jwk::public_jwk).collect())
    }
}

#[cfg(test)]
mod tests;
