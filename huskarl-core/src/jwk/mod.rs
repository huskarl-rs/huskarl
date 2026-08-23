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
pub use source::{JwksSource, JwksStartup};
use zeroize::Zeroize;

use crate::{
    error::Error,
    jwk::serde_utils::{
        base64url, base64url_uint, option_base64url, option_base64url_uint, trim_leading_zeros,
    },
};

/// The cause of a JWK handling failure.
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum JwkError {
    /// A symmetric key was supplied where an asymmetric one is required.
    #[snafu(display("expected an asymmetric private JWK, got a symmetric (oct) key"))]
    #[classify(no)]
    ExpectedAsymmetric,
    /// An asymmetric key was supplied where a symmetric one is required.
    #[snafu(display("expected a symmetric (oct) JWK, got an asymmetric private key"))]
    #[classify(no)]
    ExpectedSymmetric,
    /// The JWK JSON did not parse.
    #[snafu(display("parsing JWK JSON"))]
    #[classify(no)]
    ParsingJson {
        /// The underlying error.
        source: serde_json::Error,
    },
    /// The JWK parsed but carries no private key material.
    #[snafu(display("JWK JSON contains no secret key material"))]
    #[classify(no)]
    NoSecretKeyMaterial,
    /// A JWKS exceeded the configured key limit.
    #[snafu(display("JWKS contains {count} keys, exceeding the limit of {max}"))]
    #[classify(no)]
    TooManyKeys {
        /// How many keys the JWKS carried.
        count: usize,
        /// The configured ceiling.
        max: usize,
    },
    /// The platform has no verifier for any key type.
    #[snafu(display("this platform supports no keys"))]
    #[classify(no)]
    NoSupportedKeys,
}

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

    /// Returns a [`PrivateJwk`] if the underlying key has secret material
    /// present: [`PrivateJwk::Asymmetric`] for RSA/EC/OKP keys carrying their
    /// private parameters, [`PrivateJwk::Symmetric`] for `oct` keys (which are
    /// nothing but secret material). Returns `None` for public-only or unknown
    /// keys.
    #[must_use]
    pub fn private_jwk(&self) -> Option<PrivateJwk> {
        if let Key::Oct(oct) = &self.key {
            return Some(PrivateJwk::Symmetric(SymmetricJwk {
                key: oct.clone(),
                key_use: self.key_use,
                key_operations: self.key_operations.clone(),
                algorithm: self.algorithm.clone(),
                kid: self.kid.clone(),
            }));
        }
        self.key.private_key().map(|key| {
            PrivateJwk::Asymmetric(Box::new(AsymmetricPrivateJwk {
                key,
                key_use: self.key_use,
                key_operations: self.key_operations.clone(),
                algorithm: self.algorithm.clone(),
                kid: self.kid.clone(),
                x5u: self.x5u.clone(),
            }))
        })
    }
}

/// An asymmetric JSON Web Key with guaranteed private material (RFC 7517 §4).
///
/// Like [`Jwk`], but the key is a [`PrivateKey`] — the private exponent `d` is
/// guaranteed present, so the public half is always derivable
/// ([`public_jwk`](Self::public_jwk) and [`thumbprint`](Self::thumbprint) are
/// infallible). Obtained via [`Jwk::private_jwk()`] (as the
/// [`PrivateJwk::Asymmetric`] variant); to serialize/deserialize, convert
/// to/from [`Jwk`].
#[non_exhaustive]
#[derive(Debug, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct AsymmetricPrivateJwk {
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

impl AsymmetricPrivateJwk {
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

impl From<AsymmetricPrivateJwk> for Jwk {
    fn from(pjwk: AsymmetricPrivateJwk) -> Self {
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

impl From<AsymmetricPrivateJwk> for PublicJwk {
    fn from(pjwk: AsymmetricPrivateJwk) -> Self {
        pjwk.public_jwk()
    }
}

/// A symmetric (`oct`) JSON Web Key (RFC 7518 §6.4).
///
/// Like [`Jwk`], but the key is guaranteed to be an [`OctKey`] — pure secret
/// material with no public half, used for HMAC signing (`HS*`) and symmetric
/// AEAD encryption (`A*GCM`, `A*KW`). Obtained via [`Jwk::private_jwk()`] (as
/// the [`PrivateJwk::Symmetric`] variant); to serialize/deserialize, convert
/// to/from [`Jwk`].
#[non_exhaustive]
#[derive(Debug, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct SymmetricJwk {
    /// The symmetric key material.
    #[builder(into)]
    pub key: OctKey,
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
}

impl From<SymmetricJwk> for Jwk {
    fn from(sjwk: SymmetricJwk) -> Self {
        Self {
            key: sjwk.key.into(),
            key_use: sjwk.key_use,
            key_operations: sjwk.key_operations,
            algorithm: sjwk.algorithm,
            kid: sjwk.kid,
            x5u: None,
        }
    }
}

/// A JSON Web Key with guaranteed secret material, of either kind.
///
/// The single currency of the key-loading funnels: every loader takes a
/// `Secret<Output = PrivateJwk>`, so decoders are chosen by *input format*
/// (JWK JSON, PKCS#8, raw bytes) rather than by key kind. Each `from_secret`
/// funnel accepts the variant it can finalize and rejects the other with a
/// configuration error.
///
/// Not serializable directly — convert to/from [`Jwk`] for the wire form.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum PrivateJwk {
    /// An asymmetric (RSA/EC/OKP) key with private parameters present.
    // Boxed: RSA private parameters make this variant much larger than the
    // symmetric one.
    Asymmetric(Box<AsymmetricPrivateJwk>),
    /// A symmetric (`oct`) key.
    Symmetric(SymmetricJwk),
}

impl PrivateJwk {
    /// The key ID, whichever variant carries it.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        match self {
            PrivateJwk::Asymmetric(jwk) => jwk.kid.as_deref(),
            PrivateJwk::Symmetric(jwk) => jwk.kid.as_deref(),
        }
    }

    /// Applies the loading funnels' key-ID precedence: an explicit JWK `kid`
    /// wins; otherwise `fallback` (typically the secret source's identity,
    /// e.g. a secret-manager version name) fills it.
    #[must_use]
    pub fn with_kid_fallback(mut self, fallback: Option<String>) -> Self {
        let kid = match &mut self {
            PrivateJwk::Asymmetric(jwk) => &mut jwk.kid,
            PrivateJwk::Symmetric(jwk) => &mut jwk.kid,
        };
        if kid.is_none() {
            *kid = fallback;
        }
        self
    }
}

impl From<AsymmetricPrivateJwk> for PrivateJwk {
    fn from(jwk: AsymmetricPrivateJwk) -> Self {
        Self::Asymmetric(Box::new(jwk))
    }
}

impl From<SymmetricJwk> for PrivateJwk {
    fn from(jwk: SymmetricJwk) -> Self {
        Self::Symmetric(jwk)
    }
}

impl From<PrivateJwk> for Jwk {
    fn from(pjwk: PrivateJwk) -> Self {
        match pjwk {
            PrivateJwk::Asymmetric(jwk) => (*jwk).into(),
            PrivateJwk::Symmetric(jwk) => jwk.into(),
        }
    }
}

impl TryFrom<PrivateJwk> for AsymmetricPrivateJwk {
    type Error = Error;

    fn try_from(value: PrivateJwk) -> Result<Self, Self::Error> {
        match value {
            PrivateJwk::Asymmetric(jwk) => Ok(*jwk),
            PrivateJwk::Symmetric(_) => Err(JwkError::ExpectedAsymmetric.into()),
        }
    }
}

impl TryFrom<PrivateJwk> for SymmetricJwk {
    type Error = Error;

    fn try_from(value: PrivateJwk) -> Result<Self, Self::Error> {
        match value {
            PrivateJwk::Symmetric(jwk) => Ok(jwk),
            PrivateJwk::Asymmetric(_) => Err(JwkError::ExpectedSymmetric.into()),
        }
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
