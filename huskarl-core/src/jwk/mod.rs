//! JSON Web Key (JWK) types per RFC 7517/7518/8037.
//!
//! This module provides wire format types for creating and parsing JWK/JWKS.
//!
//! Some values here are sourced from the above RFCs, also with reference to
//! <https://www.iana.org/assignments/jose/jose.xhtml>.
//!
//! ## X.509 certificate parameters (`x5c`, `x5t`, `x5t#S256`, `x5u`)
//!
//! RFC 7517 §4.6–4.9 defines four X.509-related JWK parameters. This library
//! handles them as follows:
//!
//! - **`x5u`** (X.509 URL): Captured and **rejected** when present in JWKs from
//!   untrusted sources such as `DPoP` proof headers (RFC 9449 §4.2). Like `jku` in
//!   JWS headers, `x5u` triggers a remote fetch which introduces SSRF risk and
//!   allows an attacker to substitute their own key material. Per RFC 7517 §4.6,
//!   the referenced resource must be secured, but this cannot be verified at parse
//!   time; rejection is the safe default.
//!
//! - **`x5c`** (X.509 certificate chain): Silently ignored. Certificate chain
//!   validation against trust anchors is not implemented; the key material (`n`,
//!   `e`, `x`, `y`, etc.) is used directly. Some providers (e.g. Microsoft Entra)
//!   include `x5c` in their JWKS — this is harmless since the signing key material
//!   is present regardless.
//!
//! - **`x5t`** (X.509 SHA-1 thumbprint): Silently ignored. SHA-1 is deprecated
//!   for cryptographic use (RFC 6151) and this field provides no additional
//!   security without certificate chain validation.
//!
//! - **`x5t#S256`** (X.509 SHA-256 thumbprint): Silently ignored at the JWK
//!   level. Note that `cnf.x5t#S256` in JWT access tokens is a distinct concept
//!   (RFC 8705 §4) handled separately by the resource server validator.

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

/// A JSON Web Key Set (RFC 7517 §5).
#[non_exhaustive]
#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct PublicJwks {
    /// List of keys
    pub keys: Vec<PublicJwk>,
}

impl PublicJwks {
    /// Creates a new `PublicJwks` from the given keys.
    #[must_use]
    pub fn new(keys: Vec<PublicJwk>) -> Self {
        Self { keys }
    }
}

/// A JSON Web Key (RFC 7517 §4).
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct PublicJwk {
    /// The key details.
    #[builder(into)]
    #[serde(flatten)]
    pub key: PublicKey,
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
    /// Captured to enable rejection when present in JWKs from untrusted sources
    /// (e.g. `DPoP` proof headers). See the [module-level documentation](self) for
    /// the full rationale. Never serialized by this library.
    #[builder(skip)]
    #[serde(rename = "x5u", default, skip_serializing)]
    pub x5u: Option<String>,
}

impl PublicJwk {
    /// Returns the JWK thumbprint (RFC 7638) for the key.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let canonical_form = match &self.key {
            PublicKey::Rsa(rsa) => rsa.canonical_form(),
            PublicKey::Ec(ec) => ec.canonical_form(),
            PublicKey::Okp(okp) => okp.canonical_form(),
        };
        let mut hasher = Sha256::new();
        hasher.update(canonical_form.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }
}

/// Key use parameter (RFC 7517 §4.2).
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum KeyUse {
    /// Digital signature or MAC.
    #[serde(rename = "sig")]
    Sign,
    /// Encryption.
    #[serde(rename = "enc")]
    Encrypt,
    /// Unknown key use value. Any unrecognized `use` value deserializes here;
    /// it is never serialized.
    #[serde(skip_serializing, other)]
    Unknown,
}

/// Key operations parameter (RFC 7517 §4.3).
#[non_exhaustive]
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
    /// Unknown key operation. Any unrecognized `key_ops` value deserializes
    /// here; it is never serialized.
    #[serde(skip_serializing, other)]
    Unknown,
}

/// The parts of a public key that vary structurally between types (RFC 7517 §4).
///
/// The list of values for `kty` come from
/// <https://www.iana.org/assignments/jose/jose.xhtml#web-key-types>.
/// It doesn't include `AKP` which is an RFC draft at this time.
#[non_exhaustive]
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
}

/// An RSA public key.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
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
        let e = URL_SAFE_NO_PAD.encode(trim_leading_zeros(&self.e));
        let n = URL_SAFE_NO_PAD.encode(trim_leading_zeros(&self.n));

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
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
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
        let crv = serde_json::to_string(&self.crv).unwrap();
        let x = URL_SAFE_NO_PAD.encode(&self.x);
        let y = URL_SAFE_NO_PAD.encode(&self.y);

        format!(r#"{{"crv":{crv},"kty":"EC","x":"{x}","y":"{y}"}}"#)
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
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
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
        let crv = serde_json::to_string(&self.crv).unwrap();
        let x = URL_SAFE_NO_PAD.encode(&self.x);

        format!(r#"{{"crv":{crv},"kty":"OKP","x":"{x}"}}"#)
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

// ---------------------------------------------------------------------------
// Private-key JWK types
// ---------------------------------------------------------------------------

/// Additional prime factor info for multi-prime RSA keys (RFC 7518 §6.3.2.7).
///
/// Each entry represents a prime factor beyond `p` and `q`.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Builder, PartialEq, Clone)]
pub struct OtherPrimeInfo {
    /// The additional prime factor.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url_uint")]
    pub r: Vec<u8>,
    /// The CRT exponent for this prime factor.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url_uint")]
    pub d: Vec<u8>,
    /// The CRT coefficient for this prime factor.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url_uint")]
    pub t: Vec<u8>,
}

impl std::fmt::Debug for OtherPrimeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtherPrimeInfo").finish_non_exhaustive()
    }
}

impl Zeroize for OtherPrimeInfo {
    fn zeroize(&mut self) {
        self.r.zeroize();
        self.d.zeroize();
        self.t.zeroize();
    }
}

impl Drop for OtherPrimeInfo {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An RSA private key (RFC 7518 §6.3).
///
/// Composes [`RsaPublicKey`] with the private exponent and optional CRT parameters.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct RsaKey {
    /// The public key components.
    #[serde(flatten)]
    #[builder(into)]
    pub public: RsaPublicKey,
    /// The private exponent.
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,
    /// First prime factor (CRT parameter, RFC 7518 §6.3.2).
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub p: Option<Vec<u8>>,
    /// Second prime factor (CRT parameter).
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub q: Option<Vec<u8>>,
    /// First factor CRT exponent.
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dp: Option<Vec<u8>>,
    /// Second factor CRT exponent.
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dq: Option<Vec<u8>>,
    /// First CRT coefficient.
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub qi: Option<Vec<u8>>,
    /// Additional prime factors for multi-prime RSA (RFC 7518 §6.3.2.7).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub oth: Option<Vec<OtherPrimeInfo>>,
}

impl std::fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for RsaKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qi.zeroize();
        if let Some(oth) = &mut self.oth {
            for info in oth.iter_mut() {
                info.zeroize();
            }
        }
    }
}

impl Drop for RsaKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<RsaKey> for RsaPublicKey {
    fn from(mut key: RsaKey) -> Self {
        std::mem::replace(
            &mut key.public,
            RsaPublicKey {
                n: vec![],
                e: vec![],
            },
        )
    }
}

impl From<RsaKey> for Key {
    fn from(value: RsaKey) -> Self {
        Self::Rsa(value)
    }
}

impl<S: rsa_key_builder::State> From<RsaKeyBuilder<S>> for Key
where
    S: rsa_key_builder::IsComplete,
{
    fn from(value: RsaKeyBuilder<S>) -> Self {
        Self::Rsa(value.build())
    }
}

/// An Elliptic Curve private key (RFC 7518 §6.2).
///
/// Composes [`EcPublicKey`] with the private key parameter `d`.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct EcKey {
    /// The public key components.
    #[serde(flatten)]
    #[builder(into)]
    pub public: EcPublicKey,
    /// The private key value.
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,
}

impl std::fmt::Debug for EcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for EcKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

impl Drop for EcKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<EcKey> for EcPublicKey {
    fn from(mut key: EcKey) -> Self {
        std::mem::replace(
            &mut key.public,
            EcPublicKey {
                crv: String::new(),
                x: vec![],
                y: vec![],
            },
        )
    }
}

impl From<EcKey> for Key {
    fn from(value: EcKey) -> Self {
        Self::Ec(value)
    }
}

impl<S: ec_key_builder::State> From<EcKeyBuilder<S>> for Key
where
    S: ec_key_builder::IsComplete,
{
    fn from(value: EcKeyBuilder<S>) -> Self {
        Self::Ec(value.build())
    }
}

/// An Octet Key Pair private key (RFC 8037 §2).
///
/// Composes [`OkpPublicKey`] with the private key parameter `d`.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct OkpKey {
    /// The public key components.
    #[serde(flatten)]
    #[builder(into)]
    pub public: OkpPublicKey,
    /// The private key value.
    #[builder(with = <_>::from_iter)]
    #[serde(
        with = "option_base64url",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,
}

impl std::fmt::Debug for OkpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OkpKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for OkpKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

impl Drop for OkpKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<OkpKey> for OkpPublicKey {
    fn from(mut key: OkpKey) -> Self {
        std::mem::replace(
            &mut key.public,
            OkpPublicKey {
                crv: String::new(),
                x: vec![],
            },
        )
    }
}

impl From<OkpKey> for Key {
    fn from(value: OkpKey) -> Self {
        Self::Okp(value)
    }
}

impl<S: okp_key_builder::State> From<OkpKeyBuilder<S>> for Key
where
    S: okp_key_builder::IsComplete,
{
    fn from(value: OkpKeyBuilder<S>) -> Self {
        Self::Okp(value.build())
    }
}

/// A symmetric octet sequence key (RFC 7518 §6.4).
///
/// Used for HMAC signing and symmetric encryption (e.g., `A128KW`).
/// Has no public key equivalent — purely secret material.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Builder, PartialEq, Clone)]
#[builder(derive(Into))]
pub struct OctKey {
    /// The key value.
    #[builder(with = <_>::from_iter)]
    #[serde(with = "base64url")]
    pub k: Vec<u8>,
}

impl std::fmt::Debug for OctKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OctKey").finish_non_exhaustive()
    }
}

impl Zeroize for OctKey {
    fn zeroize(&mut self) {
        self.k.zeroize();
    }
}

impl Drop for OctKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<OctKey> for Key {
    fn from(value: OctKey) -> Self {
        Self::Oct(value)
    }
}

impl<S: oct_key_builder::State> From<OctKeyBuilder<S>> for Key
where
    S: oct_key_builder::IsComplete,
{
    fn from(value: OctKeyBuilder<S>) -> Self {
        Self::Oct(value.build())
    }
}

/// A JSON Web Key with private key material (RFC 7517/7518).
///
/// Superset of [`PublicKey`] — includes all asymmetric key types plus symmetric
/// (`oct`) keys.
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(tag = "kty")]
pub enum Key {
    /// An RSA private key.
    #[serde(rename = "RSA")]
    Rsa(RsaKey),
    /// An Elliptic Curve private key.
    #[serde(rename = "EC")]
    Ec(EcKey),
    /// An Octet Key Pair private key.
    #[serde(rename = "OKP")]
    Okp(OkpKey),
    /// A symmetric octet sequence key.
    #[serde(rename = "oct")]
    Oct(OctKey),
    /// Unknown key type.
    #[serde(skip_serializing, other)]
    Unknown,
}

impl Key {
    /// Returns the public key if this is an asymmetric key, or `None` for
    /// symmetric (`Oct`) or unknown keys.
    #[must_use]
    pub fn public_key(&self) -> Option<PublicKey> {
        match self {
            Key::Rsa(rsa) => Some(PublicKey::Rsa(rsa.public.clone())),
            Key::Ec(ec) => Some(PublicKey::Ec(ec.public.clone())),
            Key::Okp(okp) => Some(PublicKey::Okp(okp.public.clone())),
            Key::Oct(_) | Key::Unknown => None,
        }
    }

    /// Returns a validated [`PrivateKey`] if this is an asymmetric key with
    /// private material present, or `None` for public-only, symmetric (`Oct`),
    /// or unknown keys.
    #[must_use]
    pub fn private_key(&self) -> Option<PrivateKey> {
        match self {
            Key::Rsa(rsa) => rsa.private_key().map(PrivateKey::Rsa),
            Key::Ec(ec) => ec.private_key().map(PrivateKey::Ec),
            Key::Okp(okp) => okp.private_key().map(PrivateKey::Okp),
            Key::Oct(_) | Key::Unknown => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Validated private-key types
// ---------------------------------------------------------------------------

/// An RSA private key with guaranteed private material.
///
/// Obtained via [`RsaKey::private_key()`]. The private exponent `d` is
/// guaranteed present; CRT parameters remain optional.
#[non_exhaustive]
#[derive(PartialEq, Clone)]
pub struct RsaPrivateKey {
    /// The public key components.
    pub public: RsaPublicKey,
    /// The private exponent (guaranteed present).
    pub d: Vec<u8>,
    /// First prime factor (CRT parameter, RFC 7518 §6.3.2).
    pub p: Option<Vec<u8>>,
    /// Second prime factor (CRT parameter).
    pub q: Option<Vec<u8>>,
    /// First factor CRT exponent.
    pub dp: Option<Vec<u8>>,
    /// Second factor CRT exponent.
    pub dq: Option<Vec<u8>>,
    /// First CRT coefficient.
    pub qi: Option<Vec<u8>>,
    /// Additional prime factors for multi-prime RSA (RFC 7518 §6.3.2.7).
    pub oth: Option<Vec<OtherPrimeInfo>>,
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for RsaPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qi.zeroize();
        if let Some(oth) = &mut self.oth {
            for info in oth.iter_mut() {
                info.zeroize();
            }
        }
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An EC private key with guaranteed private material.
///
/// Obtained via [`EcKey::private_key()`].
#[non_exhaustive]
#[derive(PartialEq, Clone)]
pub struct EcPrivateKey {
    /// The public key components.
    pub public: EcPublicKey,
    /// The private key value (guaranteed present).
    pub d: Vec<u8>,
}

impl std::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for EcPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

impl Drop for EcPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An OKP private key with guaranteed private material.
///
/// Obtained via [`OkpKey::private_key()`].
#[non_exhaustive]
#[derive(PartialEq, Clone)]
pub struct OkpPrivateKey {
    /// The public key components.
    pub public: OkpPublicKey,
    /// The private key value (guaranteed present).
    pub d: Vec<u8>,
}

impl std::fmt::Debug for OkpPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OkpPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for OkpPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

impl Drop for OkpPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A validated private key with guaranteed private material.
///
/// Obtained via [`Key::private_key()`] or [`Jwk::private_key()`]. Each variant
/// guarantees that the private exponent / key parameter `d` is present.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum PrivateKey {
    /// An RSA private key.
    Rsa(RsaPrivateKey),
    /// An Elliptic Curve private key.
    Ec(EcPrivateKey),
    /// An Octet Key Pair private key.
    Okp(OkpPrivateKey),
}

impl PrivateKey {
    /// Returns the public key, stripping all private material.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(rsa) => PublicKey::Rsa(rsa.public.clone()),
            PrivateKey::Ec(ec) => PublicKey::Ec(ec.public.clone()),
            PrivateKey::Okp(okp) => PublicKey::Okp(okp.public.clone()),
        }
    }
}

// --- From: variant → PrivateKey enum ---

impl From<RsaPrivateKey> for PrivateKey {
    fn from(value: RsaPrivateKey) -> Self {
        Self::Rsa(value)
    }
}

impl From<EcPrivateKey> for PrivateKey {
    fn from(value: EcPrivateKey) -> Self {
        Self::Ec(value)
    }
}

impl From<OkpPrivateKey> for PrivateKey {
    fn from(value: OkpPrivateKey) -> Self {
        Self::Okp(value)
    }
}

// --- From: private → serde type (infallible widening) ---

impl From<RsaPrivateKey> for RsaKey {
    fn from(mut key: RsaPrivateKey) -> Self {
        Self {
            public: std::mem::replace(
                &mut key.public,
                RsaPublicKey {
                    n: vec![],
                    e: vec![],
                },
            ),
            d: Some(std::mem::take(&mut key.d)),
            p: key.p.take(),
            q: key.q.take(),
            dp: key.dp.take(),
            dq: key.dq.take(),
            qi: key.qi.take(),
            oth: key.oth.take(),
        }
    }
}

impl From<EcPrivateKey> for EcKey {
    fn from(mut key: EcPrivateKey) -> Self {
        Self {
            public: std::mem::replace(
                &mut key.public,
                EcPublicKey {
                    crv: String::new(),
                    x: vec![],
                    y: vec![],
                },
            ),
            d: Some(std::mem::take(&mut key.d)),
        }
    }
}

impl From<OkpPrivateKey> for OkpKey {
    fn from(mut key: OkpPrivateKey) -> Self {
        Self {
            public: std::mem::replace(
                &mut key.public,
                OkpPublicKey {
                    crv: String::new(),
                    x: vec![],
                },
            ),
            d: Some(std::mem::take(&mut key.d)),
        }
    }
}

impl From<PrivateKey> for Key {
    fn from(value: PrivateKey) -> Self {
        match value {
            PrivateKey::Rsa(rsa) => Key::Rsa(rsa.into()),
            PrivateKey::Ec(ec) => Key::Ec(ec.into()),
            PrivateKey::Okp(okp) => Key::Okp(okp.into()),
        }
    }
}

// --- From: private → public (strip private material) ---

impl From<RsaPrivateKey> for RsaPublicKey {
    fn from(mut key: RsaPrivateKey) -> Self {
        std::mem::replace(
            &mut key.public,
            RsaPublicKey {
                n: vec![],
                e: vec![],
            },
        )
    }
}

impl From<EcPrivateKey> for EcPublicKey {
    fn from(mut key: EcPrivateKey) -> Self {
        std::mem::replace(
            &mut key.public,
            EcPublicKey {
                crv: String::new(),
                x: vec![],
                y: vec![],
            },
        )
    }
}

impl From<OkpPrivateKey> for OkpPublicKey {
    fn from(mut key: OkpPrivateKey) -> Self {
        std::mem::replace(
            &mut key.public,
            OkpPublicKey {
                crv: String::new(),
                x: vec![],
            },
        )
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        value.public_key()
    }
}

// --- private_key() methods on serde types ---

impl RsaKey {
    /// Returns a validated [`RsaPrivateKey`] if private material is present.
    #[must_use]
    pub fn private_key(&self) -> Option<RsaPrivateKey> {
        Some(RsaPrivateKey {
            public: self.public.clone(),
            d: self.d.clone()?,
            p: self.p.clone(),
            q: self.q.clone(),
            dp: self.dp.clone(),
            dq: self.dq.clone(),
            qi: self.qi.clone(),
            oth: self.oth.clone(),
        })
    }
}

impl EcKey {
    /// Returns a validated [`EcPrivateKey`] if private material is present.
    #[must_use]
    pub fn private_key(&self) -> Option<EcPrivateKey> {
        Some(EcPrivateKey {
            public: self.public.clone(),
            d: self.d.clone()?,
        })
    }
}

impl OkpKey {
    /// Returns a validated [`OkpPrivateKey`] if private material is present.
    #[must_use]
    pub fn private_key(&self) -> Option<OkpPrivateKey> {
        Some(OkpPrivateKey {
            public: self.public.clone(),
            d: self.d.clone()?,
        })
    }
}

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
    pub keys: Vec<Jwk>,
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
