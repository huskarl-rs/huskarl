//! JWK wire-format key types, including optional private parameters (RFC 7518).

use super::*;

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
