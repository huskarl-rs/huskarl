//! Public JWK types — key material without private parameters.

use super::*;

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
    /// (e.g. `DPoP` proof headers). See the [module-level documentation](super) for
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
        // Serializing a field-less enum to a JSON string is infallible.
        #[allow(clippy::unwrap_used)]
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
        // Serializing a field-less enum to a JSON string is infallible.
        #[allow(clippy::unwrap_used)]
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
