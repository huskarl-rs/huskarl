//! Decoding key-material secrets into a [`PrivateJwk`].

use snafu::prelude::*;

use crate::{
    error::Error,
    jwk::{Jwk, OctKey, ParsingJsonSnafu, PrivateJwk, SymmetricJwk},
    secrets::{SecretBytes, SecretMap, SecretString},
};

/// A [`SecretMap`] that parses a JWK-JSON secret into a [`PrivateJwk`].
///
/// A JWK is self-describing — it carries its own `alg` and `kid` — so, unlike
/// the PKCS#8 decoders, it needs no algorithm or key-id argument. Compose it
/// onto a string secret. It serves every key kind: asymmetric
/// private JWKs and symmetric (`oct`) JWKs alike. Compose it onto a string
/// secret, `secret.mapped(JwkJson)`, to reach a `Secret<Output = PrivateJwk>`
/// for any loading funnel. Being pure JSON with no key derivation, it is
/// backend-independent and lives in core.
#[derive(Debug, Clone, Copy, Default)]
pub struct JwkJson;

impl SecretMap for JwkJson {
    type In = SecretString;
    type Out = PrivateJwk;

    fn apply(&self, input: SecretString) -> Result<PrivateJwk, Error> {
        let jwk: Jwk = serde_json::from_str(input.expose_secret()).context(ParsingJsonSnafu)?;
        jwk.private_jwk()
            .ok_or_else(|| Error::from(crate::jwk::JwkError::NoSecretKeyMaterial))
    }
}

/// A [`SecretMap`] that wraps raw key bytes into a symmetric [`PrivateJwk`].
///
/// The raw-bytes counterpart of [`JwkJson`] for symmetric keys: an HMAC or AES
/// key held as bare bytes (an environment variable, a file, a secret-manager
/// payload) carries no metadata, so — like the PKCS#8 decoders on the
/// asymmetric side — this decoder takes the algorithm out of band and stamps
/// it onto a self-describing `oct` JWK that any symmetric loading funnel can
/// finalize. Compose it onto a byte secret:
/// `secret.mapped(OctBytes::new("HS256"))`.
///
/// Raw bytes carry no key ID either; [`with_kid`](Self::with_kid) stamps one
/// onto the produced JWK. Without it, the funnels fall back to the secret
/// source's identity.
#[derive(Debug, Clone)]
pub struct OctBytes {
    algorithm: String,
    kid: Option<String>,
}

impl OctBytes {
    /// Decodes raw key bytes as an `oct` key for the given JWA algorithm
    /// (e.g. `HS256`, `A256GCM`), with no key ID.
    #[must_use]
    pub fn new(algorithm: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            kid: None,
        }
    }

    /// Stamps `kid` onto the produced JWK.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

impl SecretMap for OctBytes {
    type In = SecretBytes;
    type Out = PrivateJwk;

    fn apply(&self, input: SecretBytes) -> Result<PrivateJwk, Error> {
        Ok(PrivateJwk::Symmetric(
            SymmetricJwk::builder()
                .key(
                    OctKey::builder()
                        .k(input.expose_secret().iter().copied())
                        .build(),
                )
                .algorithm(self.algorithm.clone())
                .maybe_kid(self.kid.clone())
                .build(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{ProvidedSecret, Secret as _};

    // A minimal P-256 private JWK (RFC 7517 Appendix A.2), with alg + kid.
    const PRIVATE_JWK: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": "in-the-jwk",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
    }"#;

    #[tokio::test]
    async fn parses_a_private_jwk_and_keeps_its_kid_and_alg() {
        let jwk = ProvidedSecret::new(SecretString::new(PRIVATE_JWK))
            .mapped(JwkJson)
            .get_secret_value()
            .await
            .unwrap()
            .value;
        assert_eq!(jwk.kid(), Some("in-the-jwk"));
        let PrivateJwk::Asymmetric(jwk) = jwk else {
            panic!("an EC private JWK must parse as the Asymmetric variant");
        };
        assert_eq!(jwk.algorithm.as_deref(), Some("ES256"));
    }

    #[test]
    fn parses_an_oct_jwk_as_symmetric() {
        let oct = r#"{"kty":"oct","alg":"HS256","kid":"sym-1",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
        let jwk = JwkJson.apply(SecretString::new(oct)).unwrap();
        let PrivateJwk::Symmetric(jwk) = jwk else {
            panic!("an oct JWK must parse as the Symmetric variant");
        };
        assert_eq!(jwk.algorithm.as_deref(), Some("HS256"));
        assert_eq!(jwk.kid.as_deref(), Some("sym-1"));
        assert_eq!(jwk.key.k.len(), 64);
    }

    #[test]
    fn rejects_json_without_private_material() {
        // A public-only JWK (no `d`) has no secret key to load.
        let public_only = r#"{"kty":"EC","crv":"P-256","alg":"ES256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
        let _err = JwkJson.apply(SecretString::new(public_only)).unwrap_err();
    }

    #[test]
    fn rejects_malformed_json() {
        let _err = JwkJson.apply(SecretString::new("not json")).unwrap_err();
    }

    #[test]
    fn oct_bytes_stamps_alg_and_kid() {
        let jwk = OctBytes::new("A256GCM")
            .with_kid("cookie-key")
            .apply(SecretBytes::new(vec![7u8; 32]))
            .unwrap();
        let PrivateJwk::Symmetric(jwk) = jwk else {
            panic!("OctBytes must produce the Symmetric variant");
        };
        assert_eq!(jwk.algorithm.as_deref(), Some("A256GCM"));
        assert_eq!(jwk.kid.as_deref(), Some("cookie-key"));
        assert_eq!(jwk.key.k, vec![7u8; 32]);
    }

    #[test]
    fn oct_bytes_without_kid_leaves_it_empty() {
        let jwk = OctBytes::new("HS256")
            .apply(SecretBytes::new(vec![1u8; 32]))
            .unwrap();
        assert_eq!(jwk.kid(), None);
    }
}
