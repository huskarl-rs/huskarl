//! Decoding a JWK-JSON secret into a [`PrivateJwk`].

use crate::{
    error::{Error, ErrorKind},
    jwk::{Jwk, PrivateJwk},
    secrets::{SecretMap, SecretString},
};

/// A [`SecretMap`] that parses a JWK-JSON secret into a [`PrivateJwk`].
///
/// A JWK is self-describing — it carries its own `alg` and `kid` — so, unlike
/// the PKCS#8 decoders, it needs no algorithm or key-id argument. Compose it
/// onto a string secret,
/// `secret.mapped(JwkJson)`, to reach a `Secret<Output = PrivateJwk>` for the
/// private-key loading funnel. Being pure JSON with no key derivation, it is
/// backend-independent and lives in core.
#[derive(Debug, Clone, Copy, Default)]
pub struct JwkJson;

impl SecretMap for JwkJson {
    type In = SecretString;
    type Out = PrivateJwk;

    fn apply(&self, input: SecretString) -> Result<PrivateJwk, Error> {
        let jwk: Jwk = serde_json::from_str(input.expose_secret()).map_err(|source| {
            Error::new(ErrorKind::Config, source).with_context("parsing JWK JSON")
        })?;
        jwk.private_jwk().ok_or_else(|| {
            Error::from(ErrorKind::Config).with_context("JWK JSON contains no private key material")
        })
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
        assert_eq!(jwk.kid.as_deref(), Some("in-the-jwk"));
        assert_eq!(jwk.algorithm.as_deref(), Some("ES256"));
    }

    #[test]
    fn rejects_json_without_private_material() {
        // A public-only JWK (no `d`) has no private key to load.
        let public_only = r#"{"kty":"EC","crv":"P-256","alg":"ES256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
        let err = JwkJson.apply(SecretString::new(public_only)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    #[test]
    fn rejects_malformed_json() {
        let err = JwkJson.apply(SecretString::new("not json")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }
}
