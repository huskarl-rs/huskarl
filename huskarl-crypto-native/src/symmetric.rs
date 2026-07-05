//! HMAC symmetric keys for JWS signing and verification.
//!
//! [`SymmetricKey`] is the HMAC key (HS256/384/512) implementing huskarl-core's
//! signer and verifier traits. Build one from a JWK with
//! [`SymmetricKey::from_jwk`], or from a secret store with
//! [`SymmetricKey::from_secret`] — compose [`jwk::JwkJson`] onto a JWK-JSON
//! secret, or [`jwk::OctBytes`] onto raw key bytes.

use std::{borrow::Cow, sync::Arc};

use hmac::{Hmac, KeyInit as _, Mac as _};
use huskarl_core::{
    Error, ErrorKind,
    crypto::{
        KeyMatchStrength,
        signer::{JwsSigner, JwsSignerSelector},
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    jwk,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes},
};
use sha2::Digest as _;

/// Encodes which algorithm is used by this key.
// `UPPERCASE` serialization yields the JWA names (`Hs256` -> `HS256`); `AsRefStr`
// gives the `AsRef<str>` impl and `EnumString` the `"HS256".parse()` direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::AsRefStr, strum::EnumString)]
#[strum(serialize_all = "UPPERCASE")]
pub enum SymmetricAlgorithm {
    /// HS256 algorithm
    Hs256,
    /// HS384 algorithm
    Hs384,
    /// HS512 algorithm
    Hs512,
}

impl SymmetricAlgorithm {
    /// The minimum key size in bytes (RFC 7518 §3.2: the hash output size).
    fn min_key_size(self) -> usize {
        match self {
            Self::Hs256 => sha2::Sha256::output_size(),
            Self::Hs384 => sha2::Sha384::output_size(),
            Self::Hs512 => sha2::Sha512::output_size(),
        }
    }
}

#[derive(Debug)]
struct SymmetricKeyInner {
    key: SecretBytes,
    algorithm: SymmetricAlgorithm,
    key_id: Option<String>,
}

/// An HMAC symmetric key (HS256/384/512), used to both sign and verify JWS.
///
/// Implements huskarl-core's [`JwsSigner`], [`JwsVerifier`], and
/// [`JwsSignerSelector`]. Build one with [`from_jwk`](Self::from_jwk) or
/// [`from_secret`](Self::from_secret); cheap to clone (`Arc`-backed).
#[derive(Debug, Clone)]
pub struct SymmetricKey {
    inner: Arc<SymmetricKeyInner>,
}

impl SymmetricKey {
    /// Constructs a symmetric key from a [`jwk::SymmetricJwk`].
    ///
    /// The JWK must have an `alg` field identifying the HMAC algorithm (HS256,
    /// HS384, or HS512) — a bare oct key cannot self-identify, unlike an AES
    /// key whose length picks the variant. The `kid` field, if present, is
    /// used as the key ID. Holding a [`jwk::PrivateJwk`], convert with
    /// `try_into()` — the conversion rejects asymmetric keys.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the JWK is missing its algorithm, uses
    /// an unsupported one, or the key is shorter than the RFC 7518 §3.2
    /// minimum for the algorithm (the hash output size).
    ///
    /// # Examples
    ///
    /// When the key comes from a secret store, prefer
    /// [`from_secret`](Self::from_secret), which fetches and decodes in one
    /// step. Use `from_jwk` when you already hold a parsed JWK — for example
    /// one selected from a JWKS — rather than hard-coding key material:
    ///
    /// ```
    /// use huskarl_core::jwk::SymmetricJwk;
    /// use huskarl_crypto_native::symmetric::SymmetricKey;
    ///
    /// # fn example(jwk: SymmetricJwk) -> Result<(), Box<dyn std::error::Error>> {
    /// // `jwk` was parsed from a trusted source, not baked into the binary.
    /// let key = SymmetricKey::from_jwk(jwk)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_jwk(jwk: jwk::SymmetricJwk) -> Result<Self, Error> {
        let alg = jwk.algorithm.as_deref();
        let Some(algorithm) = alg.and_then(|a| a.parse::<SymmetricAlgorithm>().ok()) else {
            return Err(Error::from(ErrorKind::Config).with_context(format!(
                "unsupported or missing JWK algorithm for an HMAC key: {alg:?}"
            )));
        };

        let required_key_size = algorithm.min_key_size();
        let actual = jwk.key.k.len();
        if actual < required_key_size {
            return Err(Error::from(ErrorKind::Config).with_context(format!(
                "invalid {} key size: got {actual} bytes, need at least {required_key_size}",
                algorithm.as_ref()
            )));
        }

        Ok(Self {
            inner: Arc::new(SymmetricKeyInner {
                key: SecretBytes::new(jwk.key.k.clone()),
                algorithm,
                key_id: jwk.kid,
            }),
        })
    }

    /// Finalizes a symmetric key from a secret that yields a
    /// [`jwk::PrivateJwk`].
    ///
    /// The single loading funnel, shared with the asymmetric side: compose a
    /// decoder onto your secret to reach a `Secret<Output = PrivateJwk>` —
    /// [`jwk::JwkJson`] for a JWK-JSON secret, or
    /// [`jwk::OctBytes`] for raw key bytes — and this resolves it into a
    /// usable key.
    ///
    /// The key ID follows a clear precedence: an explicit `kid` in the JWK
    /// wins; otherwise the secret's `identity` (e.g. a secret-manager version
    /// name) fills it; otherwise there is none.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the secret cannot be fetched or
    /// decoded, if the JWK is asymmetric rather than symmetric (`oct`), or if
    /// it is not a valid HMAC key.
    pub async fn from_secret<S: Secret<Output = jwk::PrivateJwk>>(
        secret: S,
    ) -> Result<Self, Error> {
        let output = secret.get_secret_value().await?;
        // Explicit JWK kid > secret identity > none.
        let jwk = output.value.with_kid_fallback(output.identity);
        Self::from_jwk(jwk.try_into()?)
    }

    // `Hmac::new_from_slice` accepts a key of any length, so it never errors.
    #[allow(clippy::expect_used)]
    fn hmac(&self, input: &[u8]) -> Vec<u8> {
        let key_bytes = self.inner.key.expose_secret();

        match self.inner.algorithm {
            SymmetricAlgorithm::Hs256 => {
                let mut key: Hmac<sha2::Sha256> = Hmac::new_from_slice(key_bytes)
                    .expect("Key length checked at construction time");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            SymmetricAlgorithm::Hs384 => {
                let mut key: Hmac<sha2::Sha384> = Hmac::new_from_slice(key_bytes)
                    .expect("Key length checked at construction time");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            SymmetricAlgorithm::Hs512 => {
                let mut key: Hmac<sha2::Sha512> = Hmac::new_from_slice(key_bytes)
                    .expect("Key length checked at construction time");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
        }
    }
}

impl JwsSignerSelector for SymmetricKey {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let signer: Arc<dyn JwsSigner> = Arc::new(self.clone());
        Box::pin(async move { signer })
    }
}

impl JwsSigner for SymmetricKey {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.inner.algorithm.as_ref())
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.key_id.as_deref().map(Cow::Borrowed)
    }

    fn sign<'a>(&'a self, input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move { Ok(self.hmac(input)) })
    }
}

impl JwsVerifier for SymmetricKey {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        key_match.strength_for(
            &[self.inner.algorithm.as_ref()],
            self.inner.key_id.as_deref(),
        )
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        use subtle::ConstantTimeEq as _;

        Box::pin(async move {
            if self.key_match(key_match).is_none() {
                return Err(VerifyError::NoMatchingKey);
            }

            let hashed_input = self.hmac(input);

            if hashed_input.ct_ne(signature).into() {
                return Err(VerifyError::SignatureMismatch);
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use huskarl_core::{
        crypto::{signer::JwsSigner, verifier::JwsVerifier},
        jwk::OctBytes,
        secrets::{ProvidedSecret, SecretString},
    };

    use super::*;

    fn symmetric_jwk(algorithm: &str, key_bytes: Vec<u8>) -> jwk::SymmetricJwk {
        jwk::SymmetricJwk::builder()
            .key(jwk::OctKey::builder().k(key_bytes).build())
            .algorithm(algorithm)
            .build()
    }

    async fn roundtrip_symmetric(algorithm: &str, key_size: usize) {
        let key_bytes: Vec<u8> = (0..=u8::MAX).cycle().take(key_size).collect();
        let mut jwk = symmetric_jwk(algorithm, key_bytes);
        jwk.kid = Some("sym-key-1".into());

        let key = SymmetricKey::from_jwk(jwk).unwrap();

        let data = b"hello world";
        let signature = key.sign(data).await.unwrap();

        let key_match = KeyMatch::builder().alg(algorithm).kid("sym-key-1").build();
        key.verify(data, &signature, &key_match).await.unwrap();
    }

    // The RFC 7518 §3.2 minimum key size for each algorithm — keys of exactly
    // the hash output size must be accepted (they're typical for
    // client-secret-derived keys).
    #[tokio::test]
    async fn from_jwk_hs256() {
        roundtrip_symmetric("HS256", 32).await;
    }

    #[tokio::test]
    async fn from_jwk_hs384() {
        roundtrip_symmetric("HS384", 48).await;
    }

    #[tokio::test]
    async fn from_jwk_hs512() {
        roundtrip_symmetric("HS512", 64).await;
    }

    #[tokio::test]
    async fn from_jwk_oversized_keys() {
        roundtrip_symmetric("HS256", 64).await;
        roundtrip_symmetric("HS384", 128).await;
        roundtrip_symmetric("HS512", 128).await;
    }

    #[test]
    fn symmetric_algorithm_str_roundtrip() {
        for (alg, name) in [
            (SymmetricAlgorithm::Hs256, "HS256"),
            (SymmetricAlgorithm::Hs384, "HS384"),
            (SymmetricAlgorithm::Hs512, "HS512"),
        ] {
            assert_eq!(alg.as_ref(), name);
            assert_eq!(name.parse::<SymmetricAlgorithm>().unwrap(), alg);
        }
        // Unknown and wrong-case algorithms are rejected (parse is case-sensitive).
        assert!("HS999".parse::<SymmetricAlgorithm>().is_err());
        assert!("hs256".parse::<SymmetricAlgorithm>().is_err());
    }

    #[test]
    fn from_jwk_key_size_boundaries() {
        for (alg, min) in [("HS256", 32), ("HS384", 48), ("HS512", 64)] {
            assert!(
                SymmetricKey::from_jwk(symmetric_jwk(alg, vec![0u8; min])).is_ok(),
                "{alg}: RFC-minimum {min}-byte key must be accepted"
            );
            let err = SymmetricKey::from_jwk(symmetric_jwk(alg, vec![0u8; min - 1])).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Config,
                "{alg}: {}-byte key must be rejected",
                min - 1
            );
        }
    }

    /// RFC 7515 Appendix A.1 — HS256 known-answer vector.
    #[tokio::test]
    async fn hs256_rfc7515_a1_vector() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let key_bytes = URL_SAFE_NO_PAD
            .decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
            .unwrap();
        let key = SymmetricKey::from_jwk(symmetric_jwk("HS256", key_bytes)).unwrap();

        let input = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let expected = URL_SAFE_NO_PAD
            .decode("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .unwrap();

        assert_eq!(key.sign(input).await.unwrap(), expected);

        let key_match = KeyMatch::builder().alg("HS256").build();
        key.verify(input, &expected, &key_match).await.unwrap();
    }

    #[tokio::test]
    async fn from_secret_jwk_json() {
        // The blessed path: a JWK-JSON secret through the shared funnel.
        let json = r#"{"kty":"oct","alg":"HS256","kid":"sym-1",
            "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
        let key = SymmetricKey::from_secret(
            ProvidedSecret::new(SecretString::new(json)).mapped(jwk::JwkJson),
        )
        .await
        .unwrap();
        assert_eq!(key.key_id().as_deref(), Some("sym-1"));
        assert_eq!(key.jws_algorithm().as_ref(), "HS256");
    }

    #[tokio::test]
    async fn from_secret_raw_bytes() {
        // Raw bytes reach the same funnel through the OctBytes decoder.
        let key = SymmetricKey::from_secret(
            ProvidedSecret::new(SecretBytes::new(vec![9u8; 32]))
                .mapped(OctBytes::new("HS256").with_kid("env-key")),
        )
        .await
        .unwrap();
        assert_eq!(key.key_id().as_deref(), Some("env-key"));
    }

    #[tokio::test]
    async fn from_secret_rejects_asymmetric_jwk() {
        // A P-256 private JWK is valid for the funnel type but not for HMAC.
        let json = r#"{"kty":"EC","crv":"P-256","alg":"ES256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
        let err = SymmetricKey::from_secret(
            ProvidedSecret::new(SecretString::new(json)).mapped(jwk::JwkJson),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    #[test]
    fn from_jwk_missing_algorithm() {
        let jwk = jwk::SymmetricJwk::builder()
            .key(jwk::OctKey::builder().k(vec![0u8; 32]).build())
            .build();

        let err = SymmetricKey::from_jwk(jwk).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    #[test]
    fn from_jwk_unsupported_algorithm() {
        // A valid JWA algorithm, but not an HMAC one.
        let err = SymmetricKey::from_jwk(symmetric_jwk("A128KW", vec![0u8; 32])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    #[test]
    fn oct_jwk_from_wire_yields_symmetric_variant() {
        // The Jwk -> PrivateJwk -> SymmetricJwk path a JWKS consumer takes.
        let jwk = huskarl_core::jwk::Jwk::builder()
            .key(jwk::OctKey::builder().k(vec![1u8; 32]).build())
            .algorithm("HS256")
            .kid("from-set")
            .build();
        let private: jwk::SymmetricJwk = jwk.private_jwk().unwrap().try_into().unwrap();
        let key = SymmetricKey::from_jwk(private).unwrap();
        assert_eq!(key.key_id().as_deref(), Some("from-set"));
    }
}
