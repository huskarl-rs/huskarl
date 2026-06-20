//! HMAC symmetric keys for JWS signing and verification.
//!
//! [`SymmetricKey`] is the HMAC key (HS256/384/512) implementing huskarl-core's
//! signer and verifier traits. Build one from a JWK with
//! [`SymmetricKey::from_jwk`] or [`SymmetricKey::load_jwk`], or from raw bytes
//! with [`SymmetricKey::load_bytes`].

use std::{borrow::Cow, sync::Arc};

use hmac::{Hmac, KeyInit as _, Mac as _};
use huskarl_core::{
    Error,
    crypto::{
        KeyMatchStrength,
        signer::{JwsSigner, JwsSignerSelector},
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    jwk,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes, SecretString},
};
use sha2::Digest as _;
use snafu::{ResultExt, Snafu, ensure};
use subtle::ConstantTimeEq as _;

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
    /// The minimum key size in bytes.
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
/// [`JwsSignerSelector`]. Build one with [`from_jwk`](Self::from_jwk),
/// [`load_jwk`](Self::load_jwk), or [`load_bytes`](Self::load_bytes); cheap to
/// clone (`Arc`-backed).
#[derive(Debug, Clone)]
pub struct SymmetricKey {
    inner: Arc<SymmetricKeyInner>,
}

/// An error that occurred while loading a symmetric key.
#[derive(Debug, Snafu)]
pub enum KeyLoadError {
    /// The provided key was shorter than the minimum required for the algorithm.
    InvalidKeySize {
        /// The size of the provided key.
        actual: usize,
        /// The minimum required key size.
        required: usize,
    },
    /// The secret could not be accessed.
    Secret {
        /// The underlying error.
        source: Error,
    },
}

/// Errors that may occur when constructing a symmetric key from JWK material.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum JwkError {
    /// The algorithm is unsupported or missing.
    #[snafu(display("Unsupported JWK algorithm: {algorithm:?}"))]
    UnsupportedAlgorithm {
        /// The algorithm field from the JWK, if present.
        algorithm: Option<String>,
    },
    /// The JWK key type is not `oct`.
    #[snafu(display("JWK key type is not oct"))]
    NotOctKey,
    /// The key size does not meet the minimum for the algorithm.
    #[snafu(display("Invalid key size: got {actual}, need at least {required}"))]
    InvalidKeySize {
        /// The size of the provided key.
        actual: usize,
        /// The required minimum key size.
        required: usize,
    },
}

/// Errors that may occur when loading a symmetric key from a JWK secret.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum JwkLoadError {
    /// Failed to access secret information.
    Secret {
        /// The underlying error.
        source: Error,
    },
    /// Failed to parse the JWK JSON.
    #[snafu(display("Failed to parse JWK JSON"))]
    JsonParse {
        /// The underlying error.
        source: serde_json::Error,
    },
    /// JWK processing error.
    Jwk {
        /// The underlying error.
        source: JwkError,
    },
}

impl SymmetricKey {
    /// Loads the bytes from a binary secret.
    ///
    /// # Errors
    ///
    /// The secret could not be accessed.
    pub async fn load_bytes<
        S: Secret<Output = SecretBytes>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        algorithm: SymmetricAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, KeyLoadError> {
        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let key_id = key_id_from_secret_identity(secret_output.identity.as_deref());
        let key = secret_output.value;

        let required_key_size = algorithm.min_key_size();

        ensure!(
            key.expose_secret().len() >= required_key_size,
            InvalidKeySizeSnafu {
                required: required_key_size,
                actual: key.expose_secret().len()
            }
        );

        Ok(Self {
            inner: Arc::new(SymmetricKeyInner {
                key,
                algorithm,
                key_id,
            }),
        })
    }

    /// Constructs a symmetric key from a [`jwk::Jwk`].
    ///
    /// The JWK must be of key type `oct` and have an `alg` field identifying
    /// the HMAC algorithm (HS256, HS384, or HS512). The `kid` field, if
    /// present, is used as the key ID.
    ///
    /// # Errors
    ///
    /// The JWK is not an `oct` key, is missing an algorithm, has an
    /// unsupported algorithm, or the key is too short for the algorithm.
    pub fn from_jwk(jwk: jwk::Jwk) -> Result<Self, JwkError> {
        let jwk::Key::Oct(oct) = jwk.key else {
            return jwk_error::NotOctKeySnafu.fail();
        };

        let alg = jwk.algorithm.as_deref();
        let Some(algorithm) = alg.and_then(|a| a.parse::<SymmetricAlgorithm>().ok()) else {
            return jwk_error::UnsupportedAlgorithmSnafu {
                algorithm: alg.map(String::from),
            }
            .fail();
        };

        let required_key_size = algorithm.min_key_size();

        ensure!(
            oct.k.len() >= required_key_size,
            jwk_error::InvalidKeySizeSnafu {
                required: required_key_size,
                actual: oct.k.len()
            }
        );

        Ok(Self {
            inner: Arc::new(SymmetricKeyInner {
                key: SecretBytes::new(oct.k.clone()),
                algorithm,
                key_id: jwk.kid,
            }),
        })
    }

    /// Loads a symmetric key from a JWK JSON secret.
    ///
    /// The secret value must be a JSON string representing a JWK of key type
    /// `oct`. The JWK's `alg` and `kid` fields are used directly.
    ///
    /// # Errors
    ///
    /// The secret could not be accessed, the JSON is invalid,
    /// or the JWK is not a valid symmetric key.
    pub async fn load_jwk<S: Secret<Output = SecretString>>(
        secret: S,
    ) -> Result<Self, JwkLoadError> {
        let secret_output = secret
            .get_secret_value()
            .await
            .context(jwk_load_error::SecretSnafu)?;
        let json = secret_output.value.expose_secret();
        let parsed: jwk::Jwk =
            serde_json::from_str(json).context(jwk_load_error::JsonParseSnafu)?;
        Self::from_jwk(parsed).context(jwk_load_error::JwkSnafu)
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
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        Arc::new(self.clone())
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
    use huskarl_core::crypto::{signer::JwsSigner, verifier::JwsVerifier};

    use super::*;

    async fn roundtrip_symmetric(algorithm: &str, key_size: usize) {
        let key_bytes: Vec<u8> = (0..=u8::MAX).cycle().take(key_size).collect();
        let jwk = huskarl_core::jwk::Jwk::builder()
            .key(huskarl_core::jwk::OctKey::builder().k(key_bytes).build())
            .algorithm(algorithm)
            .kid("sym-key-1")
            .build();

        let key = SymmetricKey::from_jwk(jwk).unwrap();

        let data = b"hello world";
        let signature = key.sign(data).await.unwrap();

        let key_match = KeyMatch {
            alg: algorithm,
            kid: Some("sym-key-1"),
        };
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
        let jwk_with_key = |alg: &str, len: usize| {
            huskarl_core::jwk::Jwk::builder()
                .key(
                    huskarl_core::jwk::OctKey::builder()
                        .k(vec![0u8; len])
                        .build(),
                )
                .algorithm(alg)
                .build()
        };

        for (alg, min) in [("HS256", 32), ("HS384", 48), ("HS512", 64)] {
            assert!(
                SymmetricKey::from_jwk(jwk_with_key(alg, min)).is_ok(),
                "{alg}: RFC-minimum {min}-byte key must be accepted"
            );
            let err = SymmetricKey::from_jwk(jwk_with_key(alg, min - 1)).unwrap_err();
            assert!(
                matches!(err, JwkError::InvalidKeySize { required, .. } if required == min),
                "{alg}: {}-byte key must be rejected with required={min}",
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
        let jwk = huskarl_core::jwk::Jwk::builder()
            .key(huskarl_core::jwk::OctKey::builder().k(key_bytes).build())
            .algorithm("HS256")
            .build();
        let key = SymmetricKey::from_jwk(jwk).unwrap();

        let input = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let expected = URL_SAFE_NO_PAD
            .decode("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .unwrap();

        assert_eq!(key.sign(input).await.unwrap(), expected);

        let key_match = KeyMatch {
            alg: "HS256",
            kid: None,
        };
        key.verify(input, &expected, &key_match).await.unwrap();
    }

    #[test]
    fn from_jwk_not_oct_key() {
        let jwk = huskarl_core::jwk::Jwk::builder()
            .key(huskarl_core::jwk::Key::Unknown)
            .algorithm("HS256")
            .build();

        let err = SymmetricKey::from_jwk(jwk).unwrap_err();
        assert!(matches!(err, JwkError::NotOctKey));
    }

    #[test]
    fn from_jwk_missing_algorithm() {
        let jwk = huskarl_core::jwk::Jwk::builder()
            .key(
                huskarl_core::jwk::OctKey::builder()
                    .k(vec![0u8; 32])
                    .build(),
            )
            .build();

        let err = SymmetricKey::from_jwk(jwk).unwrap_err();
        assert!(matches!(err, JwkError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn from_jwk_unsupported_algorithm() {
        let jwk = huskarl_core::jwk::Jwk::builder()
            .key(
                huskarl_core::jwk::OctKey::builder()
                    .k(vec![0u8; 32])
                    .build(),
            )
            .algorithm("A128KW")
            .build();

        let err = SymmetricKey::from_jwk(jwk).unwrap_err();
        assert!(matches!(err, JwkError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn from_jwk_undersized_key() {
        let jwk = huskarl_core::jwk::Jwk::builder()
            .key(
                huskarl_core::jwk::OctKey::builder()
                    .k(vec![0u8; 16])
                    .build(),
            )
            .algorithm("HS256")
            .build();

        let err = SymmetricKey::from_jwk(jwk).unwrap_err();
        assert!(matches!(err, JwkError::InvalidKeySize { .. }));
    }
}
