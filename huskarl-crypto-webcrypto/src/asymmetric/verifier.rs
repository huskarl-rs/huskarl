//! JWS verification with asymmetric public keys via the WebCrypto/SubtleCrypto
//! API, backing huskarl-core's [`JwsVerifier`] trait.
//!
//! [`AsymmetricPublicKey`] is the entry type; build one with
//! [`AsymmetricPublicKey::from_jwk`] (async, as key import goes through
//! `SubtleCrypto`).

use std::sync::Arc;

use huskarl_core::{
    Error, ErrorKind,
    crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    jwk::{self, KeyOperation, KeyUse},
    platform::MaybeSendBoxFuture,
};
use snafu::prelude::*;
use web_sys::{Crypto, CryptoKey};

use crate::{
    KeyUsage,
    helpers::{
        GetCryptoError, ImportParams, JsVerifyError, SignAlgorithm, get_crypto, import_key,
        verify_with_key,
    },
};

/// An asymmetric public key for JWS verification (ES256/384, RS/PS 256/384/512,
/// Ed25519) via the `WebCrypto` `SubtleCrypto` API, implementing [`JwsVerifier`].
///
/// Build one with [`from_jwk`](Self::from_jwk); cheap to clone (`Arc`-backed).
#[derive(Debug, Clone)]
pub struct AsymmetricPublicKey {
    inner: Arc<AsymmetricPublicKeyInner>,
}

impl AsymmetricPublicKey {
    /// Creates an asymmetric public key from a public JWK, importing it through
    /// `SubtleCrypto` (hence `async`).
    ///
    /// Returns `None` if the JWK cannot be used for verification: its `use` is
    /// not `sig`, its `key_ops` excludes `verify`, the algorithm is unsupported,
    /// or the key material cannot be imported.
    #[must_use]
    pub async fn from_jwk(key: jwk::PublicJwk) -> Option<Self> {
        let kid = key.kid.clone();

        if let Some(r#use) = key.key_use
            && r#use != KeyUse::Sign
        {
            return None;
        }

        if let Some(key_ops) = &key.key_operations
            && !key_ops.contains(&KeyOperation::Verify)
        {
            return None;
        }

        let verifying_key = Key::new(key).await;

        verifying_key.map(|k| Self {
            inner: Arc::new(AsymmetricPublicKeyInner {
                verifying_key: k,
                kid,
            }),
        })
    }
}

#[derive(Debug)]
struct AsymmetricPublicKeyInner {
    verifying_key: Key,
    kid: Option<String>,
}

#[derive(Debug)]
enum Key {
    Es256(CryptoKey),
    Es384(CryptoKey),
    Rsa {
        /// RS256 key
        rs256: CryptoKey,
        /// RS384 key
        rs384: CryptoKey,
        /// RS512 key
        rs512: CryptoKey,
        /// PS256 key
        ps256: CryptoKey,
        /// PS384 key
        ps384: CryptoKey,
        /// PS512 key
        ps512: CryptoKey,
    },
    Rs256(CryptoKey),
    Rs384(CryptoKey),
    Rs512(CryptoKey),
    Ps256(CryptoKey),
    Ps384(CryptoKey),
    Ps512(CryptoKey),
    Ed25519(CryptoKey),
}

/// Bit length of a big-endian modulus, sans bignum dep (native uses `crypto-bigint`).
fn rsa_modulus_bits(n: &[u8]) -> u32 {
    match n.iter().position(|&b| b != 0) {
        None => 0,
        // Saturate: a modulus too long to fit u32 bytes is far past MAX_RSA_BITS anyway.
        Some(i) => {
            u32::try_from(n.len() - i)
                .unwrap_or(u32::MAX)
                .saturating_mul(8)
                - n[i].leading_zeros()
        }
    }
}

/// Min: RFC 7518 §3.3 floor. Max: `DoS` guard on attacker-supplied JWKs (importKey enforces neither).
fn rsa_modulus_in_range(rsa_key: &jwk::RsaPublicKey) -> bool {
    const MIN_RSA_BITS: u32 = 2048;
    const MAX_RSA_BITS: u32 = 8192;
    (MIN_RSA_BITS..=MAX_RSA_BITS).contains(&rsa_modulus_bits(&rsa_key.n))
}

async fn create_rsa_key(
    crypto: &Crypto,
    alg_name: &str,
    hash: &str,
    jwk_key: &jwk::PublicJwk,
) -> Option<CryptoKey> {
    import_key(
        &crypto.subtle(),
        jwk_key,
        ImportParams::RsaHashed {
            name: alg_name,
            hash,
        },
        &[KeyUsage::Verify],
    )
    .await
    .ok()
}

async fn create_ec_key(
    crypto: &Crypto,
    named_curve: &str,
    jwk_key: &jwk::PublicJwk,
) -> Option<CryptoKey> {
    import_key(
        &crypto.subtle(),
        jwk_key,
        ImportParams::Ec {
            name: "ECDSA",
            named_curve,
        },
        &[KeyUsage::Verify],
    )
    .await
    .ok()
}

/// Union of [`Key::supported_algorithms`] across all variants.
pub(crate) const SUPPORTED_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "Ed25519", "EdDSA",
];

impl Key {
    fn supported_algorithms(&self) -> &[&str] {
        match self {
            Key::Es256(..) => &["ES256"],
            Key::Es384(..) => &["ES384"],
            Key::Rsa { .. } => &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
            Key::Rs256(..) => &["RS256"],
            Key::Rs384(..) => &["RS384"],
            Key::Rs512(..) => &["RS512"],
            Key::Ps256(..) => &["PS256"],
            Key::Ps384(..) => &["PS384"],
            Key::Ps512(..) => &["PS512"],
            Key::Ed25519(..) => &["Ed25519", "EdDSA"],
        }
    }

    async fn new(jwk: jwk::PublicJwk) -> Option<Key> {
        let crypto = get_crypto().ok()?;

        match &jwk.key {
            jwk::PublicKey::Ec(ec_public_key)
                if jwk.algorithm.as_ref().is_none_or(|a| a == "ES256")
                    && ec_public_key.crv == "P-256" =>
            {
                Some(Key::Es256(create_ec_key(&crypto, "P-256", &jwk).await?))
            }
            jwk::PublicKey::Ec(ec_public_key)
                if jwk.algorithm.as_ref().is_none_or(|a| a == "ES384")
                    && ec_public_key.crv == "P-384" =>
            {
                Some(Key::Es384(create_ec_key(&crypto, "P-384", &jwk).await?))
            }
            jwk::PublicKey::Rsa(rsa_key)
                if jwk.algorithm.is_none() && rsa_modulus_in_range(rsa_key) =>
            {
                Some(Key::Rsa {
                    rs256: create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-256", &jwk).await?,
                    rs384: create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-384", &jwk).await?,
                    rs512: create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-512", &jwk).await?,
                    ps256: create_rsa_key(&crypto, "RSA-PSS", "SHA-256", &jwk).await?,
                    ps384: create_rsa_key(&crypto, "RSA-PSS", "SHA-384", &jwk).await?,
                    ps512: create_rsa_key(&crypto, "RSA-PSS", "SHA-512", &jwk).await?,
                })
            }
            jwk::PublicKey::Rsa(rsa_key)
                if jwk.algorithm.as_ref().is_some_and(|alg| alg == "RS256")
                    && rsa_modulus_in_range(rsa_key) =>
            {
                Some(Key::Rs256(
                    create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-256", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(rsa_key)
                if jwk.algorithm.as_ref().is_some_and(|alg| alg == "RS384")
                    && rsa_modulus_in_range(rsa_key) =>
            {
                Some(Key::Rs384(
                    create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-384", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(rsa_key)
                if jwk.algorithm.as_ref().is_some_and(|alg| alg == "RS512")
                    && rsa_modulus_in_range(rsa_key) =>
            {
                Some(Key::Rs512(
                    create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-512", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(rsa_key)
                if jwk.algorithm.as_ref().is_some_and(|alg| alg == "PS256")
                    && rsa_modulus_in_range(rsa_key) =>
            {
                Some(Key::Ps256(
                    create_rsa_key(&crypto, "RSA-PSS", "SHA-256", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(rsa_key)
                if jwk.algorithm.as_ref().is_some_and(|alg| alg == "PS384")
                    && rsa_modulus_in_range(rsa_key) =>
            {
                Some(Key::Ps384(
                    create_rsa_key(&crypto, "RSA-PSS", "SHA-384", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(rsa_key)
                if jwk.algorithm.as_ref().is_some_and(|alg| alg == "PS512")
                    && rsa_modulus_in_range(rsa_key) =>
            {
                Some(Key::Ps512(
                    create_rsa_key(&crypto, "RSA-PSS", "SHA-512", &jwk).await?,
                ))
            }
            jwk::PublicKey::Okp(_)
                if jwk
                    .algorithm
                    .as_ref()
                    .is_none_or(|alg| alg == "EdDSA" || alg == "Ed25519") =>
            {
                Some(Key::Ed25519(
                    import_key(
                        &crypto.subtle(),
                        &jwk,
                        ImportParams::Ed25519,
                        &[KeyUsage::Verify],
                    )
                    .await
                    .ok()?,
                ))
            }
            _ => None,
        }
    }

    fn matching_key_and_alg(&self, alg: &str) -> Option<(SignAlgorithm<'static>, &CryptoKey)> {
        match self {
            Key::Es256(k) if alg == "ES256" => Some((
                SignAlgorithm::EcDsa {
                    name: "ECDSA",
                    hash: "SHA-256",
                },
                k,
            )),
            Key::Es384(k) if alg == "ES384" => Some((
                SignAlgorithm::EcDsa {
                    name: "ECDSA",
                    hash: "SHA-384",
                },
                k,
            )),
            Key::Rsa {
                rs256,
                rs384,
                rs512,
                ps256,
                ps384,
                ps512,
            } => match alg {
                "RS256" => Some((SignAlgorithm::RsaPkcs1, rs256)),
                "RS384" => Some((SignAlgorithm::RsaPkcs1, rs384)),
                "RS512" => Some((SignAlgorithm::RsaPkcs1, rs512)),
                "PS256" => Some((
                    SignAlgorithm::RsaPss {
                        name: "RSA-PSS",
                        salt_length: 32,
                    },
                    ps256,
                )),
                "PS384" => Some((
                    SignAlgorithm::RsaPss {
                        name: "RSA-PSS",
                        salt_length: 48,
                    },
                    ps384,
                )),
                "PS512" => Some((
                    SignAlgorithm::RsaPss {
                        name: "RSA-PSS",
                        salt_length: 64,
                    },
                    ps512,
                )),
                _ => None,
            },
            Key::Rs256(k) if alg == "RS256" => Some((SignAlgorithm::RsaPkcs1, k)),
            Key::Rs384(k) if alg == "RS384" => Some((SignAlgorithm::RsaPkcs1, k)),
            Key::Rs512(k) if alg == "RS512" => Some((SignAlgorithm::RsaPkcs1, k)),
            Key::Ps256(k) if alg == "PS256" => Some((
                SignAlgorithm::RsaPss {
                    name: "RSA-PSS",
                    salt_length: 32,
                },
                k,
            )),
            Key::Ps384(k) if alg == "PS384" => Some((
                SignAlgorithm::RsaPss {
                    name: "RSA-PSS",
                    salt_length: 48,
                },
                k,
            )),
            Key::Ps512(k) if alg == "PS512" => Some((
                SignAlgorithm::RsaPss {
                    name: "RSA-PSS",
                    salt_length: 64,
                },
                k,
            )),
            Key::Ed25519(k) if ["EdDSA", "Ed25519"].contains(&alg) => {
                Some((SignAlgorithm::Ed25519, k))
            }
            _ => None,
        }
    }
}

/// Errors that can occur when verifying.
#[derive(Debug, Snafu)]
pub enum AsymmetricPublicKeyError {
    /// Unable to find `WebCrypto` support in environment.
    #[snafu(display("Failed to find WebCrypto support"))]
    NoCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// Error occurred when attempting to verify.
    #[snafu(display("Verification failed"))]
    Verify {
        /// The underlying error.
        source: JsVerifyError,
    },
}

impl From<AsymmetricPublicKeyError> for Error {
    fn from(value: AsymmetricPublicKeyError) -> Self {
        Error::new(ErrorKind::Crypto, value)
    }
}

impl JwsVerifier for AsymmetricPublicKey {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        key_match.strength_for(
            self.inner.verifying_key.supported_algorithms(),
            self.inner.kid.as_deref(),
        )
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async move {
            // Same gate as the native backend: a kid mismatch is
            // NoMatchingKey (letting RetryingVerifier refresh on rotation),
            // never an attempted verification.
            if self.key_match(key_match).is_none() {
                return Err(VerifyError::NoMatchingKey);
            }

            let crypto = get_crypto().context(NoCryptoSnafu).map_err(Error::from)?;

            let Some((sign_alg, crypto_key)) =
                self.inner.verifying_key.matching_key_and_alg(key_match.alg)
            else {
                return Err(VerifyError::NoMatchingKey);
            };

            let is_verified =
                verify_with_key(&crypto.subtle(), sign_alg, crypto_key, input, signature)
                    .await
                    .context(VerifySnafu)
                    .map_err(Error::from)?;

            if !is_verified {
                return Err(VerifyError::SignatureMismatch);
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use huskarl_core::crypto::signer::{AsymmetricJwsSignerSelector as _, JwsSignerSelector as _};
    use wasm_bindgen_test::*;

    use super::*;
    use crate::asymmetric::signer::{GenerateAlgorithm, PrivateKey, RSA_MODULUS_2048};

    // RFC 8037 §A.2 — Ed25519 public key.
    const RFC8037_ED25519_PUBLIC_JWK: &str =
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

    /// The signer's exported public JWK with `alg` overridden, so [`Key::new`]
    /// takes a deterministic dispatch arm regardless of what the platform stamps
    /// on export. Pass `None` to import without an `alg` (e.g. the all-RSA case).
    ///
    /// The exported `key_ops`/`use` are left untouched: the generated key is
    /// verification-capable (see `exported_public_jwk_is_verification_capable`),
    /// so `from_jwk` accepts it unmodified.
    async fn verification_jwk(signer: &PrivateKey, alg: Option<&str>) -> jwk::PublicJwk {
        let mut jwk = signer
            .select_asymmetric_signer()
            .await
            .public_key_jwk()
            .into_owned();
        jwk.algorithm = alg.map(str::to_string);
        jwk
    }

    /// Regression guard: a signer's exported public JWK must advertise the
    /// `verify` operation, otherwise verifiers re-importing it (`DPoP` proofs, JWS
    /// `jwk` headers) reject it via [`AsymmetricPublicKey::from_jwk`]. Exercises
    /// the *unmodified* exported JWK.
    #[wasm_bindgen_test]
    async fn exported_public_jwk_is_verification_capable() {
        let signer = PrivateKey::generate(GenerateAlgorithm::Es256, None)
            .await
            .unwrap();
        let jwk = signer
            .select_asymmetric_signer()
            .await
            .public_key_jwk()
            .into_owned();

        assert!(
            jwk.key_operations
                .as_ref()
                .is_none_or(|ops| ops.contains(&KeyOperation::Verify)),
            "exported public JWK must permit verify, got key_ops {:?}",
            jwk.key_operations,
        );
        assert!(
            AsymmetricPublicKey::from_jwk(jwk).await.is_some(),
            "the unmodified exported public JWK must import as a verifier",
        );
    }

    /// Regression: a kid-mismatched token must be rejected with
    /// `NoMatchingKey` *before* verification is attempted — matching the
    /// native backend, and letting `RetryingVerifier` refresh on rotation —
    /// even when the signature would verify under this key.
    #[wasm_bindgen_test]
    async fn kid_mismatch_is_no_matching_key() {
        let signer = PrivateKey::generate(GenerateAlgorithm::Es256, None)
            .await
            .unwrap();
        let mut jwk = verification_jwk(&signer, Some("ES256")).await;
        jwk.kid = Some("key-a".to_string());
        let verifier = AsymmetricPublicKey::from_jwk(jwk)
            .await
            .expect("from_jwk should import the generated key");

        let input = b"kid mismatch input";
        let signature = signer.select_signer().await.sign(input).await.unwrap();
        let key_match = KeyMatch::builder().alg("ES256").kid("key-b").build();

        let outcome = verifier.verify(input, &signature, &key_match).await;
        assert!(
            matches!(outcome, Err(VerifyError::NoMatchingKey)),
            "kid mismatch must be NoMatchingKey, got {outcome:?}"
        );
    }

    /// Generates a keypair, re-imports its public JWK as a verifier, and confirms
    /// a real signature round-trips. Mirrors native's `roundtrip_jwk` helper.
    async fn roundtrip(algorithm: GenerateAlgorithm, jws_alg: &str) {
        let signer = PrivateKey::generate(algorithm, None).await.unwrap();
        let verifier =
            AsymmetricPublicKey::from_jwk(verification_jwk(&signer, Some(jws_alg)).await)
                .await
                .expect("from_jwk should import the generated key");

        let input = b"webcrypto asymmetric roundtrip input";
        let signature = signer.select_signer().await.sign(input).await.unwrap();
        let key_match = KeyMatch::builder().alg(jws_alg).build();

        let outcome = verifier.verify(input, &signature, &key_match).await;
        assert!(
            outcome.is_ok(),
            "{jws_alg} roundtrip should verify: {outcome:?}"
        );

        let mut tampered = input.to_vec();
        tampered[0] ^= 1;
        assert!(
            matches!(
                verifier.verify(&tampered, &signature, &key_match).await,
                Err(VerifyError::SignatureMismatch)
            ),
            "{jws_alg} tampered input must fail"
        );
    }

    #[wasm_bindgen_test]
    async fn roundtrip_es256() {
        roundtrip(GenerateAlgorithm::Es256, "ES256").await;
    }

    #[wasm_bindgen_test]
    async fn roundtrip_es384() {
        roundtrip(GenerateAlgorithm::Es384, "ES384").await;
    }

    #[wasm_bindgen_test]
    async fn roundtrip_rs256() {
        roundtrip(
            GenerateAlgorithm::Rs256 {
                modulus_length: RSA_MODULUS_2048,
            },
            "RS256",
        )
        .await;
    }

    #[wasm_bindgen_test]
    async fn roundtrip_rs384() {
        roundtrip(
            GenerateAlgorithm::Rs384 {
                modulus_length: RSA_MODULUS_2048,
            },
            "RS384",
        )
        .await;
    }

    #[wasm_bindgen_test]
    async fn roundtrip_rs512() {
        roundtrip(
            GenerateAlgorithm::Rs512 {
                modulus_length: RSA_MODULUS_2048,
            },
            "RS512",
        )
        .await;
    }

    #[wasm_bindgen_test]
    async fn roundtrip_ps256() {
        roundtrip(
            GenerateAlgorithm::Ps256 {
                modulus_length: RSA_MODULUS_2048,
            },
            "PS256",
        )
        .await;
    }

    #[wasm_bindgen_test]
    async fn roundtrip_ps384() {
        roundtrip(
            GenerateAlgorithm::Ps384 {
                modulus_length: RSA_MODULUS_2048,
            },
            "PS384",
        )
        .await;
    }

    #[wasm_bindgen_test]
    async fn roundtrip_ps512() {
        roundtrip(
            GenerateAlgorithm::Ps512 {
                modulus_length: RSA_MODULUS_2048,
            },
            "PS512",
        )
        .await;
    }

    /// An RSA JWK with no `alg` imports the key under all six RSA algorithms
    /// ([`Key::Rsa`]). The single key advertises and can verify each of them.
    #[wasm_bindgen_test]
    async fn rsa_without_alg_imports_all_variants() {
        let signer = PrivateKey::generate(
            GenerateAlgorithm::Rs256 {
                modulus_length: RSA_MODULUS_2048,
            },
            None,
        )
        .await
        .unwrap();

        let verifier = AsymmetricPublicKey::from_jwk(verification_jwk(&signer, None).await)
            .await
            .expect("alg-less RSA JWK should import");

        for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            assert!(
                verifier
                    .key_match(&KeyMatch::builder().alg(alg).build())
                    .is_some(),
                "alg-less RSA key should match {alg}"
            );
        }

        // The same key really verifies a signature it produced (RS256 here).
        let input = b"alg-less rsa input";
        let signature = signer.select_signer().await.sign(input).await.unwrap();
        verifier
            .verify(input, &signature, &KeyMatch::builder().alg("RS256").build())
            .await
            .unwrap();
    }

    /// A sub-2048-bit RSA modulus is below the RFC 7518 §4.2 minimum and is
    /// rejected before any `SubtleCrypto` import, matching the native backend
    /// (`from_jwk_rejects_small_rsa_modulus`).
    #[wasm_bindgen_test]
    async fn from_jwk_rejects_small_rsa_modulus() {
        // A 1024-bit modulus (128 bytes) is below the 2048-bit minimum.
        let jwk = jwk::PublicJwk::builder()
            .algorithm("RS256")
            .key(
                jwk::RsaPublicKey::builder()
                    .n([0xFF; 128])
                    .e([0x01, 0x00, 0x01])
                    .build(),
            )
            .build();
        assert!(AsymmetricPublicKey::from_jwk(jwk).await.is_none());

        // The same undersized key is also rejected when it carries no `alg`
        // (the all-RSA import arm).
        let jwk_no_alg = jwk::PublicJwk::builder()
            .key(
                jwk::RsaPublicKey::builder()
                    .n([0xFF; 128])
                    .e([0x01, 0x00, 0x01])
                    .build(),
            )
            .build();
        assert!(AsymmetricPublicKey::from_jwk(jwk_no_alg).await.is_none());
    }

    /// Above the 8192-bit ceiling: rejected before any `SubtleCrypto` import.
    #[wasm_bindgen_test]
    async fn from_jwk_rejects_oversized_rsa_modulus() {
        // A 16384-bit modulus (2048 bytes) is above the 8192-bit ceiling.
        let jwk = jwk::PublicJwk::builder()
            .algorithm("RS256")
            .key(
                jwk::RsaPublicKey::builder()
                    .n([0xFF; 2048])
                    .e([0x01, 0x00, 0x01])
                    .build(),
            )
            .build();
        assert!(AsymmetricPublicKey::from_jwk(jwk).await.is_none());
    }

    /// Significant bits of a big-endian modulus, skipping leading zero bytes.
    #[wasm_bindgen_test]
    fn modulus_bits_counts_significant_bits() {
        use super::rsa_modulus_bits;
        assert_eq!(rsa_modulus_bits(&[]), 0);
        assert_eq!(rsa_modulus_bits(&[0x00, 0x00]), 0);
        assert_eq!(rsa_modulus_bits(&[0x00, 0x01]), 1);
        assert_eq!(rsa_modulus_bits(&[0xFF]), 8);
        assert_eq!(rsa_modulus_bits(&[0x01, 0x00]), 9);
        // 256 big-endian bytes led by 0x80 is exactly 2048 bits.
        let mut n = [0u8; 256];
        n[0] = 0x80;
        assert_eq!(rsa_modulus_bits(&n), 2048);
    }

    /// A P-256 key labelled `ES384` matches no [`Key::new`] arm and is rejected.
    #[wasm_bindgen_test]
    async fn ec_curve_algorithm_mismatch_is_rejected() {
        let signer = PrivateKey::generate(GenerateAlgorithm::Es256, None)
            .await
            .unwrap();
        let jwk = verification_jwk(&signer, Some("ES384")).await;
        assert!(AsymmetricPublicKey::from_jwk(jwk).await.is_none());
    }

    /// An RSA key labelled with an EC algorithm matches no [`Key::new`] arm.
    #[wasm_bindgen_test]
    async fn rsa_with_ec_algorithm_is_rejected() {
        let signer = PrivateKey::generate(
            GenerateAlgorithm::Rs256 {
                modulus_length: RSA_MODULUS_2048,
            },
            None,
        )
        .await
        .unwrap();
        let jwk = verification_jwk(&signer, Some("ES256")).await;
        assert!(AsymmetricPublicKey::from_jwk(jwk).await.is_none());
    }

    /// Verifying against an algorithm the key does not support hits the
    /// `None` arm of [`Key::matching_key_and_alg`].
    #[wasm_bindgen_test]
    async fn verify_with_unsupported_alg_reports_no_matching_key() {
        let signer = PrivateKey::generate(GenerateAlgorithm::Es256, None)
            .await
            .unwrap();
        let verifier =
            AsymmetricPublicKey::from_jwk(verification_jwk(&signer, Some("ES256")).await)
                .await
                .unwrap();

        let input = b"unsupported alg input";
        let signature = signer.select_signer().await.sign(input).await.unwrap();
        assert!(matches!(
            verifier
                .verify(input, &signature, &KeyMatch::builder().alg("ES384").build(),)
                .await,
            Err(VerifyError::NoMatchingKey)
        ));
    }

    async fn rfc8037_verifier() -> AsymmetricPublicKey {
        let jwk: jwk::PublicJwk = serde_json::from_str(RFC8037_ED25519_PUBLIC_JWK).unwrap();
        AsymmetricPublicKey::from_jwk(jwk).await.unwrap()
    }

    /// JWS headers in the wild carry the polymorphic name `EdDSA` (RFC 8037),
    /// not the fully-specified `Ed25519` (RFC 9864); the key must match under
    /// both, since multi-key dispatch selects on `key_match`.
    #[wasm_bindgen_test]
    async fn ed25519_key_matches_eddsa_and_ed25519() {
        let verifier = rfc8037_verifier().await;
        for alg in ["EdDSA", "Ed25519"] {
            assert!(
                verifier
                    .key_match(&KeyMatch::builder().alg(alg).build())
                    .is_some(),
                "expected key_match for alg {alg}"
            );
        }
        assert!(
            verifier
                .key_match(&KeyMatch::builder().alg("RS256").build())
                .is_none()
        );
    }

    /// RFC 8037 §A.4/§A.5 — verify the worked Ed25519 JWS example.
    #[wasm_bindgen_test]
    async fn ed25519_verifies_rfc8037_example() {
        let verifier = rfc8037_verifier().await;
        let input = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
        let signature = URL_SAFE_NO_PAD
            .decode("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
            .unwrap();

        // The worked example must verify under both the polymorphic `EdDSA` name
        // and the fully-specified `Ed25519` name (RFC 8037 / RFC 9864) — the
        // `verify` path dispatches on `alg`, not just `key_match`.
        for alg in ["EdDSA", "Ed25519"] {
            let outcome = verifier
                .verify(input, &signature, &KeyMatch::builder().alg(alg).build())
                .await;
            assert!(
                outcome.is_ok(),
                "RFC 8037 worked example should verify under {alg}: {outcome:?}"
            );
        }

        // Tampering with the signed input is detected.
        let mut tampered = input.to_vec();
        tampered[0] ^= 1;
        assert!(matches!(
            verifier
                .verify(
                    &tampered,
                    &signature,
                    &KeyMatch::builder().alg("EdDSA").build()
                )
                .await,
            Err(VerifyError::SignatureMismatch)
        ));

        // An algorithm the Ed25519 key cannot satisfy reports NoMatchingKey
        // (the `None` arm of `matching_key_and_alg`) rather than mis-verifying.
        assert!(matches!(
            verifier
                .verify(input, &signature, &KeyMatch::builder().alg("ES256").build())
                .await,
            Err(VerifyError::NoMatchingKey)
        ));
    }
}
