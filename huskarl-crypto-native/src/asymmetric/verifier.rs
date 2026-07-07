//! JWS verification with asymmetric public keys (ES256/384, RS/PS 256/384/512,
//! Ed25519), backing huskarl-core's [`JwsVerifier`] trait.
//!
//! [`AsymmetricPublicKey`] is the entry type; build one with
//! [`AsymmetricPublicKey::from_jwk`].

use std::sync::Arc;

use huskarl_core::{
    crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    jwk::{self, KeyOperation, KeyUse},
    platform::MaybeSendBoxFuture,
};
use rsa::{BoxedUint, RsaPublicKey, signature::Verifier};

#[derive(Debug)]
enum Key {
    Es256(p256::ecdsa::VerifyingKey),
    Es384(p384::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
    Rs256(rsa::pkcs1v15::VerifyingKey<sha2::Sha256>),
    Rs384(rsa::pkcs1v15::VerifyingKey<sha2::Sha384>),
    Rs512(rsa::pkcs1v15::VerifyingKey<sha2::Sha512>),
    Ps256(rsa::pss::VerifyingKey<sha2::Sha256>),
    Ps384(rsa::pss::VerifyingKey<sha2::Sha384>),
    Ps512(rsa::pss::VerifyingKey<sha2::Sha512>),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// Union of [`Key::supported_algorithms`] across all variants.
pub(crate) const SUPPORTED_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "Ed25519", "EdDSA",
];

impl Key {
    pub fn supported_algorithms(&self) -> &[&str] {
        match self {
            Key::Es256(_) => &["ES256"],
            Key::Es384(_) => &["ES384"],
            Key::Rsa(_) => &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
            Key::Rs256(_) => &["RS256"],
            Key::Rs384(_) => &["RS384"],
            Key::Rs512(_) => &["RS512"],
            Key::Ps256(_) => &["PS256"],
            Key::Ps384(_) => &["PS384"],
            Key::Ps512(_) => &["PS512"],
            Key::Ed25519(_) => &["Ed25519", "EdDSA"],
        }
    }

    pub fn new(jwk_key: jwk::PublicKey, alg: Option<&str>) -> Option<Key> {
        fn rsa_key_from_jwk(rsa_jwk: jwk::RsaPublicKey) -> Option<rsa::RsaPublicKey> {
            // RFC 7518 §4.2 sets 2048 bits as the minimum RSA key size for JWS;
            // anything smaller is rejected rather than verified.
            let modulus_bytes = rsa_jwk.n.iter().skip_while(|&&b| b == 0).count();
            if modulus_bytes < 2048 / 8 {
                return None;
            }
            let n_boxed = BoxedUint::from_be_slice_vartime(&rsa_jwk.n.into_boxed_slice());
            let e_boxed = BoxedUint::from_be_slice_vartime(&rsa_jwk.e.into_boxed_slice());
            RsaPublicKey::new(n_boxed, e_boxed).ok()
        }

        match jwk_key {
            jwk::PublicKey::Rsa(rsa_public_key) if alg.is_none() => {
                rsa_key_from_jwk(rsa_public_key).map(Self::Rsa)
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("RS256") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Rs256(rsa::pkcs1v15::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("RS384") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Rs384(rsa::pkcs1v15::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("RS512") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Rs512(rsa::pkcs1v15::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("PS256") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Ps256(rsa::pss::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("PS384") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Ps384(rsa::pss::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("PS512") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Ps512(rsa::pss::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Ec(ec_public_key)
                if alg.is_none_or(|a| a == "ES256") && ec_public_key.crv == "P-256" =>
            {
                let mut point =
                    Vec::with_capacity(1 + ec_public_key.x.len() + ec_public_key.y.len());
                point.push(0x04);
                point.extend_from_slice(&ec_public_key.x);
                point.extend_from_slice(&ec_public_key.y);

                p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .ok()
                    .map(Self::Es256)
            }
            jwk::PublicKey::Ec(ec_public_key)
                if alg.is_none_or(|a| a == "ES384") && ec_public_key.crv == "P-384" =>
            {
                let mut point =
                    Vec::with_capacity(1 + ec_public_key.x.len() + ec_public_key.y.len());
                point.push(0x04);
                point.extend_from_slice(&ec_public_key.x);
                point.extend_from_slice(&ec_public_key.y);

                p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .ok()
                    .map(Self::Es384)
            }
            jwk::PublicKey::Okp(okp_public_key)
                if alg.is_none_or(|a| ["Ed25519", "EdDSA"].contains(&a))
                    && okp_public_key.crv == "Ed25519" =>
            {
                ed25519_dalek::VerifyingKey::from_bytes(
                    okp_public_key.x.as_slice().try_into().ok()?,
                )
                .ok()
                .map(Self::Ed25519)
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
struct AsymmetricPublicKeyInner {
    verifying_key: Key,
    kid: Option<String>,
}

/// An asymmetric public key for JWS verification (ES256/384, RS/PS 256/384/512,
/// Ed25519), implementing [`JwsVerifier`].
///
/// Build one with [`from_jwk`](Self::from_jwk); cheap to clone (`Arc`-backed).
#[derive(Debug, Clone)]
pub struct AsymmetricPublicKey {
    inner: Arc<AsymmetricPublicKeyInner>,
}

impl AsymmetricPublicKey {
    /// Creates an asymmetric public key from a public JWK.
    ///
    /// Returns `None` if the JWK cannot be used for verification: its `use` is
    /// not `sig`, its `key_ops` excludes `verify`, the algorithm is unsupported,
    /// the key material fails to parse, or — for RSA — the modulus is under 2048
    /// bits (RFC 7518 §6.3).
    ///
    /// # Examples
    ///
    /// ```
    /// use huskarl_crypto_native::asymmetric::{
    ///     signer::{GenerateAlgorithm, PrivateKey},
    ///     verifier::AsymmetricPublicKey,
    /// };
    ///
    /// // In practice the JWK arrives from a JWKS endpoint; here we derive one
    /// // from a freshly generated key.
    /// let public_jwk = PrivateKey::generate(GenerateAlgorithm::Ed25519, Some("key-1".to_string()))?
    ///     .as_private_jwk()
    ///     .public_jwk();
    ///
    /// let verifier = AsymmetricPublicKey::from_jwk(public_jwk)
    ///     .expect("a freshly generated public JWK is verifiable");
    /// # Ok::<(), huskarl_core::error::Error>(())
    /// ```
    #[must_use]
    pub fn from_jwk(key: jwk::PublicJwk) -> Option<Self> {
        let kid = key.kid;

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

        let verifying_key = Key::new(key.key, key.algorithm.as_deref());

        verifying_key.map(|k| Self {
            inner: Arc::new(AsymmetricPublicKeyInner {
                verifying_key: k,
                kid,
            }),
        })
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
        // A malformed signature encoding can never verify, so it maps to
        // SignatureMismatch just like a failed verification.
        fn mismatch(_: signature::Error) -> VerifyError {
            VerifyError::SignatureMismatch
        }

        Box::pin(async move {
            if self.key_match(key_match).is_none() {
                return Err(VerifyError::NoMatchingKey);
            }

            match &self.inner.verifying_key {
                Key::Es256(verifying_key) => verifying_key.verify(
                    input,
                    &p256::ecdsa::Signature::from_slice(signature).map_err(mismatch)?,
                ),
                Key::Es384(verifying_key) => verifying_key.verify(
                    input,
                    &p384::ecdsa::Signature::from_slice(signature).map_err(mismatch)?,
                ),
                Key::Rsa(public_key) => match key_match.alg {
                    "RS256" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key.clone())
                        .verify(
                            input,
                            &rsa::pkcs1v15::Signature::try_from(signature).map_err(mismatch)?,
                        ),
                    "RS384" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(public_key.clone())
                        .verify(
                            input,
                            &rsa::pkcs1v15::Signature::try_from(signature).map_err(mismatch)?,
                        ),
                    "RS512" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public_key.clone())
                        .verify(
                            input,
                            &rsa::pkcs1v15::Signature::try_from(signature).map_err(mismatch)?,
                        ),
                    "PS256" => rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key.clone())
                        .verify(
                            input,
                            &rsa::pss::Signature::try_from(signature).map_err(mismatch)?,
                        ),
                    "PS384" => rsa::pss::VerifyingKey::<sha2::Sha384>::new(public_key.clone())
                        .verify(
                            input,
                            &rsa::pss::Signature::try_from(signature).map_err(mismatch)?,
                        ),
                    "PS512" => rsa::pss::VerifyingKey::<sha2::Sha512>::new(public_key.clone())
                        .verify(
                            input,
                            &rsa::pss::Signature::try_from(signature).map_err(mismatch)?,
                        ),
                    _ => {
                        unreachable!("RSA algorithm is already checked")
                    }
                },
                Key::Rs256(verifying_key) => verifying_key.verify(
                    input,
                    &rsa::pkcs1v15::Signature::try_from(signature).map_err(mismatch)?,
                ),
                Key::Rs384(verifying_key) => verifying_key.verify(
                    input,
                    &rsa::pkcs1v15::Signature::try_from(signature).map_err(mismatch)?,
                ),
                Key::Rs512(verifying_key) => verifying_key.verify(
                    input,
                    &rsa::pkcs1v15::Signature::try_from(signature).map_err(mismatch)?,
                ),
                Key::Ps256(verifying_key) => verifying_key.verify(
                    input,
                    &rsa::pss::Signature::try_from(signature).map_err(mismatch)?,
                ),
                Key::Ps384(verifying_key) => verifying_key.verify(
                    input,
                    &rsa::pss::Signature::try_from(signature).map_err(mismatch)?,
                ),
                Key::Ps512(verifying_key) => verifying_key.verify(
                    input,
                    &rsa::pss::Signature::try_from(signature).map_err(mismatch)?,
                ),
                Key::Ed25519(verifying_key) => verifying_key.verify_strict(
                    input,
                    &ed25519_dalek::Signature::from_slice(signature).map_err(mismatch)?,
                ),
            }
            .map_err(mismatch)
        })
    }
}

#[cfg(test)]
mod tests {
    use huskarl_core::{
        Error,
        crypto::signer::{
            AsymmetricJwsSigner as _, AsymmetricJwsSignerSelector as _, JwsSigner as _,
        },
        jwt::{
            Jwt,
            validator::{ClaimCheck, JwtValidator},
        },
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput, SecretString},
    };
    use serde::{Deserialize, Serialize};

    use crate::asymmetric::{
        signer::{AsymmetricAlgorithm, GenerateAlgorithm, Pkcs8Der, Pkcs8Pem, PrivateKey},
        verifier::AsymmetricPublicKey,
    };

    #[derive(Clone, Serialize, Deserialize)]
    struct Claims {
        sub: String,
    }

    #[derive(Clone)]
    struct StringSecret {
        value: String,
        identity: Option<String>,
    }

    impl Secret for StringSecret {
        type Output = SecretString;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                Ok(SecretOutput {
                    value: SecretString::new(&self.value),
                    identity: self.identity.clone(),
                })
            })
        }
    }

    #[derive(Clone)]
    struct ByteSecret {
        bytes: Vec<u8>,
        identity: Option<String>,
    }

    impl Secret for ByteSecret {
        type Output = SecretBytes;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                Ok(SecretOutput {
                    value: SecretBytes::new(self.bytes.clone()),
                    identity: self.identity.clone(),
                })
            })
        }
    }

    #[tokio::test]
    async fn verify_access_token() {
        #[derive(Clone, Serialize, Deserialize)]
        struct MyClaims {
            earnest_id: String,
        }

        let signing_key = PrivateKey::generate(GenerateAlgorithm::EdDsa, None).unwrap();
        let selected_key = signing_key.select_asymmetric_signer().await;

        let jwt = Jwt::builder()
            .issuer("https://as.example.com")
            .audience("my-api")
            .issued_now_expires_after(std::time::Duration::from_mins(5))
            .claims(MyClaims {
                earnest_id: "abc123".to_string(),
            })
            .build();
        let token = jwt.to_jws_compact(&selected_key).await.unwrap();

        let public_key =
            AsymmetricPublicKey::from_jwk(selected_key.public_key_jwk().into_owned()).unwrap();

        let validator = JwtValidator::builder()
            .verifier(public_key)
            .aud(ClaimCheck::required_value("my-api"))
            .build();

        let validated = validator
            .validate::<serde_json::Value>(token.expose_secret())
            .await
            .unwrap();

        assert_eq!(validated.issuer.as_deref(), Some("https://as.example.com"));
        assert_eq!(validated.audience, ["my-api"]);
        assert!(validated.expiration.is_some());
    }

    #[test]
    fn from_jwk_rejects_small_rsa_modulus() {
        // A 1024-bit modulus is below the RFC 7518 §4.2 minimum of 2048 bits.
        let jwk = huskarl_core::jwk::PublicJwk::builder()
            .algorithm("RS256")
            .key(
                huskarl_core::jwk::RsaPublicKey::builder()
                    .n([0xFF; 128])
                    .e([0x01, 0x00, 0x01])
                    .build(),
            )
            .build();
        assert!(AsymmetricPublicKey::from_jwk(jwk).is_none());
    }

    #[tokio::test]
    async fn roundtrip_jwk_es256() {
        roundtrip_jwk(GenerateAlgorithm::Es256).await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_rs256() {
        roundtrip_jwk(GenerateAlgorithm::Rs256 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_ps256() {
        roundtrip_jwk(GenerateAlgorithm::Ps256 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_eddsa() {
        roundtrip_jwk(GenerateAlgorithm::EdDsa).await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_ed25519() {
        roundtrip_jwk(GenerateAlgorithm::Ed25519).await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_es384() {
        roundtrip_jwk(GenerateAlgorithm::Es384).await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_rs384() {
        roundtrip_jwk(GenerateAlgorithm::Rs384 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_rs512() {
        roundtrip_jwk(GenerateAlgorithm::Rs512 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_ps384() {
        roundtrip_jwk(GenerateAlgorithm::Ps384 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn roundtrip_jwk_ps512() {
        roundtrip_jwk(GenerateAlgorithm::Ps512 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn roundtrip_load_jwk_es256() {
        roundtrip_load_jwk(GenerateAlgorithm::Es256).await;
    }

    #[tokio::test]
    async fn roundtrip_load_jwk_rs256() {
        roundtrip_load_jwk(GenerateAlgorithm::Rs256 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn roundtrip_load_jwk_eddsa() {
        roundtrip_load_jwk(GenerateAlgorithm::EdDsa).await;
    }

    async fn roundtrip_load_jwk(algorithm: GenerateAlgorithm) {
        let kid = "load-jwk-key".to_string();
        let original = PrivateKey::generate(algorithm, Some(kid.clone())).unwrap();
        let private_jwk = original.as_private_jwk();

        // Convert to Jwk (which is Serialize) and serialize to JSON
        let jwk: huskarl_core::jwk::Jwk = private_jwk.into();
        let json = serde_json::to_string(&jwk).unwrap();
        let secret = StringSecret {
            value: json,
            identity: None,
        };
        let restored = PrivateKey::from_secret(secret.mapped(huskarl_core::jwk::JwkJson))
            .await
            .unwrap();
        let selected = restored.select_asymmetric_signer().await;

        // Sign with restored key
        let jwt = Jwt::builder()
            .issuer("https://test.example.com")
            .audience("test-aud")
            .issued_now_expires_after(std::time::Duration::from_mins(1))
            .claims(Claims {
                sub: "user-99".to_string(),
            })
            .build();
        let token = jwt.to_jws_compact(&selected).await.unwrap();

        // Verify with the original key's public key
        let public_key = AsymmetricPublicKey::from_jwk(
            original
                .select_asymmetric_signer()
                .await
                .public_key_jwk()
                .into_owned(),
        )
        .unwrap();

        let validator = JwtValidator::builder()
            .verifier(public_key)
            .aud(ClaimCheck::required_value("test-aud"))
            .build();

        let validated = validator
            .validate::<serde_json::Value>(token.expose_secret())
            .await
            .unwrap();

        assert_eq!(
            validated.issuer.as_deref(),
            Some("https://test.example.com")
        );
    }

    // -- PKCS#8 round-trip tests --

    #[tokio::test]
    async fn roundtrip_pkcs8_der_es256() {
        use p256::elliptic_curve::Generate as _;
        use pkcs8::EncodePrivateKey as _;

        let raw_key = p256::ecdsa::SigningKey::generate();
        let der = raw_key.to_pkcs8_der().unwrap();

        let secret = ByteSecret {
            bytes: der.as_bytes().to_vec(),
            identity: Some("der-es256-key".to_string()),
        };
        let loaded =
            PrivateKey::from_secret(secret.mapped(Pkcs8Der::new(AsymmetricAlgorithm::Es256)))
                .await
                .unwrap();

        sign_and_verify(&loaded).await;
    }

    #[tokio::test]
    async fn roundtrip_pkcs8_pem_es256() {
        use p256::elliptic_curve::Generate as _;
        use pkcs8::EncodePrivateKey as _;

        let raw_key = p256::ecdsa::SigningKey::generate();
        let pem = raw_key.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();

        let secret = StringSecret {
            value: pem.as_str().to_string(),
            identity: Some("pem-es256-key".to_string()),
        };
        let loaded =
            PrivateKey::from_secret(secret.mapped(Pkcs8Pem::new(AsymmetricAlgorithm::Es256)))
                .await
                .unwrap();

        sign_and_verify(&loaded).await;
    }

    #[tokio::test]
    async fn roundtrip_pkcs8_der_eddsa() {
        use pkcs8::EncodePrivateKey as _;

        let raw_key = ed25519_dalek::SigningKey::from_bytes(&{
            let mut bytes = [0u8; 32];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
            bytes
        });
        let der = raw_key.to_pkcs8_der().unwrap();

        let secret = ByteSecret {
            bytes: der.as_bytes().to_vec(),
            identity: None,
        };
        let loaded =
            PrivateKey::from_secret(secret.mapped(Pkcs8Der::new(AsymmetricAlgorithm::EdDsa)))
                .await
                .unwrap();

        sign_and_verify(&loaded).await;
    }

    #[tokio::test]
    async fn roundtrip_pkcs8_der_rs256() {
        use pkcs8::EncodePrivateKey as _;

        let rsa_key = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let der = rsa_key.to_pkcs8_der().unwrap();

        let secret = ByteSecret {
            bytes: der.as_bytes().to_vec(),
            identity: None,
        };
        let loaded =
            PrivateKey::from_secret(secret.mapped(Pkcs8Der::new(AsymmetricAlgorithm::Rs256)))
                .await
                .unwrap();

        sign_and_verify(&loaded).await;
    }

    // -- Cross-construction verification --
    // Sign with a PKCS#8-loaded key, verify with a JWK-extracted public key,
    // then round-trip the private key through JWK and confirm identical signatures.

    #[tokio::test]
    async fn cross_verify_pkcs8_and_jwk() {
        use p256::elliptic_curve::Generate as _;
        use pkcs8::EncodePrivateKey as _;

        let raw_key = p256::ecdsa::SigningKey::generate();
        let der = raw_key.to_pkcs8_der().unwrap();

        // Load via PKCS#8
        let secret = ByteSecret {
            bytes: der.as_bytes().to_vec(),
            identity: Some("cross-key".to_string()),
        };
        let pkcs8_key =
            PrivateKey::from_secret(secret.mapped(Pkcs8Der::new(AsymmetricAlgorithm::Es256)))
                .await
                .unwrap();

        // Round-trip through JWK
        let private_jwk = pkcs8_key.as_private_jwk();
        let jwk_key = PrivateKey::from_jwk(private_jwk).unwrap();

        // Both keys should produce identical signatures (ES256 uses RFC 6979)
        let data = b"cross-construction test payload";
        let sig_pkcs8 = pkcs8_key.sign(data).await.unwrap();
        let sig_jwk = jwk_key.sign(data).await.unwrap();
        assert_eq!(
            sig_pkcs8, sig_jwk,
            "PKCS#8-loaded and JWK-restored keys must produce identical signatures"
        );

        // Sign with JWK key, verify with PKCS#8 key's public key
        let jwt = Jwt::builder()
            .issuer("https://cross.example.com")
            .audience("cross-aud")
            .issued_now_expires_after(std::time::Duration::from_mins(1))
            .claims(Claims {
                sub: "cross-user".to_string(),
            })
            .build();
        let token = jwt
            .to_jws_compact(&jwk_key.select_asymmetric_signer().await)
            .await
            .unwrap();

        let public_key = AsymmetricPublicKey::from_jwk(
            pkcs8_key
                .select_asymmetric_signer()
                .await
                .public_key_jwk()
                .into_owned(),
        )
        .unwrap();

        let validator = JwtValidator::builder()
            .verifier(public_key)
            .aud(ClaimCheck::required_value("cross-aud"))
            .build();

        validator
            .validate::<serde_json::Value>(token.expose_secret())
            .await
            .unwrap();
    }

    // -- Deterministic signature tests --
    // Verify that from_jwk preserves exact key material (not just "some valid key").

    #[tokio::test]
    async fn deterministic_signature_es256() {
        deterministic_signature_roundtrip(GenerateAlgorithm::Es256).await;
    }

    #[tokio::test]
    async fn deterministic_signature_es384() {
        deterministic_signature_roundtrip(GenerateAlgorithm::Es384).await;
    }

    #[tokio::test]
    async fn deterministic_signature_rs256() {
        deterministic_signature_roundtrip(GenerateAlgorithm::Rs256 {
            modulus_length: 2048,
        })
        .await;
    }

    #[tokio::test]
    async fn deterministic_signature_eddsa() {
        deterministic_signature_roundtrip(GenerateAlgorithm::EdDsa).await;
    }

    async fn deterministic_signature_roundtrip(algorithm: GenerateAlgorithm) {
        let original = PrivateKey::generate(algorithm, Some("det-key".to_string())).unwrap();
        let private_jwk = original.as_private_jwk();
        let restored = PrivateKey::from_jwk(private_jwk).unwrap();

        let data = b"deterministic signature test payload";
        let sig_original = original.sign(data).await.unwrap();
        let sig_restored = restored.sign(data).await.unwrap();

        assert_eq!(
            sig_original, sig_restored,
            "original and JWK-restored keys must produce identical signatures"
        );
    }

    // -- Helpers --

    async fn sign_and_verify(key: &PrivateKey) {
        let selected = key.select_asymmetric_signer().await;

        let jwt = Jwt::builder()
            .issuer("https://test.example.com")
            .audience("test-aud")
            .issued_now_expires_after(std::time::Duration::from_mins(1))
            .claims(Claims {
                sub: "user-1".to_string(),
            })
            .build();
        let token = jwt.to_jws_compact(&selected).await.unwrap();

        let public_key =
            AsymmetricPublicKey::from_jwk(selected.public_key_jwk().into_owned()).unwrap();

        let validator = JwtValidator::builder()
            .verifier(public_key)
            .aud(ClaimCheck::required_value("test-aud"))
            .build();

        validator
            .validate::<serde_json::Value>(token.expose_secret())
            .await
            .unwrap();
    }

    async fn roundtrip_jwk(algorithm: GenerateAlgorithm) {
        let kid = "test-key-1".to_string();
        let original = PrivateKey::generate(algorithm, Some(kid.clone())).unwrap();
        let private_jwk = original.as_private_jwk();

        // Round-trip through from_jwk
        let restored = PrivateKey::from_jwk(private_jwk).unwrap();
        let selected = restored.select_asymmetric_signer().await;

        // Sign with restored key
        let jwt = Jwt::builder()
            .issuer("https://test.example.com")
            .audience("test-aud")
            .issued_now_expires_after(std::time::Duration::from_mins(1))
            .claims(Claims {
                sub: "user-42".to_string(),
            })
            .build();
        let token = jwt.to_jws_compact(&selected).await.unwrap();

        // Verify with the original key's public key
        let public_key = AsymmetricPublicKey::from_jwk(
            original
                .select_asymmetric_signer()
                .await
                .public_key_jwk()
                .into_owned(),
        )
        .unwrap();

        let validator = JwtValidator::builder()
            .verifier(public_key)
            .aud(ClaimCheck::required_value("test-aud"))
            .build();

        let validated = validator
            .validate::<serde_json::Value>(token.expose_secret())
            .await
            .unwrap();

        assert_eq!(
            validated.issuer.as_deref(),
            Some("https://test.example.com")
        );
    }

    #[test]
    fn rsa_verifier_does_not_match_hmac_algorithms() {
        use huskarl_core::crypto::verifier::{JwsVerifier as _, KeyMatch};

        let rsa = PrivateKey::generate(
            GenerateAlgorithm::Rs256 {
                modulus_length: 2048,
            },
            None,
        )
        .unwrap();
        let verifier = AsymmetricPublicKey::from_jwk(rsa.public_key_jwk().into_owned()).unwrap();

        // RS256→HS256 confusion is prevented at key selection: an RSA key
        // advertises only RSA algorithms, so a token claiming `alg: HS256` finds
        // no matching key and the RSA modulus is never treated as an HMAC secret.
        assert!(
            verifier
                .key_match(&KeyMatch::builder().alg("HS256").build())
                .is_none()
        );
        // The same key still matches its genuine algorithm.
        assert!(
            verifier
                .key_match(&KeyMatch::builder().alg("RS256").build())
                .is_some()
        );
    }

    #[tokio::test]
    async fn rsa_validator_rejects_hs256_key_confusion_token() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use huskarl_core::{crypto::verifier::VerifyError, jwt::validator::JwtValidationError};
        use sha2::Sha256;

        // A validator that trusts only an RSA public key, as if it had been
        // fetched from the authorization server's JWKS.
        let rsa = PrivateKey::generate(
            GenerateAlgorithm::Rs256 {
                modulus_length: 2048,
            },
            None,
        )
        .unwrap();
        let rsa_pub_jwk = rsa.public_key_jwk().into_owned();
        let verifier = AsymmetricPublicKey::from_jwk(rsa_pub_jwk.clone()).unwrap();
        let validator = JwtValidator::builder().verifier(verifier).build();

        // RS256→HS256 confusion: the attacker forges an `HS256` token whose HMAC
        // secret is the (public) RSA key material. A verifier that selected the
        // key by material rather than algorithm would treat the public modulus as
        // a shared secret and accept this; huskarl rejects it at key selection
        // (`JwsVerifier::verify` returns `NoMatchingKey`).
        let secret = serde_json::to_vec(&rsa_pub_jwk).unwrap();
        let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
        let signing_input = format!(
            "{}.{}",
            b64(br#"{"alg":"HS256","typ":"JWT"}"#),
            b64(br#"{"iss":"attacker"}"#),
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(signing_input.as_bytes());
        let forged = format!("{signing_input}.{}", b64(&mac.finalize().into_bytes()));

        // Rejected specifically at key selection (proving the token parsed and
        // reached verification): no key matched `alg: HS256`.
        let result = validator.validate::<serde_json::Value>(&forged).await;
        assert!(
            matches!(
                result,
                Err(JwtValidationError::Signature {
                    source: VerifyError::NoMatchingKey
                })
            ),
            "RS256→HS256 confusion token must be rejected at key selection, got {result:?}"
        );
    }
}
