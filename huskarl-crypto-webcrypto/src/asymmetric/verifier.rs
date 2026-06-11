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

/// An asymmetric public key used to verify JWS signatures via the `WebCrypto` `SubtleCrypto` API.
#[derive(Debug, Clone)]
pub struct AsymmetricPublicKey {
    inner: Arc<AsymmetricPublicKeyInner>,
}

impl AsymmetricPublicKey {
    /// Creates an asymmetric public key from a JWK.
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
            Key::Ed25519(..) => &["Ed25519"],
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
            jwk::PublicKey::Rsa(_) if jwk.algorithm.is_none() => Some(Key::Rsa {
                rs256: create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-256", &jwk).await?,
                rs384: create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-384", &jwk).await?,
                rs512: create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-512", &jwk).await?,
                ps256: create_rsa_key(&crypto, "RSA-PSS", "SHA-256", &jwk).await?,
                ps384: create_rsa_key(&crypto, "RSA-PSS", "SHA-384", &jwk).await?,
                ps512: create_rsa_key(&crypto, "RSA-PSS", "SHA-512", &jwk).await?,
            }),
            jwk::PublicKey::Rsa(_) if jwk.algorithm.as_ref().is_some_and(|alg| alg == "RS256") => {
                Some(Key::Rs256(
                    create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-256", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(_) if jwk.algorithm.as_ref().is_some_and(|alg| alg == "RS384") => {
                Some(Key::Rs384(
                    create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-384", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(_) if jwk.algorithm.as_ref().is_some_and(|alg| alg == "RS512") => {
                Some(Key::Rs512(
                    create_rsa_key(&crypto, "RSASSA-PKCS1-v1_5", "SHA-512", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(_) if jwk.algorithm.as_ref().is_some_and(|alg| alg == "PS256") => {
                Some(Key::Ps256(
                    create_rsa_key(&crypto, "RSA-PSS", "SHA-256", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(_) if jwk.algorithm.as_ref().is_some_and(|alg| alg == "PS384") => {
                Some(Key::Ps384(
                    create_rsa_key(&crypto, "RSA-PSS", "SHA-384", &jwk).await?,
                ))
            }
            jwk::PublicKey::Rsa(_) if jwk.algorithm.as_ref().is_some_and(|alg| alg == "PS512") => {
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

/// Errors that can occur when signing.
#[derive(Debug, Snafu)]
pub enum AsymmetricPublicKeyError {
    /// Unable to find webcrypto support in environment.
    #[snafu(display("Failed to find WebCrypto support"))]
    NoCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// Error occurred when attempting to sign.
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
