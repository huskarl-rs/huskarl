//! Implements JWS signing keys on WASM using the WebCrypto/Subtle API.
//!
//! Currently, the following JWS algorithms are available:
//!
//! - Asymmetric (NIST elliptic curves)
//!   - ES256
//!   - ES384
//!   - ES512

mod helpers;

use serde::Serialize;
use snafu::prelude::*;
use std::borrow::Cow;
use std::sync::Arc;

use wasm_bindgen::JsValue;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::{
    crypto::signer::{
        HasPublicKey, JwsSigningKey, SigningKeyMetadata,
        webcrypto::helpers::{GetCryptoError, get_crypto},
    },
    jwk,
};
use helpers::{
    AsymmetricKeyGenParams, KeyUsage, generate_asymmetric_key, get_public_jwk, sign_with_key,
};

/// Represents JavaScript errors.
#[derive(Debug, Snafu)]
#[snafu(display("{}", error.as_string().unwrap_or_default()))]
pub struct JsError {
    error: JsValue,
}

impl JsError {
    /// Create a new `JsError` from a `JsValue`.
    pub(crate) fn new(error: JsValue) -> Self {
        Self { error }
    }
}

struct AsymmetricPrivateJwsKeyInner {
    crypto_key: CryptoKey,
    algorithm: JwsAlgorithm,
    key_metadata: SigningKeyMetadata,
    jwk: jwk::PublicJwk,
}

/// A non-exportable asymmetric private key used to create JWS signatures.
///
/// Keys used here are not extractable by JavaScript.
#[derive(Clone)]
pub struct AsymmetricPrivateJwsKey {
    inner: Arc<AsymmetricPrivateJwsKeyInner>,
}

/// Algorithm supported by this key.
#[derive(Serialize, Clone, Copy)]
pub enum JwsAlgorithm {
    /// ES256
    Es256,
    /// ES384
    Es384,
    /// ES512
    Es512,
}

impl JwsAlgorithm {
    fn named_curve(&self) -> &'static str {
        match self {
            Self::Es256 => "P-256",
            Self::Es384 => "P-384",
            Self::Es512 => "P-521",
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
        }
    }

    fn hash_algorithm(&self) -> &'static str {
        match self {
            Self::Es256 => "SHA-256",
            Self::Es384 => "SHA-384",
            Self::Es512 => "SHA-512",
        }
    }
}

/// Errors that can occur when generating a private key.
#[derive(Debug, Snafu)]
pub enum GenerateError {
    /// An error occurred when attempting to generate the key.
    #[snafu(display("Error generating key"))]
    Generate {
        /// The underlying error.
        source: helpers::GenerateKeyError,
    },
    /// An error occurred when attempting to get the JWK for the key.
    #[snafu(display("Error getting JWK for private key"))]
    GetPublicJwk {
        /// The underlying error.
        source: helpers::GetPublicJwkError,
    },
}

impl AsymmetricPrivateJwsKey {
    /// Creates a non-extractable private key which can sign material using the specified JWS algorithm.
    #[must_use]
    pub async fn generate(
        crypto: &SubtleCrypto,
        algorithm: JwsAlgorithm,
    ) -> Result<Self, GenerateError> {
        let key_gen_params = AsymmetricKeyGenParams::Ec {
            name: "ECDSA",
            named_curve: algorithm.named_curve(),
        };

        let key_pair = generate_asymmetric_key(&crypto, key_gen_params, &[KeyUsage::Sign])
            .await
            .context(GenerateSnafu)?;

        let public_key_jwk = get_public_jwk(&crypto, &key_pair.get_public_key())
            .await
            .context(GetPublicJwkSnafu)?;

        Ok(Self {
            inner: Arc::new(AsymmetricPrivateJwsKeyInner {
                crypto_key: key_pair.get_private_key(),
                algorithm,
                key_metadata: SigningKeyMetadata {
                    jws_algorithm: algorithm.name().to_string(),
                    key_id: public_key_jwk.kid.clone(),
                },
                jwk: public_key_jwk,
            }),
        })
    }
}

/// Errors that can occur when signing.
#[derive(Debug, Snafu)]
pub enum SignError {
    /// Unable to find webcrypto support in environment.
    #[snafu(display("Failed to find WebCrypto support"))]
    NoCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// Error occurred when attempting to sign.
    #[snafu(display("Signing failed"))]
    Sign {
        /// The underlying error.
        source: helpers::SignError,
    },
}

impl crate::Error for SignError {
    fn is_retryable(&self) -> bool {
        false
    }
}

impl JwsSigningKey for AsymmetricPrivateJwsKey {
    type Error = SignError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let crypto = get_crypto().context(NoCryptoSnafu)?;

        sign_with_key(
            &crypto.subtle(),
            helpers::SignAlgorithm::EcDsa {
                name: "ECDSA",
                hash: self.inner.algorithm.hash_algorithm(),
            },
            &self.inner.crypto_key,
            input,
        )
        .await
        .context(SignSnafu)
    }
}

impl HasPublicKey for AsymmetricPrivateJwsKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.inner.jwk
    }
}
