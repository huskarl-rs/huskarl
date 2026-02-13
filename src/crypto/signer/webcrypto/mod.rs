mod helpers;

use bytes::Bytes;
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

#[derive(Debug, Snafu)]
#[snafu(display("{}", error.as_string().unwrap_or_default()))]
pub struct JsError {
    error: JsValue,
}

impl JsError {
    pub fn new(error: JsValue) -> Self {
        Self { error }
    }
}

struct EcDsaPrivateKeyInner {
    crypto_key: CryptoKey,
    algorithm: JwsAlgorithm,
    key_metadata: SigningKeyMetadata,
    jwk: jwk::PublicJwk,
}

#[derive(Clone)]
pub struct EcDsaPrivateKey {
    inner: Arc<EcDsaPrivateKeyInner>,
}

#[derive(Serialize, Clone, Copy)]
pub enum JwsAlgorithm {
    Es256,
    Es384,
    Es512,
}

impl JwsAlgorithm {
    pub fn named_curve(&self) -> &'static str {
        match self {
            Self::Es256 => "P-256",
            Self::Es384 => "P-384",
            Self::Es512 => "P-521",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
        }
    }

    pub fn hash_algorithm(&self) -> &'static str {
        match self {
            Self::Es256 => "SHA-256",
            Self::Es384 => "SHA-384",
            Self::Es512 => "SHA-512",
        }
    }
}

#[derive(Debug, Snafu)]
pub enum GenerateError {
    Generate { source: helpers::GenerateKeyError },
    GetPublicJwk { source: helpers::GetPublicJwkError },
}

impl EcDsaPrivateKey {
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
            inner: Arc::new(EcDsaPrivateKeyInner {
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

#[derive(Debug, Snafu)]
pub enum SignError {
    NoCrypto { source: GetCryptoError },
    Sign { source: helpers::SignError },
}

impl crate::Error for SignError {
    fn is_retryable(&self) -> bool {
        false
    }
}

impl JwsSigningKey for EcDsaPrivateKey {
    type Error = SignError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
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

impl HasPublicKey for EcDsaPrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.inner.jwk
    }
}
