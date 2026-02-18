#[cfg(feature = "crypto-native")]
use p384;

#[cfg(feature = "default-crypto-native")]
use p384_default as p384;

use bytes::Bytes;
use p384::ecdsa::{Signature, SigningKey, signature::Signer};
use p384::elliptic_curve::Generate as _;
use p384::pkcs8::DecodePrivateKey as _;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use snafu::prelude::*;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;

use crate::crypto::signer::{HasPublicKey, JwsSigningKey, SigningKeyMetadata};
use crate::jwk;
use crate::secrets::Secret;

const ALGORITHM: &str = "ES384";

/// Errors that may occur when loading ES384 private key.
#[derive(Debug, Snafu)]
pub enum Es384PrivateKeyLoadError<E: crate::Error> {
    /// Failed to access secret information.
    Secret {
        /// The underlying error.
        source: E,
    },
    /// Failed to decode PKCS#8 key
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        /// The underlying error.
        source: p384::pkcs8::Error,
    },
}

struct Es384PrivateKeyInner {
    signing_key: SigningKey,
    key_metadata: SigningKeyMetadata,
    jwk: jwk::PublicJwk,
}

/// An ES384 private key.
#[derive(Clone)]
pub struct Es384PrivateKey {
    inner: Arc<Es384PrivateKeyInner>,
}

impl From<SigningKey> for Es384PrivateKey {
    fn from(value: SigningKey) -> Self {
        let encoded_point = value.verifying_key().to_sec1_point(false);
        let key = jwk::EcPublicKey::builder()
            .crv("P-384")
            .x(encoded_point
                .x()
                .expect("uncompressed point always has x coordinate")
                .to_vec())
            .y(encoded_point
                .y()
                .expect("uncompressed point always has y coordinate")
                .to_vec())
            .build();

        Self {
            inner: Arc::new(Es384PrivateKeyInner {
                signing_key: value,
                key_metadata: SigningKeyMetadata::builder()
                    .jws_algorithm(ALGORITHM)
                    .build(),
                jwk: jwk::PublicJwk::builder()
                    .algorithm(ALGORITHM)
                    .key_use(jwk::KeyUse::Sign)
                    .key(key)
                    .build(),
            }),
        }
    }
}

impl Es384PrivateKey {
    /// Generates an ES384 private key in memory.
    #[must_use]
    pub fn generate() -> Self {
        p384::ecdsa::SigningKey::generate().into()
    }

    /// Loads the private key from a DER binary secret.
    ///
    /// # Errors
    ///
    /// The secret was not a valid DER formatted secret, or the secret
    /// could not be accessed.
    pub async fn load_pkcs8_der<S: Secret<Output = SecretBox<[u8]>>>(
        secret: S,
    ) -> Result<Self, Es384PrivateKeyLoadError<S::Error>> {
        let der = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = SigningKey::from_pkcs8_der(der.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(key.into())
    }

    /// Loads the private key from a PKCS#8 PEM secret.
    ///
    /// # Errors
    ///
    /// The secret was not a valid PKCS#8 PEM formatted string, or
    /// the secret could not be accessed.
    pub async fn load_pkcs8_pem<S: Secret<Output = SecretString>>(
        secret: S,
    ) -> Result<Self, Es384PrivateKeyLoadError<S::Error>> {
        let pem = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = SigningKey::from_pkcs8_pem(pem.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(key.into())
    }
}

impl JwsSigningKey for Es384PrivateKey {
    type Error = Infallible;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        let signature: Signature = self.inner.signing_key.sign(input);
        Ok(signature.to_vec().into())
    }
}

impl HasPublicKey for Es384PrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.inner.jwk
    }
}
