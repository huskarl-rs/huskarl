#[cfg(feature = "crypto-native")]
use p521;

#[cfg(feature = "default-crypto-native")]
use p521_default as p521;

use p521::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use p521::elliptic_curve::Generate as _;
use p521::pkcs8::DecodePrivateKey as _;

use bytes::Bytes;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use snafu::prelude::*;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;

use crate::crypto::signer::{HasPublicKey, JwsSigningKey, SigningKeyMetadata};
use crate::jwk;
use crate::secrets::Secret;

const ALGORITHM: &str = "ES512";

#[derive(Debug, Snafu)]
pub enum Es512PrivateKeyLoadError<E: crate::Error> {
    Secret {
        source: E,
    },
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        source: p521::pkcs8::Error,
    },
    /// Signature error.
    Signature {
        /// The underlying error.
        source: p521::ecdsa::Error,
    },
}

struct Es512PrivateKeyInner {
    signing_key: SigningKey,
    key_metadata: SigningKeyMetadata,
    jwk: jwk::PublicJwk,
}

#[derive(Clone)]
pub struct Es512PrivateKey {
    inner: Arc<Es512PrivateKeyInner>,
}

impl From<SigningKey> for Es512PrivateKey {
    fn from(value: SigningKey) -> Self {
        let verifying_key = VerifyingKey::from(&value);
        let encoded_point = verifying_key.to_sec1_point(false);
        let key = jwk::EcPublicKey::builder()
            .crv("P-521")
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
            inner: Arc::new(Es512PrivateKeyInner {
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

impl Es512PrivateKey {
    #[must_use]
    pub fn generate() -> Self {
        p521::ecdsa::SigningKey::generate().into()
    }

    /// Loads the private key from a DER binary secret.
    ///
    /// # Errors
    ///
    /// The secret was not a valid DER formatted secret, or the secret
    /// could not be accessed.
    pub async fn load_pkcs8_der<S: Secret<Output = SecretBox<[u8]>>>(
        secret: S,
    ) -> Result<Self, Es512PrivateKeyLoadError<S::Error>> {
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
    ) -> Result<Self, Es512PrivateKeyLoadError<S::Error>> {
        let pem = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = SigningKey::from_pkcs8_pem(pem.expose_secret()).context(KeyDecodeSnafu)?;
        Ok(key.into())
    }
}

impl JwsSigningKey for Es512PrivateKey {
    type Error = Infallible;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        let signature: Signature = self.inner.signing_key.sign(input);
        Ok(signature.to_vec().into())
    }
}

impl HasPublicKey for Es512PrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.inner.jwk
    }
}
