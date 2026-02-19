use bytes::Bytes;

#[cfg(feature = "crypto-native")]
use rsa;

#[cfg(all(feature = "default-crypto-native", not(feature = "crypto-native")))]
use rsa_default as rsa;

use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::SignatureEncoding as _;
use rsa::signature::Signer as _;
use rsa::traits::PublicKeyParts as _;

use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use snafu::prelude::*;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;

use crate::crypto::signer::{HasPublicKey, JwsSigningKey, SigningKeyMetadata};
use crate::jwk::{self, PublicJwk};
use crate::secrets::Secret;

/// RSA algorithm supported by this key.
pub enum RsaAlgorithm {
    /// Key supports RS256.
    Rs256,
    /// Key supports PS256.
    Ps256,
    /// Key supports PS384.
    Ps384,
    /// Key supports PS512.
    Ps512,
}

impl AsRef<str> for RsaAlgorithm {
    fn as_ref(&self) -> &str {
        match self {
            RsaAlgorithm::Rs256 => "RS256",
            RsaAlgorithm::Ps256 => "PS256",
            RsaAlgorithm::Ps384 => "PS384",
            RsaAlgorithm::Ps512 => "PS512",
        }
    }
}

enum SigningKey {
    Rs256(rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>),
    Ps256(rsa::pss::SigningKey<rsa::sha2::Sha256>),
    Ps384(rsa::pss::SigningKey<rsa::sha2::Sha384>),
    Ps512(rsa::pss::SigningKey<rsa::sha2::Sha512>),
}

impl SigningKey {
    pub fn sign(&self, msg: &[u8]) -> bytes::Bytes {
        use rsa::signature::RandomizedSigner;

        match self {
            SigningKey::Rs256(signing_key) => signing_key.sign(msg).to_vec().into(),
            SigningKey::Ps256(signing_key) => signing_key
                .sign_with_rng(&mut rand::rng(), msg)
                .to_vec()
                .into(),
            SigningKey::Ps384(signing_key) => signing_key
                .sign_with_rng(&mut rand::rng(), msg)
                .to_vec()
                .into(),
            SigningKey::Ps512(signing_key) => signing_key
                .sign_with_rng(&mut rand::rng(), msg)
                .to_vec()
                .into(),
        }
    }
}

/// Errors that may occur when loading RSA private key.
#[derive(Debug, Snafu)]
pub enum RsaPrivateKeyLoadError<E: crate::Error> {
    /// Failed to access secret information.
    Secret {
        /// The underlying error.
        source: E,
    },
    /// Failed to decode PKCS#8 key
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        /// The underlying error.
        source: rsa::pkcs8::Error,
    },
}

struct RsaPrivateKeyInner {
    signing_key: SigningKey,
    key_metadata: SigningKeyMetadata,
    jwk: PublicJwk,
}

impl std::fmt::Debug for RsaPrivateKeyInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPrivateKeyInner")
            .field("key_metadata", &self.key_metadata)
            .field("jwk", &self.jwk)
            .finish_non_exhaustive()
    }
}

/// An RSA private key.
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    inner: Arc<RsaPrivateKeyInner>,
}

fn convert(
    private_key: rsa::RsaPrivateKey,
    algorithm: &RsaAlgorithm,
    key_id: Option<&str>,
) -> RsaPrivateKey {
    let public_key = jwk::RsaPublicKey::builder()
        .e(private_key.e_bytes())
        .n(private_key.n_bytes())
        .build();

    let signing_key = match algorithm {
        RsaAlgorithm::Rs256 => SigningKey::Rs256(
            rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private_key),
        ),
        RsaAlgorithm::Ps256 => {
            SigningKey::Ps256(rsa::pss::SigningKey::<rsa::sha2::Sha256>::new(private_key))
        }
        RsaAlgorithm::Ps384 => {
            SigningKey::Ps384(rsa::pss::SigningKey::<rsa::sha2::Sha384>::new(private_key))
        }
        RsaAlgorithm::Ps512 => {
            SigningKey::Ps512(rsa::pss::SigningKey::<rsa::sha2::Sha512>::new(private_key))
        }
    };

    RsaPrivateKey {
        inner: Arc::new(RsaPrivateKeyInner {
            signing_key,
            key_metadata: SigningKeyMetadata::builder()
                .jws_algorithm(algorithm.as_ref())
                .maybe_key_id(key_id)
                .build(),
            jwk: PublicJwk::builder()
                .algorithm(algorithm.as_ref())
                .key_use(jwk::KeyUse::Sign)
                .key(public_key)
                .build(),
        }),
    }
}

impl RsaPrivateKey {
    /// Generates a private key supporting the specified JWS algorithm.
    ///
    /// # Errors
    ///
    /// Should not return an error during normal operation.
    pub fn generate(algorithm: &RsaAlgorithm, key_id: Option<&str>) -> Result<Self, rsa::Error> {
        Ok(convert(
            rsa::RsaPrivateKey::new(&mut rand::rng(), 2048)?,
            algorithm,
            key_id,
        ))
    }

    /// Loads the private key from a DER binary secret.
    ///
    /// # Errors
    ///
    /// The secret was not a valid DER formatted secret, or the secret
    /// could not be accessed.
    pub async fn load_pkcs8_der<
        S: Secret<Output = SecretBox<[u8]>>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        algorithm: &RsaAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, RsaPrivateKeyLoadError<S::Error>> {
        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(secret_output.value.expose_secret())
            .context(KeyDecodeSnafu)?;
        Ok(convert(
            key,
            algorithm,
            key_id_from_secret_identity(secret_output.identity.as_deref()).as_deref(),
        ))
    }

    /// Loads the private key from a PKCS#8 PEM secret.
    ///
    /// # Errors
    ///
    /// The secret was not a valid PKCS#8 PEM formatted string, or
    /// the secret could not be accessed.
    pub async fn load_pkcs8_pem<
        S: Secret<Output = SecretString>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        algorithm: &RsaAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, RsaPrivateKeyLoadError<S::Error>> {
        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(secret_output.value.expose_secret())
            .context(KeyDecodeSnafu)?;
        Ok(convert(
            key,
            algorithm,
            key_id_from_secret_identity(secret_output.identity.as_deref()).as_deref(),
        ))
    }
}

impl JwsSigningKey for RsaPrivateKey {
    type Error = Infallible;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        Ok(self.inner.signing_key.sign(input))
    }
}

impl HasPublicKey for RsaPrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.inner.jwk
    }
}
