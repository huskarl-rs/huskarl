use std::{borrow::Cow, convert::Infallible, sync::Arc};

use bytes::Bytes;
#[cfg(feature = "crypto-native")]
use hmac::{Hmac, KeyInit as _, Mac as _};

#[cfg(feature = "default-crypto-native")]
use hmac_default::{Hmac, KeyInit as _, Mac as _};

use secrecy::{ExposeSecret, SecretBox};

use crate::{
    crypto::signer::{JwsSigningKey, SigningKeyMetadata},
    secrets::Secret,
};

/// Encodes which variant of HMAC is used by this key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacAlgorithm {
    /// HS256 algorithm
    Hs256,
    /// HS384 algorithm
    Hs384,
    /// HS512 algorithm
    Hs512,
}

impl AsRef<str> for HmacAlgorithm {
    fn as_ref(&self) -> &str {
        match self {
            HmacAlgorithm::Hs256 => "HS256",
            HmacAlgorithm::Hs384 => "HS384",
            HmacAlgorithm::Hs512 => "HS512",
        }
    }
}

struct HmacKeyInner {
    key: SecretBox<[u8]>,
    algorithm: HmacAlgorithm,
    metadata: SigningKeyMetadata,
}

impl std::fmt::Debug for HmacKeyInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKeyInner")
            .field("algorithm", &self.algorithm)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// An HMAC symmetric key.
#[derive(Debug, Clone)]
pub struct HmacKey {
    inner: Arc<HmacKeyInner>,
}

impl HmacKey {
    /// Loads the bytes from a binary secret.
    ///
    /// # Errors
    ///
    /// The secret could not be accessed.
    pub async fn load_bytes<S: Secret<Output = SecretBox<[u8]>>>(
        secret: S,
        algorithm: HmacAlgorithm,
    ) -> Result<Self, S::Error> {
        let slice = secret.get_secret_value().await?;

        let metadata = SigningKeyMetadata::builder()
            .jws_algorithm(algorithm.as_ref())
            .build();

        Ok(Self {
            inner: Arc::new(HmacKeyInner {
                key: slice,
                algorithm,
                metadata,
            }),
        })
    }
}

impl JwsSigningKey for HmacKey {
    type Error = Infallible;

    fn key_metadata(&self) -> std::borrow::Cow<'_, crate::crypto::signer::SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<bytes::Bytes, Self::Error> {
        let key_bytes = self.inner.key.expose_secret();

        let signed_bytes = match self.inner.algorithm {
            HmacAlgorithm::Hs256 => {
                let mut key: Hmac<sha2::Sha256> =
                    Hmac::new_from_slice(key_bytes).expect("Should not fail with HMAC-SHA");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            HmacAlgorithm::Hs384 => {
                let mut key: Hmac<sha2::Sha384> =
                    Hmac::new_from_slice(key_bytes).expect("Should not fail with HMAC-SHA");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            HmacAlgorithm::Hs512 => {
                let mut key: Hmac<sha2::Sha512> =
                    Hmac::new_from_slice(key_bytes).expect("Should not fail with HMAC-SHA");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
        };

        Ok(Bytes::from(signed_bytes))
    }
}
