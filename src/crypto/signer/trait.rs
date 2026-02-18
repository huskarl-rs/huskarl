//! Signing key traits.

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;

use bon::Builder;
use bytes::Bytes;
use snafu::prelude::*;

use crate::crypto::signer::error::{MismatchedKeyMetadataSnafu, UnderlyingSnafu};
use crate::error::BoxedError;
use crate::jwk::PublicJwk;
use crate::platform::{MaybeSend, MaybeSendSync};
use crate::{Error, platform::MaybeSendFuture};

/// Boxed JWS Signer.
#[derive(Clone)]
pub struct BoxedJwsSigningKey {
    inner: Arc<dyn DynJwsSigningKey>,
}

impl BoxedJwsSigningKey {
    /// Create a boxed signing key from a non-boxed.
    pub fn new<Sgn: JwsSigningKey + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

/// Boxed trait for signing keys that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
trait DynJwsSigningKey: MaybeSendSync {
    /// Returns metadata about the key used by this signer.
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the algorithm
    /// and key ID match the values signed (which could happen due to key updates).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Bytes, BoxedError>> + 'a>>;
}

impl<Sgn: JwsSigningKey> DynJwsSigningKey for Sgn {
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.key_metadata()
    }

    fn sign_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Bytes, BoxedError>> + 'a>> {
        Box::pin(async {
            self.sign_unchecked(input)
                .await
                .map_err(BoxedError::from_err)
        })
    }
}

impl JwsSigningKey for BoxedJwsSigningKey {
    type Error = BoxedError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.inner.key_metadata()
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        self.inner.sign_unchecked(input).await
    }
}

/// Boxed JWS Signer for asymmetric keys.
#[derive(Clone)]
pub struct BoxedAsymmetricJwsSigningKey {
    inner: Arc<dyn DynAsymmetricJwsSigningKey>,
}

impl BoxedAsymmetricJwsSigningKey {
    /// Create a boxed signing key from a non-boxed.
    pub fn new<Sgn: JwsSigningKey + HasPublicKey + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

/// Boxed trait for signing keys that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
trait DynAsymmetricJwsSigningKey: MaybeSendSync {
    /// Returns metadata about the key used by this signer.
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the algorithm
    /// and key ID match the values signed (which could happen due to key updates).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Bytes, BoxedError>> + 'a>>;

    fn public_key_jwk(&self) -> &PublicJwk;
}

impl<Sgn: JwsSigningKey + HasPublicKey> DynAsymmetricJwsSigningKey for Sgn {
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.key_metadata()
    }

    fn sign_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Bytes, BoxedError>> + 'a>> {
        Box::pin(async {
            self.sign_unchecked(input)
                .await
                .map_err(BoxedError::from_err)
        })
    }

    fn public_key_jwk(&self) -> &PublicJwk {
        self.public_key_jwk()
    }
}

impl JwsSigningKey for BoxedAsymmetricJwsSigningKey {
    type Error = BoxedError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.inner.key_metadata()
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Bytes, Self::Error> {
        self.inner.sign_unchecked(input).await
    }
}

impl HasPublicKey for BoxedAsymmetricJwsSigningKey {
    fn public_key_jwk(&self) -> &PublicJwk {
        self.inner.public_key_jwk()
    }
}

/// Key metadata.
#[derive(Debug, Clone, Builder, PartialEq)]
pub struct SigningKeyMetadata {
    /// Returns the JWS algorithm identifier.
    ///
    /// This is specifically for use in the JWT `alg` header parameter.
    ///
    /// Note: Implementations should return fully specified algorithms, as
    /// in RFC 9864. It is the responsibility of the caller to map this to a
    /// polymorphic algorithm when needed.
    #[builder(into)]
    pub jws_algorithm: String,
    /// Returns the key ID of the signer.
    ///
    /// This is specifically for use in the JWT `kid` header parameter.
    ///
    /// Note: The "natural" key ID is not always directly suitable as a
    /// `kid` value, and may require transformation before use.
    #[builder(into)]
    pub key_id: Option<String>,
}

/// Trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigningKey: MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: Error + 'static;

    /// Returns the key metadata for this signer.
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the metadata
    /// match the values signed (which could happen due to key updates).
    ///
    /// Generally implementations should implement this function, and users will
    /// call `sign`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + MaybeSend;

    /// Asynchronously signs the given input data and returns the signature with metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the key metadata is mismatched, or the signing operation fails.
    fn sign(
        &self,
        input: &[u8],
        key_metadata: &SigningKeyMetadata,
    ) -> impl Future<Output = Result<Bytes, super::JwsSignerError<Self::Error>>> + MaybeSend {
        async move {
            if &*self.key_metadata() == key_metadata {
                self.sign_unchecked(input).await.context(UnderlyingSnafu)
            } else {
                MismatchedKeyMetadataSnafu.fail()
            }
        }
    }
}

/// Trait for asymmetric keys that provides its public key in JWK (RFC 7517) format.
pub trait HasPublicKey: MaybeSendSync {
    /// Returns the public key for this asymmetric key as a JSON Web Key.
    fn public_key_jwk(&self) -> &PublicJwk;
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, convert::Infallible};

    use super::*;
    use crate::crypto::signer::JwsSignerError;

    #[derive(Debug, Clone)]
    struct MockSigningKey {
        key_metadata: SigningKeyMetadata,
    }

    impl MockSigningKey {
        pub fn new() -> Self {
            Self {
                key_metadata: SigningKeyMetadata::builder().jws_algorithm("ALG").build(),
            }
        }
    }

    impl JwsSigningKey for MockSigningKey {
        type Error = Infallible;

        fn key_metadata(&self) -> std::borrow::Cow<'_, SigningKeyMetadata> {
            Cow::Borrowed(&self.key_metadata)
        }

        async fn sign_unchecked(&self, _input: &[u8]) -> Result<bytes::Bytes, Self::Error> {
            Ok(bytes::Bytes::new())
        }
    }

    #[tokio::test]
    async fn test_metadata_no_mismatch_succeeds() {
        MockSigningKey::new()
            .sign(
                &[],
                &SigningKeyMetadata {
                    jws_algorithm: "ALG".into(),
                    key_id: None,
                },
            )
            .await
            .expect("no mismatch");
    }

    #[tokio::test]
    async fn test_metadata_different_alg_fails() {
        let result = MockSigningKey::new()
            .sign(
                &[],
                &SigningKeyMetadata::builder().jws_algorithm("ALG2").build(),
            )
            .await;

        assert!(matches!(result, Err(JwsSignerError::MismatchedKeyMetadata)));
    }

    #[tokio::test]
    async fn test_metadata_different_kid_fails() {
        let result = MockSigningKey::new()
            .sign(
                &[],
                &SigningKeyMetadata::builder()
                    .jws_algorithm("ALG")
                    .key_id("key-id")
                    .build(),
            )
            .await;

        assert!(matches!(result, Err(JwsSignerError::MismatchedKeyMetadata)));
    }
}
