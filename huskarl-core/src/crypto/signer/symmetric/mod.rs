//! Signing key traits.

pub mod boxed;

use std::borrow::Cow;

use bon::Builder;
use snafu::prelude::*;

use crate::Error;
use crate::crypto::signer::JwsSignerError;
use crate::crypto::signer::error::{MismatchedKeyMetadataSnafu, UnderlyingSnafu};
use crate::platform::{MaybeSend, MaybeSendSync};

/// Key metadata.
#[derive(Debug, Clone, Builder, PartialEq)]
pub struct SigningKeyMetadata {
    /// The JWS algorithm identifier.
    ///
    /// This is specifically for use in the JWT `alg` header parameter.
    ///
    /// Note: Implementations should return fully specified algorithms, as
    /// in RFC 9864. It is the responsibility of the caller to map this to a
    /// polymorphic algorithm when needed.
    #[builder(into)]
    pub jws_algorithm: String,
    /// The key ID of the signer.
    ///
    /// This is specifically for use in the JWT `kid` header parameter.
    ///
    /// Note: The "natural" key ID is not always directly suitable as a
    /// `kid` value, and may require transformation before use.
    #[builder(into)]
    pub key_id: Option<String>,
}

/// Trait for signing implementations that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigningKey: std::fmt::Debug + Clone + MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: Error + 'static;

    /// Returns the key metadata for this signer.
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata>;

    /// Asynchronously signs the given input data and returns the raw signature bytes.
    ///
    /// This is an implementation method — callers should use [`JwsSigner::sign`] instead,
    /// which validates that the caller's expected key metadata matches the key before signing.
    /// This prevents writing an incorrect `alg` or `kid` into a JWT header if the key has
    /// been rotated since the header was prepared.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// Trait for using signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait JwsSigner: std::fmt::Debug + Clone + MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: Error + 'static;

    /// Returns the key metadata for this signer.
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata>;

    /// Asynchronously signs the given input data, after verifying the caller's expected key metadata.
    ///
    /// The metadata must match the values signed. For example, if a key was rotated,
    /// then either the key ID or algorithm (or both) could have changed, and this will be
    /// detected by the `sign` implementation. In that case, the caller should retry the operation
    /// (this is already done internally in the `OAuth2` exchange code).
    ///
    /// # Errors
    ///
    /// Returns [`super::JwsSignerError::MismatchedKeyMetadata`] if the key metadata is mismatched, or
    /// [`super::JwsSignerError::UnderlyingError`] if the signing operation fails.
    fn sign(
        &self,
        input: &[u8],
        key_metadata: &SigningKeyMetadata,
    ) -> impl Future<Output = Result<Vec<u8>, JwsSignerError<Self::Error>>> + MaybeSend;
}

impl<T: JwsSigningKey> JwsSigner for T {
    type Error = T::Error;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.key_metadata()
    }

    async fn sign(
        &self,
        input: &[u8],
        key_metadata: &SigningKeyMetadata,
    ) -> Result<Vec<u8>, super::JwsSignerError<Self::Error>> {
        if &*self.key_metadata() == key_metadata {
            self.sign_unchecked(input).await.context(UnderlyingSnafu)
        } else {
            MismatchedKeyMetadataSnafu.fail()
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
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

        async fn sign_unchecked(&self, _input: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(vec![])
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
