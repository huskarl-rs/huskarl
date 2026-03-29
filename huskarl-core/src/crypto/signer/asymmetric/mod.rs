use std::borrow::Cow;

use snafu::prelude::*;

use crate::{
    Error,
    crypto::signer::{JwsSigner, JwsSigningKey, SigningKeyMetadata},
    jwk::PublicJwk,
    platform::{MaybeSend, MaybeSendSync},
};

pub mod boxed;

/// Asymmetric key metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct AsymmetricSigningKeyMetadata {
    /// The base key metadata of the signer.
    pub key_metadata: SigningKeyMetadata,

    /// The public key of the signer.
    pub public_key: PublicJwk,
}

impl AsymmetricSigningKeyMetadata {
    /// Returns the JWK thumbprint for the public key.
    #[must_use]
    pub fn thumbprint(&self) -> Option<String> {
        self.public_key.thumbprint()
    }
}

/// Trait for asymmetric signing keys that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait AsymmetricJwsSigningKey: std::fmt::Debug + Clone + MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: Error + 'static;

    /// The key type used by this signer.
    ///
    /// The key type is chosen by the trait implementor, and is used to match the key returned by
    /// [`Self::key_and_metadata_by_thumbprint`], to the value passed to [`Self::sign_with_key`]; it identifies the
    /// key to use for signing.
    type Key;

    /// Returns the primary key and metadata for this signer.
    fn primary_key_metadata(&self) -> &AsymmetricSigningKeyMetadata;

    /// Asynchronously signs the given input data using the primary key and returns the raw signature bytes.
    ///
    /// This is an implementation method — callers should use [`JwsSigner::sign`] instead,
    /// which validates that the caller's expected key metadata matches the key before signing.
    /// This prevents writing an incorrect `alg` or `kid` into a JWT header if the key has
    /// been rotated since the header was prepared.
    ///
    /// To sign with a specific non-primary key (e.g. during key rotation), implement
    /// [`Self::key_and_metadata_by_thumbprint`] and [`Self::sign_with_key`], and call
    /// [`AsymmetricJwsSigner::sign_by_thumbprint`].
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_unchecked(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;

    /// Returns the key and metadata for the given JWK thumbprint, if one is available.
    ///
    /// If the implementation is aware of a key with the given thumbprint, it will return a reference
    /// to the key and its metadata. Otherwise, it will return `None`. This includes the primary key.
    fn key_and_metadata_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<(&Self::Key, &AsymmetricSigningKeyMetadata)>;

    /// Asynchronously signs the given input data using the provided key and returns the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails, or if the key is not recognized by this signer.
    fn sign_with_key(
        &self,
        key: &Self::Key,
        input: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// Trait for asymmetric signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait AsymmetricJwsSigner: JwsSigner {
    /// Returns the key metadata for this signer.
    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata>;

    /// Returns the key metadata for the given JWK thumbprint, if one is available.
    fn key_metadata_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Cow<'_, AsymmetricSigningKeyMetadata>>;

    /// Asynchronously signs the given input data using the key identified by the given JWK thumbprint.
    ///
    /// # Errors
    ///
    /// Returns [`SignByThumbprintError::KeyNotFound`] if no key with the given thumbprint is known, or
    /// [`SignByThumbprintError::Sign`] if the signing operation fails.
    fn sign_by_thumbprint(
        &self,
        input: &[u8],
        thumbprint: &str,
    ) -> impl Future<Output = Result<Vec<u8>, SignByThumbprintError<Self::Error>>> + MaybeSend;
}

impl<T: AsymmetricJwsSigningKey> JwsSigningKey for T {
    type Error = T::Error;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.primary_key_metadata().key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        AsymmetricJwsSigningKey::sign_unchecked(self, input).await
    }
}

impl<T: AsymmetricJwsSigningKey> AsymmetricJwsSigner for T {
    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata> {
        Cow::Borrowed(self.primary_key_metadata())
    }

    fn key_metadata_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Cow<'_, AsymmetricSigningKeyMetadata>> {
        let (_, metadata) = self.key_and_metadata_by_thumbprint(thumbprint)?;
        Some(Cow::Borrowed(metadata))
    }

    async fn sign_by_thumbprint(
        &self,
        input: &[u8],
        thumbprint: &str,
    ) -> Result<Vec<u8>, SignByThumbprintError<Self::Error>> {
        let Some((key, _)) = self.key_and_metadata_by_thumbprint(thumbprint) else {
            return KeyNotFoundSnafu.fail();
        };

        self.sign_with_key(key, input).await.context(SignSnafu)
    }
}

/// Error type for [`AsymmetricJwsSigner::sign_by_thumbprint`].
///
/// This error is returned when the key is not found or the signing operation fails.
#[derive(Debug, Snafu, Clone)]
pub enum SignByThumbprintError<E: crate::Error> {
    /// The key corresponding to the thumbprint was not found.
    KeyNotFound,
    /// The signing operation failed.
    Sign {
        /// The underlying error.
        source: E,
    },
}

impl<E: crate::Error> crate::Error for SignByThumbprintError<E> {
    fn is_retryable(&self) -> bool {
        match self {
            SignByThumbprintError::KeyNotFound => false,
            SignByThumbprintError::Sign { source } => source.is_retryable(),
        }
    }
}
