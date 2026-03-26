use std::borrow::Cow;

use snafu::prelude::*;

use crate::{
    Error,
    crypto::signer::{
        JwsSigningKey, SigningKeyMetadata,
        error::{MismatchedKeyMetadataSnafu, UnderlyingSnafu},
    },
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

/// Trait for asymmetric signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
pub trait AsymmetricJwsSigningKey: std::fmt::Debug + Clone + MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: Error + 'static;

    /// Returns the key metadata for this signer.
    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the metadata
    /// match the values signed (which could happen due to key updates).
    ///
    /// Generally implementations should implement this function, and users will
    /// call `sign_asymmetric`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_asymmetric_unchecked(
        &self,
        input: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;

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
    fn sign_asymmetric(
        &self,
        input: &[u8],
        key_metadata: &AsymmetricSigningKeyMetadata,
    ) -> impl Future<Output = Result<Vec<u8>, super::JwsSignerError<Self::Error>>> + MaybeSend {
        async move {
            if &*self.asymmetric_key_metadata() == key_metadata {
                self.sign_asymmetric_unchecked(input)
                    .await
                    .context(UnderlyingSnafu)
            } else {
                MismatchedKeyMetadataSnafu.fail()
            }
        }
    }
}

impl<T: AsymmetricJwsSigningKey> JwsSigningKey for T {
    type Error = T::Error;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        match AsymmetricJwsSigningKey::asymmetric_key_metadata(self) {
            Cow::Borrowed(m) => Cow::Borrowed(&m.key_metadata),
            Cow::Owned(m) => Cow::Owned(m.key_metadata),
        }
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign_asymmetric_unchecked(input).await
    }
}
