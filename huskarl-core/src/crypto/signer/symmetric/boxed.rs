use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::signer::{JwsSigningKey, SigningKeyMetadata},
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// Boxed JWS Signer.
#[derive(Debug, Clone)]
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
trait DynJwsSigningKey: std::fmt::Debug + MaybeSendSync {
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
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>>;
}

impl<Sgn: JwsSigningKey> DynJwsSigningKey for Sgn {
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.key_metadata()
    }

    fn sign_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>> {
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

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.sign_unchecked(input).await
    }
}
