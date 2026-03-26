use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::signer::{HasPublicKey, JwsSigningKey, SigningKeyMetadata},
    jwk::PublicJwk,
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// Boxed JWS Signer for asymmetric keys.
#[derive(Debug, Clone)]
pub struct BoxedAsymmetricJwsSigningKey {
    inner: Arc<dyn DynAsymmetricJwsSigningKey>,
}

impl BoxedAsymmetricJwsSigningKey {
    /// Create a boxed signing key from a non-boxed.
    pub fn new<Sgn: JwsSigningKey + HasPublicKey + std::fmt::Debug + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

/// Boxed trait for signing keys that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
trait DynAsymmetricJwsSigningKey: std::fmt::Debug + MaybeSendSync {
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

    fn public_key_jwk(&self) -> &PublicJwk;
}

impl<Sgn: std::fmt::Debug + JwsSigningKey + HasPublicKey> DynAsymmetricJwsSigningKey for Sgn {
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

    fn public_key_jwk(&self) -> &PublicJwk {
        self.public_key_jwk()
    }
}

impl JwsSigningKey for BoxedAsymmetricJwsSigningKey {
    type Error = BoxedError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.inner.key_metadata()
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.sign_unchecked(input).await
    }
}

impl HasPublicKey for BoxedAsymmetricJwsSigningKey {
    fn public_key_jwk(&self) -> &PublicJwk {
        self.inner.public_key_jwk()
    }
}
