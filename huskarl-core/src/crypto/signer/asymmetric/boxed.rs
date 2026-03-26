use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::signer::asymmetric::{AsymmetricJwsSigningKey, AsymmetricSigningKeyMetadata},
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// Boxed JWS Signer for asymmetric keys.
#[derive(Debug, Clone)]
pub struct BoxedAsymmetricJwsSigningKey {
    inner: Arc<dyn DynAsymmetricJwsSigningKey>,
}

impl BoxedAsymmetricJwsSigningKey {
    /// Create a boxed asymmetric signing key from a non-boxed.
    pub fn new<Sgn: AsymmetricJwsSigningKey + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

/// Boxed trait for asymmetric signing keys that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
trait DynAsymmetricJwsSigningKey: std::fmt::Debug + MaybeSendSync {
    /// Returns metadata about the asymmetric key used by this signer.
    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// This should not be called directly, as it does not verify that the algorithm
    /// and key ID match the values signed (which could happen due to key updates).
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign_asymmetric_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>>;
}

impl<Sgn: AsymmetricJwsSigningKey> DynAsymmetricJwsSigningKey for Sgn {
    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata> {
        self.asymmetric_key_metadata()
    }

    fn sign_asymmetric_unchecked<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>> {
        Box::pin(async {
            self.sign_asymmetric_unchecked(input)
                .await
                .map_err(BoxedError::from_err)
        })
    }
}

impl AsymmetricJwsSigningKey for BoxedAsymmetricJwsSigningKey {
    type Error = BoxedError;

    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata> {
        self.inner.asymmetric_key_metadata()
    }

    async fn sign_asymmetric_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.sign_asymmetric_unchecked(input).await
    }
}
