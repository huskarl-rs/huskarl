use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::signer::{JwsSigner, JwsSignerError, SigningKeyMetadata},
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// Boxed JWS Signer.
#[derive(Debug, Clone)]
pub struct BoxedJwsSigner {
    inner: Arc<dyn DynJwsSigner>,
}

impl BoxedJwsSigner {
    /// Create a boxed signer from a non-boxed.
    pub fn new<Sgn: JwsSigner + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

/// Boxed trait for signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
trait DynJwsSigner: std::fmt::Debug + MaybeSendSync {
    /// Returns metadata about the key used by this signer.
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    #[allow(clippy::type_complexity)]
    fn sign<'a>(
        &'a self,
        input: &'a [u8],
        key_metadata: &'a SigningKeyMetadata,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, JwsSignerError<BoxedError>>> + 'a>>;
}

impl<Sgn: JwsSigner> DynJwsSigner for Sgn {
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.key_metadata()
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
        key_metadata: &'a SigningKeyMetadata,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, JwsSignerError<BoxedError>>> + 'a>>
    {
        Box::pin(async {
            self.sign(input, key_metadata).await.map_err(|e| match e {
                JwsSignerError::MismatchedKeyMetadata => JwsSignerError::MismatchedKeyMetadata,
                JwsSignerError::UnderlyingError { source } => JwsSignerError::UnderlyingError {
                    source: BoxedError::from_err(source),
                },
            })
        })
    }
}

impl JwsSigner for BoxedJwsSigner {
    type Error = BoxedError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        self.inner.key_metadata()
    }

    async fn sign(
        &self,
        input: &[u8],
        key_metadata: &SigningKeyMetadata,
    ) -> Result<Vec<u8>, JwsSignerError<Self::Error>> {
        self.inner.sign(input, key_metadata).await
    }
}
