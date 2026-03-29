use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::signer::{
        JwsSigner, JwsSignerError, SigningKeyMetadata,
        asymmetric::{AsymmetricJwsSigner, AsymmetricSigningKeyMetadata, SignByThumbprintError},
    },
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// Boxed JWS Signer for asymmetric keys.
#[derive(Debug, Clone)]
pub struct BoxedAsymmetricJwsSigner {
    inner: Arc<dyn DynAsymmetricJwsSigner>,
}

impl BoxedAsymmetricJwsSigner {
    /// Create a boxed asymmetric signing key from a non-boxed.
    pub fn new<Sgn: AsymmetricJwsSigner + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

/// Boxed trait for asymmetric signers that produce RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
#[allow(clippy::type_complexity)]
trait DynAsymmetricJwsSigner: std::fmt::Debug + MaybeSendSync {
    // JwsSigner methods
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata>;

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
        key_metadata: &'a SigningKeyMetadata,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, JwsSignerError<BoxedError>>> + 'a>>;

    // AsymmetricJwsSigner methods
    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata>;

    fn key_metadata_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Cow<'_, AsymmetricSigningKeyMetadata>>;

    fn sign_by_thumbprint<'a>(
        &'a self,
        input: &'a [u8],
        thumbprint: &'a str,
    ) -> Pin<
        Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, SignByThumbprintError<BoxedError>>> + 'a>,
    >;
}

impl<Sgn: AsymmetricJwsSigner> DynAsymmetricJwsSigner for Sgn {
    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        JwsSigner::key_metadata(self)
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
        key_metadata: &'a SigningKeyMetadata,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, JwsSignerError<BoxedError>>> + 'a>>
    {
        Box::pin(async {
            JwsSigner::sign(self, input, key_metadata)
                .await
                .map_err(|e| match e {
                    JwsSignerError::MismatchedKeyMetadata => JwsSignerError::MismatchedKeyMetadata,
                    JwsSignerError::UnderlyingError { source } => JwsSignerError::UnderlyingError {
                        source: BoxedError::from_err(source),
                    },
                })
        })
    }

    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata> {
        AsymmetricJwsSigner::asymmetric_key_metadata(self)
    }

    fn key_metadata_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Cow<'_, AsymmetricSigningKeyMetadata>> {
        AsymmetricJwsSigner::key_metadata_by_thumbprint(self, thumbprint)
    }

    fn sign_by_thumbprint<'a>(
        &'a self,
        input: &'a [u8],
        thumbprint: &'a str,
    ) -> Pin<
        Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, SignByThumbprintError<BoxedError>>> + 'a>,
    > {
        Box::pin(async move {
            AsymmetricJwsSigner::sign_by_thumbprint(self, input, thumbprint)
                .await
                .map_err(|e| match e {
                    SignByThumbprintError::KeyNotFound => SignByThumbprintError::KeyNotFound,
                    SignByThumbprintError::Sign { source } => SignByThumbprintError::Sign {
                        source: BoxedError::from_err(source),
                    },
                })
        })
    }
}

impl AsymmetricJwsSigner for BoxedAsymmetricJwsSigner {
    fn asymmetric_key_metadata(&self) -> Cow<'_, AsymmetricSigningKeyMetadata> {
        self.inner.asymmetric_key_metadata()
    }

    fn key_metadata_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Cow<'_, AsymmetricSigningKeyMetadata>> {
        self.inner.key_metadata_by_thumbprint(thumbprint)
    }

    async fn sign_by_thumbprint(
        &self,
        input: &[u8],
        thumbprint: &str,
    ) -> Result<Vec<u8>, SignByThumbprintError<Self::Error>> {
        self.inner.sign_by_thumbprint(input, thumbprint).await
    }
}

impl JwsSigner for BoxedAsymmetricJwsSigner {
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
