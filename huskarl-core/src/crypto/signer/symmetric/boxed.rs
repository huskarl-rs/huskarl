use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::signer::{JwsSigner, symmetric::JwsSignerSelector},
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// Boxed JWS signer selector for symmetric keys.
#[derive(Debug, Clone)]
pub struct BoxedJwsSignerSelector {
    inner: Arc<dyn DynJwsSignerSelector>,
}

impl BoxedJwsSignerSelector {
    /// Create a boxed signer selector from a non-boxed.
    pub fn new<Sgn: JwsSignerSelector + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

pub(in crate::crypto::signer) trait DynJwsSignerSelector:
    std::fmt::Debug + MaybeSendSync
{
    fn select_signer(&self) -> BoxedJwsSigner;
}

impl<Sgn: JwsSignerSelector + 'static> DynJwsSignerSelector for Sgn {
    fn select_signer(&self) -> BoxedJwsSigner {
        BoxedJwsSigner::new(self.select_signer())
    }
}

impl JwsSignerSelector for BoxedJwsSignerSelector {
    type Signer = BoxedJwsSigner;

    fn select_signer(&self) -> Self::Signer {
        self.inner.select_signer()
    }
}

/// Boxed JWS signer for symmetric keys.
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
pub(in crate::crypto::signer) trait DynJwsSigner:
    std::fmt::Debug + MaybeSendSync
{
    /// Returns the JWS algorithm for this signer.
    ///
    /// This is the algorithm identifier to use in the JWT `alg` header parameter.
    fn jws_algorithm(&self) -> Cow<'_, str>;

    /// Returns the key ID for this signer.
    ///
    /// This is specifically for use in the JWT `kid` header parameter.
    ///
    /// Note: The "natural" key ID is not always directly suitable as a
    /// `kid` value, and may require transformation before use.
    fn key_id(&self) -> Option<Cow<'_, str>>;

    /// Asynchronously signs the given input data and returns the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    fn sign<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>>;
}

impl<Sgn: JwsSigner> DynJwsSigner for Sgn {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        self.jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.key_id()
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>> {
        Box::pin(async { self.sign(input).await.map_err(BoxedError::from_err) })
    }
}

impl JwsSigner for BoxedJwsSigner {
    type Error = BoxedError;

    fn jws_algorithm(&self) -> Cow<'_, str> {
        self.inner.jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.key_id()
    }

    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.sign(input).await
    }
}
