use std::{borrow::Cow, sync::Arc};

use crate::{
    BoxedError,
    crypto::signer::{
        JwsSigner, JwsSignerSelector,
        asymmetric::{AsymmetricJwsSigner, AsymmetricJwsSignerSelector},
        symmetric::boxed::DynJwsSigner,
    },
    jwk::PublicJwk,
    platform::MaybeSendSync,
};

/// Boxed JWS signer selector for asymmetric keys.
#[derive(Debug, Clone)]
pub struct BoxedAsymmetricJwsSignerSelector {
    inner: Arc<dyn DynAsymmetricJwsSignerSelector>,
}

impl BoxedAsymmetricJwsSignerSelector {
    /// Create a boxed signer selector from a non-boxed.
    pub fn new<Sgn: AsymmetricJwsSignerSelector + 'static>(signer: Sgn) -> Self {
        Self {
            inner: Arc::new(signer),
        }
    }
}

pub(in crate::crypto::signer) trait DynAsymmetricJwsSignerSelector:
    std::fmt::Debug + MaybeSendSync
{
    fn select_signer(&self) -> BoxedAsymmetricJwsSigner;
    fn select_signer_by_thumbprint(&self, thumbprint: &str) -> Option<BoxedAsymmetricJwsSigner>;
}

impl<Sgn: AsymmetricJwsSignerSelector + 'static> DynAsymmetricJwsSignerSelector for Sgn {
    fn select_signer(&self) -> BoxedAsymmetricJwsSigner {
        BoxedAsymmetricJwsSigner::new(self.select_signer())
    }

    fn select_signer_by_thumbprint(&self, thumbprint: &str) -> Option<BoxedAsymmetricJwsSigner> {
        self.select_signer_by_thumbprint(thumbprint)
            .map(BoxedAsymmetricJwsSigner::new)
    }
}

impl JwsSignerSelector for BoxedAsymmetricJwsSignerSelector {
    type Signer = BoxedAsymmetricJwsSigner;

    fn select_signer(&self) -> BoxedAsymmetricJwsSigner {
        self.inner.select_signer()
    }
}

impl AsymmetricJwsSignerSelector for BoxedAsymmetricJwsSignerSelector {
    fn select_signer_by_thumbprint(&self, thumbprint: &str) -> Option<BoxedAsymmetricJwsSigner> {
        self.inner.select_signer_by_thumbprint(thumbprint)
    }
}

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
trait DynAsymmetricJwsSigner: DynJwsSigner {
    // AsymmetricJwsSigner methods
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk>;
}

impl<Sgn: AsymmetricJwsSigner + DynJwsSigner> DynAsymmetricJwsSigner for Sgn {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        self.public_key_jwk()
    }
}

impl AsymmetricJwsSigner for BoxedAsymmetricJwsSigner {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        self.inner.public_key_jwk()
    }
}

impl JwsSigner for BoxedAsymmetricJwsSigner {
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
