use std::{pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::{
        refreshable::Refreshable,
        signer::{JwsSigner, JwsSignerSelector},
    },
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsSignerSelector`] that holds a hot-swappable signer selector behind an
/// [`ArcSwap`](arc_swap::ArcSwap).
///
/// This allows runtime rotation of signing keys (e.g. from a KMS or secret
/// manager) without restarting the application.
///
/// All clones share the same underlying state, so a refresh performed through
/// any clone is visible to all others.
#[derive(Debug)]
pub struct RefreshableSigner<S> {
    inner: Arc<Refreshable<S>>,
}

impl<S> Clone for RefreshableSigner<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[bon::bon]
impl<S: std::fmt::Debug + MaybeSendSync + 'static> RefreshableSigner<S> {
    /// Creates a new [`RefreshableSigner`] using the given factory.
    ///
    /// The factory is called immediately to produce the initial signer selector.
    /// The same factory is called on subsequent refreshes via [`refresh`](Self::refresh).
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<S, BoxedError>>>>
        + MaybeSendSync
        + 'static,
    ) -> Result<Self, BoxedError> {
        let refreshable = Refreshable::builder().factory(factory).build().await?;
        Ok(Self {
            inner: Arc::new(refreshable),
        })
    }

    /// Refreshes the signer selector by re-invoking the factory and atomically
    /// swapping the inner value.
    ///
    /// Concurrent callers are serialised — only one factory call runs at a time.
    /// If another task already refreshed while this one was waiting for the lock,
    /// the new value is adopted without a redundant fetch.
    ///
    /// Returns `Ok(true)` if new key material was fetched by this call, or
    /// `Ok(false)` if another task already refreshed concurrently.
    ///
    /// # Errors
    ///
    /// Returns an error if the factory call fails.
    pub async fn refresh(&self) -> Result<bool, crate::BoxedError> {
        self.inner.refresh().await
    }
}

impl<S> JwsSignerSelector for RefreshableSigner<S>
where
    S: JwsSignerSelector + 'static,
{
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        self.inner.load().select_signer()
    }
}

impl<S> super::AsymmetricJwsSignerSelector for RefreshableSigner<S>
where
    S: super::AsymmetricJwsSignerSelector + 'static,
{
    fn select_asymmetric_signer(&self) -> Arc<dyn super::AsymmetricJwsSigner> {
        self.inner.load().select_asymmetric_signer()
    }

    fn select_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Arc<dyn super::AsymmetricJwsSigner>> {
        self.inner.load().select_signer_by_thumbprint(thumbprint)
    }
}
