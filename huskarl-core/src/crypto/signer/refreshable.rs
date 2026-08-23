use std::{pin::Pin, sync::Arc};

use crate::{
    crypto::{
        refreshable::Refreshable,
        signer::{JwsSigner, JwsSignerSelector},
    },
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsSignerSelector`] that holds a hot-swappable signer selector behind an
/// [`ArcSwap`](arc_swap::ArcSwap).
///
/// This allows runtime rotation of signing keys (e.g. from a KMS or secret
/// manager) without restarting the application. It is the pure hot-swap variant
/// of [`ScheduledRefreshSigner`](super::ScheduledRefreshSigner), which adds a TTL
/// policy and reloads during selection — see that type for a construction
/// example; here you drive [`refresh`](Self::refresh) yourself.
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
        /// Asynchronous source of the current signer selector, called at
        /// construction and on each explicit refresh.
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<S, Error>>>>
        + MaybeSendSync
        + 'static,
    ) -> Result<Self, Error> {
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
    pub async fn refresh(&self) -> Result<bool, Error> {
        self.inner.refresh().await
    }
}

impl<S> JwsSignerSelector for RefreshableSigner<S>
where
    S: JwsSignerSelector + 'static,
{
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let selector = self.inner.load_full();
        Box::pin(async move { selector.select_signer().await })
    }
}

impl<S> super::AsymmetricJwsSignerSelector for RefreshableSigner<S>
where
    S: super::AsymmetricJwsSignerSelector + 'static,
{
    fn select_asymmetric_signer(
        &self,
    ) -> MaybeSendBoxFuture<'_, Arc<dyn super::AsymmetricJwsSigner>> {
        let selector = self.inner.load_full();
        Box::pin(async move { selector.select_asymmetric_signer().await })
    }

    fn select_signer_by_thumbprint<'a>(
        &'a self,
        thumbprint: &'a str,
    ) -> MaybeSendBoxFuture<'a, Option<Arc<dyn super::AsymmetricJwsSigner>>> {
        let selector = self.inner.load_full();
        Box::pin(async move { selector.select_signer_by_thumbprint(thumbprint).await })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{crypto::signer::JwsSigner, platform::MaybeSendBoxFuture};

    /// A signer that reports a fixed `kid` — used to observe which generation
    /// the refreshable selector currently holds.
    #[derive(Debug)]
    struct TaggedSigner {
        kid: String,
    }

    impl JwsSigner for TaggedSigner {
        fn jws_algorithm(&self) -> Cow<'_, str> {
            "ES256".into()
        }
        fn key_id(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(&self.kid))
        }
        fn sign<'a>(&'a self, _input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
            Box::pin(async { Ok(vec![0x01]) })
        }
    }

    #[derive(Debug)]
    struct GenSelector {
        kid: String,
    }

    impl JwsSignerSelector for GenSelector {
        fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
            let signer: Arc<dyn JwsSigner> = Arc::new(TaggedSigner {
                kid: self.kid.clone(),
            });
            Box::pin(async move { signer })
        }
    }

    /// A `RefreshableSigner` whose factory hands out `gen-0`, `gen-1`, … on each
    /// successive call.
    async fn generational_signer() -> RefreshableSigner<GenSelector> {
        let counter = Arc::new(AtomicUsize::new(0));
        RefreshableSigner::builder()
            .factory(move || {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    Ok(GenSelector {
                        kid: format!("gen-{n}"),
                    })
                })
            })
            .build()
            .await
            .unwrap()
    }

    async fn current_kid(signer: &RefreshableSigner<GenSelector>) -> Option<String> {
        signer
            .select_signer()
            .await
            .key_id()
            .map(std::borrow::Cow::into_owned)
    }

    #[tokio::test]
    async fn factory_runs_immediately_for_initial_value() {
        let signer = generational_signer().await;
        assert_eq!(current_kid(&signer).await.as_deref(), Some("gen-0"));
    }

    #[tokio::test]
    async fn refresh_swaps_in_the_next_generation() {
        let signer = generational_signer().await;
        assert_eq!(current_kid(&signer).await.as_deref(), Some("gen-0"));

        assert!(
            signer.refresh().await.unwrap(),
            "refresh fetched new material"
        );
        assert_eq!(current_kid(&signer).await.as_deref(), Some("gen-1"));
    }

    #[tokio::test]
    async fn clones_share_the_same_swappable_state() {
        let signer = generational_signer().await;
        let clone = signer.clone();

        // A refresh through the clone is visible through the original.
        clone.refresh().await.unwrap();
        assert_eq!(current_kid(&signer).await.as_deref(), Some("gen-1"));
        assert_eq!(current_kid(&clone).await.as_deref(), Some("gen-1"));
    }
}
