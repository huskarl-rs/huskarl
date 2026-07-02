use std::{pin::Pin, sync::Arc};

use crate::{
    crypto::{
        refreshable::ScheduledRefreshable,
        signer::{JwsSigner, JwsSignerSelector},
    },
    error::Error,
    platform::{Duration, MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsSignerSelector`] that bounds the age of its signing key to a TTL by
/// reloading *during selection* — the outbound analogue of
/// [`ScheduledRefreshVerifier`](crate::crypto::verifier::ScheduledRefreshVerifier)'s
/// read-path reload.
///
/// Each selection ([`select_signer`](JwsSignerSelector::select_signer) and the
/// asymmetric variants) reloads the key if it has outlived its TTL (single-flight,
/// non-blocking for concurrent callers), then hands back a frozen snapshot — so a
/// current key comes for free, with no `refresh_if_stale`-before-sign step to forget.
/// [`refresh`](Self::refresh) forces an immediate reload on an explicit rotation.
///
/// All clones share the same underlying state, so a refresh performed through
/// any clone is visible to all others.
///
/// # Example
///
/// ```
/// # use std::borrow::Cow;
/// # use std::sync::Arc;
/// # use huskarl_core::crypto::signer::{JwsSigner, JwsSignerSelector, ScheduledRefreshSigner};
/// # use huskarl_core::error::Error;
/// # use huskarl_core::platform::{Duration, MaybeSendBoxFuture};
/// # // Stand-ins for the signer + selector a crypto backend / KMS provides.
/// # #[derive(Debug)] struct BackendSigner;
/// # impl JwsSigner for BackendSigner {
/// #     fn jws_algorithm(&self) -> Cow<'_, str> { "ES256".into() }
/// #     fn key_id(&self) -> Option<Cow<'_, str>> { None }
/// #     fn sign<'a>(&'a self, _input: &'a [u8]) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
/// #         Box::pin(async { Ok(vec![]) })
/// #     }
/// # }
/// # #[derive(Debug)] struct BackendSelector;
/// # impl JwsSignerSelector for BackendSelector {
/// #     fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
/// #         Box::pin(async { Arc::new(BackendSigner) as Arc<dyn JwsSigner> })
/// #     }
/// # }
/// # async fn example() -> Result<(), Error> {
/// // The factory re-fetches the key material (e.g. from a KMS) on each reload.
/// let signer = ScheduledRefreshSigner::builder()
///     .ttl(Duration::from_secs(5 * 60))
///     .factory(|| Box::pin(async { Ok(BackendSelector) }))
///     .build()
///     .await?;
///
/// // Selecting reloads the key if it has outlived the TTL, then hands back a
/// // frozen snapshot to sign with — no "refresh before you sign" step to forget.
/// let current = signer.select_signer().await;
/// # let _ = current;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ScheduledRefreshSigner<S> {
    inner: Arc<ScheduledRefreshable<S>>,
}

impl<S> Clone for ScheduledRefreshSigner<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[bon::bon]
impl<S: std::fmt::Debug + MaybeSendSync + 'static> ScheduledRefreshSigner<S> {
    /// Creates a new [`ScheduledRefreshSigner`] using the given factory and policy parameters.
    ///
    /// The factory is called immediately to produce the initial signer selector.
    /// The same factory is called on subsequent refreshes.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<S, Error>>>>
        + MaybeSendSync
        + 'static,
        /// The time-to-live for the cached signer.
        #[builder(default = Duration::from_hours(1))]
        ttl: Duration,
        /// The backoff duration after a failed refresh.
        #[builder(default = Duration::from_secs(30))]
        failure_backoff: Duration,
        /// Minimum time between any two refresh attempts, regardless of outcome.
        #[builder(default = Duration::from_mins(1))]
        min_refresh_interval: Duration,
    ) -> Result<Self, Error> {
        let inner = ScheduledRefreshable::builder()
            .factory(factory)
            .ttl(ttl)
            .failure_backoff(failure_backoff)
            .min_refresh_interval(min_refresh_interval)
            .build()
            .await?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Reloads the signing key if it has outlived its TTL and the
    /// rate-limit/backoff policy permits; a within-TTL key is left in place.
    /// Blocking.
    ///
    /// A manual staleness poll:
    /// [`select_signer`](JwsSignerSelector::select_signer) already reloads a stale
    /// key during selection, so this only pre-warms the key ahead of a
    /// latency-sensitive sign. [`refresh`](Self::refresh) reloads unconditionally.
    ///
    /// Returns `true` if this call refreshed successfully, `false` if the policy
    /// blocked it or the refresh failed.
    pub async fn refresh_if_stale(&self) -> bool {
        self.inner.refresh_if_stale().await
    }

    /// Forces a refresh bypassing the scheduling policy, but still records the outcome.
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

impl<S> JwsSignerSelector for ScheduledRefreshSigner<S>
where
    S: JwsSignerSelector + 'static,
{
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        Box::pin(async move {
            self.inner.poll_refresh_ahead().await;
            let selector = self.inner.load_full();
            selector.select_signer().await
        })
    }
}

impl<S> super::AsymmetricJwsSignerSelector for ScheduledRefreshSigner<S>
where
    S: super::AsymmetricJwsSignerSelector + 'static,
{
    fn select_asymmetric_signer(
        &self,
    ) -> MaybeSendBoxFuture<'_, Arc<dyn super::AsymmetricJwsSigner>> {
        Box::pin(async move {
            self.inner.poll_refresh_ahead().await;
            let selector = self.inner.load_full();
            selector.select_asymmetric_signer().await
        })
    }

    fn select_signer_by_thumbprint<'a>(
        &'a self,
        thumbprint: &'a str,
    ) -> MaybeSendBoxFuture<'a, Option<Arc<dyn super::AsymmetricJwsSigner>>> {
        Box::pin(async move {
            self.inner.poll_refresh_ahead().await;
            let selector = self.inner.load_full();
            selector.select_signer_by_thumbprint(thumbprint).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use rstest::rstest;

    use super::*;
    use crate::{crypto::signer::JwsSigner, platform::MaybeSendBoxFuture};

    /// A signer that reports a fixed `kid` — used to observe which generation
    /// the scheduled selector currently holds.
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

    /// Builds a generational signer (`gen-0`, `gen-1`, …) with the given policy.
    async fn generational_signer(
        ttl: Duration,
        min_refresh_interval: Duration,
    ) -> ScheduledRefreshSigner<GenSelector> {
        let counter = Arc::new(AtomicUsize::new(0));
        ScheduledRefreshSigner::builder()
            .factory(move || {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    Ok(GenSelector {
                        kid: format!("gen-{n}"),
                    })
                })
            })
            .ttl(ttl)
            .min_refresh_interval(min_refresh_interval)
            .build()
            .await
            .unwrap()
    }

    /// Reads the currently-held generation *without* triggering a refresh, so
    /// tests can observe policy behaviour in isolation (a plain `select_signer`
    /// would itself reload when stale).
    async fn current_kid(signer: &ScheduledRefreshSigner<GenSelector>) -> Option<String> {
        signer
            .inner
            .load_full()
            .select_signer()
            .await
            .key_id()
            .map(std::borrow::Cow::into_owned)
    }

    #[tokio::test]
    async fn forced_refresh_bypasses_policy() {
        // A long TTL would block a policy-gated refresh, but `refresh` is forced.
        let signer = generational_signer(Duration::from_hours(1), Duration::from_mins(1)).await;
        assert_eq!(current_kid(&signer).await.as_deref(), Some("gen-0"));

        assert!(signer.refresh().await.unwrap());
        assert_eq!(current_kid(&signer).await.as_deref(), Some("gen-1"));
    }

    /// `refresh_if_stale` is gated by the TTL: a fresh value is left in place, a
    /// stale one (zero TTL) is swapped for the next generation.
    #[rstest]
    #[case::blocked_while_fresh(Duration::from_hours(1), false, "gen-0")]
    #[case::allowed_when_stale(Duration::from_secs(0), true, "gen-1")]
    #[tokio::test]
    async fn refresh_if_stale_respects_ttl_policy(
        #[case] ttl: Duration,
        #[case] expected_refreshed: bool,
        #[case] expected_kid: &str,
    ) {
        let signer = generational_signer(ttl, Duration::from_secs(0)).await;
        assert_eq!(signer.refresh_if_stale().await, expected_refreshed);
        assert_eq!(current_kid(&signer).await.as_deref(), Some(expected_kid));
    }
}
