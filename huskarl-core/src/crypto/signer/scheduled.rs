use std::{pin::Pin, sync::Arc};

use crate::{
    crypto::{
        refreshable::ScheduledRefreshable,
        signer::{JwsSigner, JwsSignerSelector},
    },
    error::Error,
    platform::{Duration, MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsSignerSelector`] that holds a hot-swappable signer behind a
/// `ScheduledRefreshable`, gating refresh attempts with TTL and
/// failure-backoff policy.
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

    /// Attempts a policy-gated refresh. Returns `true` if a refresh was performed
    /// and succeeded, `false` if the policy blocked the attempt or the refresh failed.
    pub async fn try_refresh(&self) -> bool {
        self.inner.try_refresh().await
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
    fn select_signer(&self) -> Arc<dyn JwsSigner> {
        self.inner.load().select_signer()
    }
}

impl<S> super::AsymmetricJwsSignerSelector for ScheduledRefreshSigner<S>
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
        fn select_signer(&self) -> Arc<dyn JwsSigner> {
            Arc::new(TaggedSigner {
                kid: self.kid.clone(),
            })
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

    fn current_kid(signer: &ScheduledRefreshSigner<GenSelector>) -> Option<String> {
        signer.select_signer().key_id().map(std::borrow::Cow::into_owned)
    }

    #[tokio::test]
    async fn forced_refresh_bypasses_policy() {
        // A long TTL would block a policy-gated refresh, but `refresh` is forced.
        let signer = generational_signer(Duration::from_hours(1), Duration::from_mins(1)).await;
        assert_eq!(current_kid(&signer).as_deref(), Some("gen-0"));

        assert!(signer.refresh().await.unwrap());
        assert_eq!(current_kid(&signer).as_deref(), Some("gen-1"));
    }

    /// `try_refresh` is gated by the TTL: a fresh value is left in place, a
    /// stale one (zero TTL) is swapped for the next generation.
    #[rstest]
    #[case::blocked_while_fresh(Duration::from_hours(1), false, "gen-0")]
    #[case::allowed_when_stale(Duration::from_secs(0), true, "gen-1")]
    #[tokio::test]
    async fn try_refresh_respects_ttl_policy(
        #[case] ttl: Duration,
        #[case] expected_refreshed: bool,
        #[case] expected_kid: &str,
    ) {
        let signer = generational_signer(ttl, Duration::from_secs(0)).await;
        assert_eq!(signer.try_refresh().await, expected_refreshed);
        assert_eq!(current_kid(&signer).as_deref(), Some(expected_kid));
    }
}
