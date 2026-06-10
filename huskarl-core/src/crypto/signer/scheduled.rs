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
