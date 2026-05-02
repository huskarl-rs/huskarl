use std::pin::Pin;

use crate::{
    BoxedError,
    crypto::{
        KeyMatchStrength,
        refreshable::ScheduledRefreshable,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    platform::{Duration, MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsVerifier`] that wraps a `ScheduledRefreshable` and gates
/// [`try_refresh`](JwsVerifier::try_refresh) with TTL and failure-backoff policy.
///
/// This is the **policy** layer — it tracks when the last successful and failed refreshes
/// occurred and only delegates to the inner `ScheduledRefreshable`'s refresh when
/// the TTL has expired and the failure backoff has elapsed.
pub struct ScheduledRefreshVerifier<V> {
    inner: ScheduledRefreshable<V>,
}

impl<V: std::fmt::Debug> std::fmt::Debug for ScheduledRefreshVerifier<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledRefreshVerifier")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

#[bon::bon]
impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> ScheduledRefreshVerifier<V> {
    /// Creates a new [`ScheduledRefreshVerifier`] using the given factory and policy parameters.
    ///
    /// The factory is called immediately to produce the initial verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, BoxedError>>>>
        + MaybeSendSync
        + 'static,
        /// The time-to-live for the cached verifier.
        #[builder(default = Duration::from_hours(1))]
        ttl: Duration,
        /// The backoff duration after a failed refresh.
        #[builder(default = Duration::from_secs(30))]
        failure_backoff: Duration,
        /// Minimum time between any two refresh attempts, regardless of outcome.
        /// Acts as a hard ceiling on refresh frequency for abuse prevention.
        #[builder(default = Duration::from_mins(1))]
        min_refresh_interval: Duration,
    ) -> Result<Self, BoxedError> {
        let inner = ScheduledRefreshable::builder()
            .factory(factory)
            .ttl(ttl)
            .failure_backoff(failure_backoff)
            .min_refresh_interval(min_refresh_interval)
            .build()
            .await?;
        Ok(Self { inner })
    }
}

impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> JwsVerifier
    for ScheduledRefreshVerifier<V>
{
    type Error = V::Error;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.load().key_match(key_match)
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<Self::Error>> {
        self.inner
            .load_full()
            .verify(input, signature, key_match)
            .await
    }

    async fn try_refresh(&self) -> bool {
        self.inner.try_refresh().await
    }
}
