use std::pin::Pin;

use crate::{
    BoxedError,
    crypto::{
        KeyMatchStrength,
        refreshable::Refreshable,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsVerifier`] that holds a hot-swappable verifier behind an [`ArcSwap`](arc_swap::ArcSwap).
///
/// This is the pure **mechanism** layer — it knows how to atomically swap the inner
/// verifier by re-invoking a factory closure. Concurrent refresh attempts are serialised
/// so that only one factory call runs at a time; waiters that arrive while a refresh is
/// in flight adopt the result.
///
/// Policy concerns (TTL, failure backoff) are handled by
/// [`ScheduledRefreshVerifier`](super::ScheduledRefreshVerifier), which wraps this type.
pub struct RefreshableVerifier<V> {
    inner: Refreshable<V>,
}

impl<V: std::fmt::Debug> std::fmt::Debug for RefreshableVerifier<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshableVerifier")
            .field("inner", &self.inner)
            .finish()
    }
}

#[bon::bon]
impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> RefreshableVerifier<V> {
    /// Creates a new [`RefreshableVerifier`] using the given factory.
    ///
    /// The factory is called immediately to produce the initial verifier. The same factory
    /// is called on subsequent refreshes via [`try_refresh`](JwsVerifier::try_refresh).
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, BoxedError>>>>
        + MaybeSendSync
        + 'static,
    ) -> Result<Self, BoxedError> {
        let inner = Refreshable::builder().factory(factory).build().await?;
        Ok(Self { inner })
    }

    /// Refreshes the verifier by re-invoking the factory and atomically swapping
    /// the inner value.
    ///
    /// Concurrent callers are serialised — only one factory call runs at a time.
    /// If another task already refreshed while this one was waiting for the lock,
    /// the new value is adopted without a redundant fetch.
    ///
    /// Returns `Ok(true)` if new key material was fetched by this call, or
    /// `Ok(false)` if another task already refreshed concurrently.
    /// Returns `Err` if the factory call failed.
    pub async fn refresh(&self) -> Result<bool, crate::BoxedError> {
        self.inner.refresh().await
    }
}

impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> JwsVerifier
    for RefreshableVerifier<V>
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
        self.refresh().await.unwrap_or(false)
    }
}
