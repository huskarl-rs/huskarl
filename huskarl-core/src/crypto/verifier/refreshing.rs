use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;

use crate::{
    BoxedError,
    crypto::verifier::{JwsVerifier, KeyMatch, KeyMatchStrength, VerifyError},
    platform::{Duration, Instant, MaybeSendFuture, MaybeSendSync},
};

/// Object-safe wrapper for a `MaybeSendSync` factory closure that builds a verifier.
///
/// This trait exists because Rust only permits auto traits (`Send`, `Sync`) as additional
/// bounds in a `dyn` type. By using `MaybeSendSync` as a supertrait of this named trait,
/// `Box<dyn RefreshFactory<V>>` is valid on all platforms without extra bounds in the `dyn`
/// position.
trait RefreshFactory<V>: MaybeSendSync {
    fn call(&self) -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, BoxedError>>>>;
}

impl<V, F> RefreshFactory<V> for F
where
    F: Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, BoxedError>>>> + MaybeSendSync,
{
    fn call(&self) -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, BoxedError>>>> {
        self()
    }
}

struct RefreshTimestamps {
    last_refreshed: Instant,
    last_failed_refresh: Option<Instant>,
}

/// A [`JwsVerifier`] that wraps another verifier and reloads it on demand via
/// [`try_refresh`](crate::crypto::verifier::JwsVerifier::try_refresh).
///
/// Key material is reloaded by re-invoking the factory closure, subject to a TTL and a
/// failure backoff. Concurrent reload attempts are serialised — only one fetch runs at a
/// time and other waiters adopt the result.
pub struct RefreshingVerifier<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> {
    verifier: ArcSwap<V>,
    factory: Box<dyn RefreshFactory<V>>,
    ttl: Duration,
    failure_backoff: Duration,
    timestamps: Mutex<RefreshTimestamps>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> std::fmt::Debug
    for RefreshingVerifier<V>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshingVerifier")
            .field("verifier", &self.verifier)
            .field("ttl", &self.ttl)
            .field("failure_backoff", &self.failure_backoff)
            .finish_non_exhaustive()
    }
}

#[bon::bon]
impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> RefreshingVerifier<V> {
    /// Creates a new [`RefreshingVerifier`] using the given factory.
    ///
    /// The factory is called immediately to produce the initial verifier. The same factory
    /// is called on subsequent refreshes.
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
        #[builder(default = Duration::from_mins(5))]
        ttl: Duration,
        /// The backoff duration after a failed refresh.
        #[builder(default = Duration::from_secs(30))]
        failure_backoff: Duration,
    ) -> Result<Self, BoxedError> {
        let initial = factory().await?;
        Ok(Self {
            verifier: ArcSwap::from_pointee(initial),
            factory: Box::new(factory),
            ttl,
            failure_backoff,
            timestamps: Mutex::new(RefreshTimestamps {
                last_refreshed: Instant::now(),
                last_failed_refresh: None,
            }),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    async fn do_refresh(&self) -> bool {
        let now = Instant::now();

        {
            let ts = self.timestamps.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if now
                .checked_duration_since(ts.last_refreshed)
                .is_some_and(|elapsed| elapsed < self.ttl)
            {
                return false;
            }
            if ts
                .last_failed_refresh
                .and_then(|t| now.checked_duration_since(t))
                .is_some_and(|elapsed| elapsed < self.failure_backoff)
            {
                return false;
            }
        }

        let cur_verifier = self.verifier.load_full();
        let _lock = self.refresh_lock.lock().await;
        if !Arc::ptr_eq(&self.verifier.load_full(), &cur_verifier) {
            // Another task already refreshed the verifier while we were waiting for the lock.
            return true;
        }

        if let Ok(new_verifier) = self.factory.call().await {
            self.verifier.store(Arc::new(new_verifier));
            let mut ts = self.timestamps.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            ts.last_refreshed = Instant::now();
            ts.last_failed_refresh = None;
            true
        } else {
            let mut ts = self.timestamps.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            ts.last_failed_refresh = Some(Instant::now());
            false
        }
    }
}

impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync + 'static> JwsVerifier
    for RefreshingVerifier<V>
{
    type Error = V::Error;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.verifier.load().key_match(key_match)
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<Self::Error>> {
        self.verifier
            .load_full()
            .verify(input, signature, key_match)
            .await
    }

    async fn try_refresh(&self) -> bool {
        self.do_refresh().await
    }
}
