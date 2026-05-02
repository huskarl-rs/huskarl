//! Shared hot-swap mechanism backed by [`ArcSwap`].
//!
//! [`Refreshable`] holds a value behind an [`ArcSwap`] and can atomically
//! replace it by re-invoking a factory closure. Concurrent refresh attempts
//! are serialised so that only one factory call runs at a time; waiters that
//! arrive while a refresh is in flight adopt the result.

use std::{pin::Pin, sync::Arc};

use arc_swap::ArcSwap;

use crate::{
    BoxedError,
    platform::{Duration, Instant, MaybeSendFuture, MaybeSendSync},
};

/// Object-safe wrapper for a `MaybeSendSync` factory closure.
pub(crate) trait RefreshFactory<V>: MaybeSendSync {
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

/// A value that can be atomically refreshed by re-invoking a factory closure.
pub(crate) struct Refreshable<V> {
    value: ArcSwap<V>,
    factory: Box<dyn RefreshFactory<V>>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl<V: std::fmt::Debug> std::fmt::Debug for Refreshable<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refreshable")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

#[bon::bon]
impl<V: std::fmt::Debug + MaybeSendSync + 'static> Refreshable<V> {
    /// Creates a new [`Refreshable`] using the given factory.
    ///
    /// The factory is called immediately to produce the initial value. The same factory
    /// is called on subsequent refreshes via [`refresh`](Self::refresh).
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub(crate) async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, BoxedError>>>>
        + MaybeSendSync
        + 'static,
    ) -> Result<Self, BoxedError> {
        let initial = factory().await?;
        Ok(Self {
            value: ArcSwap::from_pointee(initial),
            factory: Box::new(factory),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Refreshes the value by re-invoking the factory and atomically swapping
    /// the inner value.
    ///
    /// Concurrent callers are serialised — only one factory call runs at a time.
    /// If another task already refreshed while this one was waiting for the lock,
    /// the new value is adopted without a redundant fetch.
    pub(crate) async fn refresh(&self) -> Result<(), BoxedError> {
        let cur = self.value.load_full();
        let _lock = self.refresh_lock.lock().await;
        if !Arc::ptr_eq(&self.value.load_full(), &cur) {
            // Another task already refreshed while we were waiting for the lock.
            return Ok(());
        }

        let new_value = self.factory.call().await?;
        self.value.store(Arc::new(new_value));
        Ok(())
    }

    /// Returns a cheap guard reference to the current value.
    pub(crate) fn load(&self) -> arc_swap::Guard<Arc<V>> {
        self.value.load()
    }

    /// Returns a cloned `Arc` pointing to the current value.
    pub(crate) fn load_full(&self) -> Arc<V> {
        self.value.load_full()
    }
}

#[allow(clippy::struct_field_names)]
struct RefreshTimestamps {
    last_refreshed: Instant,
    last_failed_refresh: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
}

/// A [`Refreshable`] combined with TTL, failure-backoff, and rate-limiting policy.
pub(crate) struct ScheduledRefreshable<V> {
    inner: Refreshable<V>,
    ttl: Duration,
    failure_backoff: Duration,
    min_refresh_interval: Duration,
    timestamps: std::sync::Mutex<RefreshTimestamps>,
}

impl<V: std::fmt::Debug> std::fmt::Debug for ScheduledRefreshable<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledRefreshable")
            .field("inner", &self.inner)
            .field("ttl", &self.ttl)
            .field("failure_backoff", &self.failure_backoff)
            .finish_non_exhaustive()
    }
}

#[bon::bon]
impl<V: std::fmt::Debug + MaybeSendSync + 'static> ScheduledRefreshable<V> {
    /// Creates a new [`ScheduledRefreshable`] using the given factory and policy parameters.
    ///
    /// The factory is called immediately to produce the initial value.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub(crate) async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, BoxedError>>>>
        + MaybeSendSync
        + 'static,
        /// The time-to-live for the cached value.
        #[builder(default = Duration::from_hours(1))]
        ttl: Duration,
        /// The backoff duration after a failed refresh.
        #[builder(default = Duration::from_secs(30))]
        failure_backoff: Duration,
        /// Minimum time between any two refresh attempts, regardless of outcome.
        #[builder(default = Duration::from_mins(1))]
        min_refresh_interval: Duration,
    ) -> Result<Self, BoxedError> {
        let inner = Refreshable::builder().factory(factory).build().await?;
        Ok(Self {
            inner,
            ttl,
            failure_backoff,
            min_refresh_interval,
            timestamps: std::sync::Mutex::new(RefreshTimestamps {
                last_refreshed: Instant::now(),
                last_failed_refresh: None,
                last_refresh_attempt: None,
            }),
        })
    }

    fn should_refresh(&self) -> bool {
        let now = Instant::now();
        let ts = self
            .timestamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Rate limit: hard floor on refresh frequency
        if ts
            .last_refresh_attempt
            .and_then(|t| now.checked_duration_since(t))
            .is_some_and(|elapsed| elapsed < self.min_refresh_interval)
        {
            return false;
        }

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

        true
    }

    fn record_refresh(&self, success: bool) {
        let now = Instant::now();
        let mut ts = self
            .timestamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ts.last_refresh_attempt = Some(now);
        if success {
            ts.last_refreshed = now;
            ts.last_failed_refresh = None;
        } else {
            ts.last_failed_refresh = Some(now);
        }
    }

    /// Attempts a policy-gated refresh. Returns `true` if a refresh was performed
    /// and succeeded, `false` if the policy blocked the attempt or the refresh failed.
    pub(crate) async fn try_refresh(&self) -> bool {
        if !self.should_refresh() {
            return false;
        }

        let success = self.inner.refresh().await.is_ok();
        self.record_refresh(success);
        success
    }

    /// Forces a refresh bypassing the scheduling policy, but still records the outcome.
    pub(crate) async fn refresh(&self) -> Result<(), BoxedError> {
        let result = self.inner.refresh().await;
        self.record_refresh(result.is_ok());
        result
    }

    /// Returns a cheap guard reference to the current value.
    pub(crate) fn load(&self) -> arc_swap::Guard<Arc<V>> {
        self.inner.load()
    }

    /// Returns a cloned `Arc` pointing to the current value.
    pub(crate) fn load_full(&self) -> Arc<V> {
        self.inner.load_full()
    }
}
