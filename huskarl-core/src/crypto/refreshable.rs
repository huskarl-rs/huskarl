//! Shared hot-swap mechanism backed by [`ArcSwap`].
//!
//! [`Refreshable`] holds a value behind an [`ArcSwap`] and can atomically
//! replace it by re-invoking a factory closure. Concurrent refresh attempts
//! are serialised so that only one factory call runs at a time; waiters that
//! arrive while a refresh is in flight adopt the result.

use std::{pin::Pin, sync::Arc};

use arc_swap::ArcSwap;

use crate::{
    error::Error,
    platform::{Duration, Instant, MaybeSendFuture, MaybeSendSync},
};

/// Object-safe wrapper for a `MaybeSendSync` factory closure.
pub(crate) trait RefreshFactory<V>: MaybeSendSync {
    fn call(&self) -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>>;
}

impl<V, F> RefreshFactory<V> for F
where
    F: Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>> + MaybeSendSync,
{
    fn call(&self) -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>> {
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
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>>
        + MaybeSendSync
        + 'static,
    ) -> Result<Self, Error> {
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
    ///
    /// Returns `Ok(true)` if a new value was fetched by this call, or `Ok(false)`
    /// if another task already refreshed concurrently.
    pub(crate) async fn refresh(&self) -> Result<bool, Error> {
        let cur = self.value.load_full();
        let _lock = self.refresh_lock.lock().await;
        if !Arc::ptr_eq(&self.value.load_full(), &cur) {
            // Another task already refreshed while we were waiting for the lock.
            return Ok(false);
        }

        let new_value = self.factory.call().await?;
        self.value.store(Arc::new(new_value));
        Ok(true)
    }

    /// Non-blocking, single-flight refresh: if no refresh is in flight, fetch a
    /// new value and swap it in; if another caller already holds the refresh lock,
    /// return immediately without waiting.
    ///
    /// Returns `Ok(true)` if this call fetched and swapped a new value, or
    /// `Ok(false)` if a refresh was already in flight (or had just completed) and
    /// this call did nothing.
    pub(crate) async fn try_refresh_ahead(&self) -> Result<bool, Error> {
        let cur = self.value.load_full();
        let Ok(_lock) = self.refresh_lock.try_lock() else {
            // Another caller is refreshing; don't block, keep serving `cur`.
            return Ok(false);
        };
        if !Arc::ptr_eq(&self.value.load_full(), &cur) {
            // A refresh landed between our load and taking the lock.
            return Ok(false);
        }

        let new_value = self.factory.call().await?;
        self.value.store(Arc::new(new_value));
        Ok(true)
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
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>>
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
    ) -> Result<Self, Error> {
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

    /// The abuse-prevention gate — *may* a refresh be attempted right now, quite
    /// apart from whether the value is stale? Evaluated against an already-held
    /// timestamp snapshot. Shared by both refresh paths so neither can hammer the
    /// upstream faster than `min_refresh_interval`, and both honour the
    /// post-failure `failure_backoff`.
    ///
    /// Deliberately does **not** consider the TTL: the TTL is a *staleness* bound
    /// (how old a cached value may get before the read path reloads it), not an
    /// attempt-permission. Folding it in here is what would neuter the
    /// miss-triggered reload — see [`should_refresh_stale`](Self::should_refresh_stale)
    /// versus [`policy_permits_miss_refresh`](Self::policy_permits_miss_refresh).
    fn policy_permits_attempt(&self, now: Instant, ts: &RefreshTimestamps) -> bool {
        // Rate limit: hard floor on refresh frequency.
        if ts
            .last_refresh_attempt
            .and_then(|t| now.checked_duration_since(t))
            .is_some_and(|elapsed| elapsed < self.min_refresh_interval)
        {
            return false;
        }

        // Failure backoff: hold off after a recent failed attempt.
        if ts
            .last_failed_refresh
            .and_then(|t| now.checked_duration_since(t))
            .is_some_and(|elapsed| elapsed < self.failure_backoff)
        {
            return false;
        }

        true
    }

    /// Read-path gate: the value has outlived its TTL *and* policy permits an
    /// attempt. Drives [`poll_refresh_ahead`](Self::poll_refresh_ahead), bounding
    /// the value's age to the TTL so a *removed* key cannot outlive it.
    fn should_refresh_stale(&self) -> bool {
        let now = Instant::now();
        let ts = self
            .timestamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Not stale yet — the read path leaves a within-TTL value alone.
        if now
            .checked_duration_since(ts.last_refreshed)
            .is_some_and(|elapsed| elapsed < self.ttl)
        {
            return false;
        }

        self.policy_permits_attempt(now, &ts)
    }

    /// Miss-path gate: policy permits an attempt, *regardless of staleness*. A
    /// miss — no held key matched an arriving token — is itself the trigger (a
    /// key was likely *added* upstream), so the TTL, which bounds removals, must
    /// not gate it; only the abuse-prevention floor does. This is what makes the
    /// miss-triggered reload a genuine fast path for key additions *within* the
    /// TTL window, rather than a no-op until the TTL happens to expire.
    fn policy_permits_miss_refresh(&self) -> bool {
        let now = Instant::now();
        let ts = self
            .timestamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        self.policy_permits_attempt(now, &ts)
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

    /// Manual staleness poll (blocking): if the value has outlived its TTL *and*
    /// the rate-limit/backoff policy permits, reload it and wait for the result; a
    /// within-TTL value is left alone. This is the *outbound* manual-refresh hook
    /// (e.g. the inherent `ScheduledRefreshSigner::refresh_if_stale` /
    /// `ScheduledRefreshCipher::refresh_if_stale`), where "refresh if warranted"
    /// means "refresh if stale" because there is no miss to react to. The *inbound*
    /// miss path uses [`try_refresh_on_miss`](Self::try_refresh_on_miss) instead,
    /// which is deliberately **not** TTL-gated. Returns `true` if this call
    /// refreshed successfully, `false` if the policy blocked it or it failed.
    pub(crate) async fn refresh_if_stale(&self) -> bool {
        if !self.should_refresh_stale() {
            return false;
        }

        let success = self.inner.refresh().await.is_ok();
        self.record_refresh(success);
        success
    }

    /// Miss-triggered refresh (blocking): a held-key *miss* asks for a reload.
    /// Gated by the rate-limit/backoff policy but **not** the TTL — a miss is
    /// itself the trigger (a key was likely *added* upstream), so a fresh-but-
    /// incomplete keyset must still be allowed to reload and pick it up. This is
    /// what makes [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier)
    /// and [`RetryingDecryptor`](crate::crypto::cipher::RetryingDecryptor) a
    /// genuine fast path for key additions *within* the TTL window, rather than a
    /// no-op until the TTL happens to expire. Returns `true` if this call
    /// refreshed successfully, `false` if the policy blocked it or it failed.
    pub(crate) async fn try_refresh_on_miss(&self) -> bool {
        if !self.policy_permits_miss_refresh() {
            return false;
        }

        let success = self.inner.refresh().await.is_ok();
        self.record_refresh(success);
        success
    }

    /// Policy-gated, non-blocking, single-flight refresh-ahead for the read path.
    ///
    /// If the value is stale (its TTL has elapsed) and the rate-limit/backoff
    /// policy allows, the first caller to observe the staleness reloads it in
    /// place while concurrent callers return immediately and keep serving the
    /// current value. This bounds a cached value to its TTL — so a retired key
    /// cannot outlive it — with no background task: the reload is driven by
    /// whichever read first crosses the TTL.
    pub(crate) async fn poll_refresh_ahead(&self) {
        if !self.should_refresh_stale() {
            return;
        }
        // This `.await` is the seam for a future opt-in *async* mode: rather than
        // the elected caller blocking here on the fetch, it could hand the refresh
        // to a runtime spawn and return immediately, so the invoking request also
        // continues (serving the still-in-TTL keyset) while the reload lands for
        // later reads. That needs an `Arc`-shared inner to own the detached future
        // and a runtime-agnostic spawner, so it stays opt-in and out of the
        // default/wasm build; the single-flight lock keeps it duplicate-free.
        match self.inner.try_refresh_ahead().await {
            Ok(true) => self.record_refresh(true),
            // Another caller won the single-flight; let them record the attempt.
            Ok(false) => {}
            Err(_) => self.record_refresh(false),
        }
    }

    /// Forces a refresh bypassing the scheduling policy, but still records the outcome.
    pub(crate) async fn refresh(&self) -> Result<bool, Error> {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A factory that counts how many times it has been invoked and returns that
    /// count as the value, so a test can assert exactly how many reloads ran.
    fn counting_factory(
        calls: Arc<AtomicUsize>,
    ) -> impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<usize, Error>>>>
    + MaybeSendSync
    + 'static {
        move || {
            let calls = Arc::clone(&calls);
            Box::pin(async move { Ok(calls.fetch_add(1, Ordering::SeqCst)) })
        }
    }

    async fn scheduled(
        calls: Arc<AtomicUsize>,
        ttl: Duration,
        min_refresh_interval: Duration,
        failure_backoff: Duration,
    ) -> ScheduledRefreshable<usize> {
        ScheduledRefreshable::builder()
            .factory(counting_factory(calls))
            .ttl(ttl)
            .min_refresh_interval(min_refresh_interval)
            .failure_backoff(failure_backoff)
            .build()
            .await
            .unwrap()
    }

    /// The regression guard for the miss/TTL split: a miss-triggered
    /// `try_refresh_on_miss` must fetch even while the value is well within its
    /// TTL. Before the split the miss path shared the read path's TTL gate and
    /// returned `false` here — silently neutering the additions fast path for the
    /// whole TTL window.
    #[tokio::test]
    async fn miss_refresh_fetches_within_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        // Large TTL (nowhere near stale), no rate limit.
        let sr = scheduled(
            calls.clone(),
            Duration::from_hours(1),
            Duration::ZERO,
            Duration::ZERO,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "initial build");

        assert!(
            sr.try_refresh_on_miss().await,
            "a miss reloads despite being within TTL"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the miss drove one reload");
    }

    /// The miss path is still rate-limited: `min_refresh_interval` caps how often
    /// a burst of misses can fetch, so bogus unknown-kid tokens can't hammer the
    /// upstream.
    #[tokio::test]
    async fn miss_refresh_is_rate_limited() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sr = scheduled(
            calls.clone(),
            Duration::from_hours(1),
            Duration::from_hours(1),
            Duration::ZERO,
        )
        .await;

        assert!(sr.try_refresh_on_miss().await, "first miss fetches");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            !sr.try_refresh_on_miss().await,
            "a second miss within min_refresh_interval is blocked"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "no extra fetch");
    }

    /// The manual `refresh_if_stale` stays TTL-gated (the outbound staleness poll
    /// used by the inherent `ScheduledRefreshSigner`/`ScheduledRefreshCipher`
    /// methods): a fresh value is left alone, and it fires once the value is stale.
    /// This is the sibling of the miss path and must not inherit its TTL-bypass.
    #[tokio::test]
    async fn refresh_if_stale_is_ttl_gated() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fresh = scheduled(
            calls.clone(),
            Duration::from_hours(1),
            Duration::ZERO,
            Duration::ZERO,
        )
        .await;
        assert!(
            !fresh.refresh_if_stale().await,
            "refresh_if_stale leaves a within-TTL value alone"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no fetch while fresh");

        let stale_calls = Arc::new(AtomicUsize::new(0));
        let stale = scheduled(
            stale_calls.clone(),
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
        )
        .await;
        assert!(
            stale.refresh_if_stale().await,
            "refresh_if_stale fires when stale"
        );
        assert_eq!(stale_calls.load(Ordering::SeqCst), 2);
    }

    /// The read path stays TTL-gated: a within-TTL value is not reloaded ahead.
    #[tokio::test]
    async fn read_path_skips_within_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sr = scheduled(
            calls.clone(),
            Duration::from_hours(1),
            Duration::ZERO,
            Duration::ZERO,
        )
        .await;

        sr.poll_refresh_ahead().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "fresh value is left alone by the read path"
        );
    }

    /// The read path reloads once the value is stale (TTL elapsed).
    #[tokio::test]
    async fn read_path_reloads_when_stale() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sr = scheduled(
            calls.clone(),
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
        )
        .await;

        sr.poll_refresh_ahead().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a stale value is reloaded on the read path"
        );
    }
}
