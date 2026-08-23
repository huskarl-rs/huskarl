//! Shared hot-swap mechanism backed by [`ArcSwap`].
//!
//! [`Refreshable`] holds a value behind an [`ArcSwap`] and can atomically
//! replace it by re-invoking a factory closure. Concurrent refresh attempts
//! are serialised so that only one factory call runs at a time; waiters that
//! arrive while a refresh is in flight adopt the result.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

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

    /// Seeds an explicit initial value without calling the factory (so it cannot
    /// fail). The seam for a tolerated cold start: a placeholder value now,
    /// refreshed through `factory` later.
    pub(crate) fn from_seed(
        seed: V,
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>>
        + MaybeSendSync
        + 'static,
    ) -> Self {
        Self {
            value: ArcSwap::from_pointee(seed),
            factory: Box::new(factory),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
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
        match self.refresh_gated(|| true, |_| {}).await? {
            GatedRefresh::Refreshed => Ok(true),
            GatedRefresh::Adopted | GatedRefresh::Blocked => Ok(false),
        }
    }

    /// [`refresh`](Self::refresh), but with a `gate` evaluated **after** the
    /// single-flight lock is acquired (and after the adopt-concurrent check):
    /// the factory only runs if the gate returns `true`. The factory's outcome
    /// is reported to `record` **while the lock is still held**, so whatever
    /// state the gate consults is already up to date when the next queued
    /// waiter's gate runs.
    ///
    /// This matters when the fetch can fail: a failed fetch stores nothing, so
    /// the pointer-swap dedup does not fire for it, and every waiter queued on
    /// the lock would otherwise re-invoke the factory in turn. A gate that
    /// consults (and claims) attempt state under the lock — kept current by
    /// `record` — lets the first waiter's failed attempt block the rest of the
    /// queue.
    pub(crate) async fn refresh_gated(
        &self,
        gate: impl FnOnce() -> bool,
        record: impl FnOnce(bool),
    ) -> Result<GatedRefresh, Error> {
        let cur = self.value.load_full();
        let _lock = self.refresh_lock.lock().await;
        if !Arc::ptr_eq(&self.value.load_full(), &cur) {
            // Another task already refreshed while we were waiting for the lock.
            return Ok(GatedRefresh::Adopted);
        }
        if !gate() {
            return Ok(GatedRefresh::Blocked);
        }

        match self.factory.call().await {
            Ok(new_value) => {
                self.value.store(Arc::new(new_value));
                record(true);
                Ok(GatedRefresh::Refreshed)
            }
            Err(e) => {
                record(false);
                Err(e)
            }
        }
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

/// Outcome of a [`Refreshable::refresh_gated`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatedRefresh {
    /// This call invoked the factory and swapped in a new value.
    Refreshed,
    /// Another task refreshed while this one waited for the lock; its value
    /// was adopted without a redundant fetch.
    Adopted,
    /// The gate declined the attempt once the lock was held.
    Blocked,
}

#[allow(clippy::struct_field_names)]
struct RefreshTimestamps {
    /// When a value last loaded successfully. `None` = never (cold seed): reads as
    /// infinitely stale and selects the cold-backoff regime.
    last_refreshed: Option<Instant>,
    last_failed_refresh: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
    /// Consecutive failures while cold; escalates the cold backoff, reset on success.
    consecutive_cold_failures: u32,
}

/// A [`Refreshable`] combined with TTL, failure-backoff, and rate-limiting policy.
pub(crate) struct ScheduledRefreshable<V> {
    inner: Refreshable<V>,
    ttl: Duration,
    failure_backoff: Duration,
    min_refresh_interval: Duration,
    /// Backoff floor while cold (no value has ever loaded). Escalates per
    /// consecutive failure, capped at `failure_backoff`.
    cold_backoff: Duration,
    /// Lock-free mirror of `timestamps.last_refreshed.is_none()` for the per-verify
    /// [`is_cold`](Self::is_cold) fast path. Monotonic: cleared once a value loads,
    /// never re-set.
    cold: AtomicBool,
    timestamps: std::sync::Mutex<RefreshTimestamps>,
}

impl<V: std::fmt::Debug> std::fmt::Debug for ScheduledRefreshable<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledRefreshable")
            .field("inner", &self.inner)
            .field("ttl", &self.ttl)
            .field("failure_backoff", &self.failure_backoff)
            .field("cold_backoff", &self.cold_backoff)
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
        /// Backoff floor while cold, before any value has loaded. Escalates per
        /// consecutive failure up to `failure_backoff`.
        #[builder(default = Duration::from_millis(250))]
        cold_backoff: Duration,
        /// Opt-in placeholder used if the initial fetch fails: construction then
        /// succeeds in a cold state that self-heals, rather than failing. `None`
        /// (the default) keeps a failed initial fetch fatal.
        fallback: Option<V>,
    ) -> Result<Self, Error> {
        let now = Instant::now();
        let (initial, timestamps) = match (factory().await, fallback) {
            (Ok(value), _) => (
                value,
                RefreshTimestamps {
                    last_refreshed: Some(now),
                    last_failed_refresh: None,
                    last_refresh_attempt: None,
                    consecutive_cold_failures: 0,
                },
            ),
            // Tolerated cold start: seed the placeholder and stamp the failed
            // build as the last failure so the first retry waits one `cold_backoff`
            // (the floor). Escalation begins only once a cold *retry* also fails.
            (Err(_), Some(seed)) => (
                seed,
                RefreshTimestamps {
                    last_refreshed: None,
                    last_failed_refresh: Some(now),
                    last_refresh_attempt: Some(now),
                    consecutive_cold_failures: 0,
                },
            ),
            (Err(e), None) => return Err(e),
        };
        let cold = AtomicBool::new(timestamps.last_refreshed.is_none());
        Ok(Self {
            inner: Refreshable::from_seed(initial, factory),
            ttl,
            failure_backoff,
            min_refresh_interval,
            cold_backoff,
            cold,
            timestamps: std::sync::Mutex::new(timestamps),
        })
    }

    /// Whether no value has ever loaded (the initial fetch failed and a placeholder
    /// was seeded). Drives the caller's cold-vs-warm read path. Lock-free: a stale
    /// `true` self-corrects, since the caller re-checks after the miss-refresh.
    pub(crate) fn is_cold(&self) -> bool {
        self.cold.load(Ordering::Acquire)
    }

    /// The abuse-prevention gate — *may* a refresh be attempted right now, quite
    /// apart from whether the value is stale? Evaluated against an already-held
    /// timestamp snapshot. Shared by both refresh paths so neither can hammer the
    /// upstream faster than `min_refresh_interval`, and both honour the
    /// post-failure `failure_backoff`.
    ///
    /// Does **not** consider the TTL — that is a *staleness* bound, not an
    /// attempt-permission. See [`should_refresh_stale`](Self::should_refresh_stale)
    /// versus [`policy_permits_miss_refresh`](Self::policy_permits_miss_refresh).
    fn policy_permits_attempt(&self, now: Instant, ts: &RefreshTimestamps) -> bool {
        // Cold: no value has ever loaded, so every request is failing now — recover
        // far more urgently than the warm `failure_backoff`/`min_refresh_interval`,
        // which assume a good value is still being served. The first retry waits
        // one `cold_backoff` (the floor), then doubles per consecutive cold
        // failure, capped at `failure_backoff`.
        if ts.last_refreshed.is_none() {
            let backoff = self
                .cold_backoff
                .saturating_mul(1u32 << ts.consecutive_cold_failures.min(16))
                .min(self.failure_backoff);
            return match ts
                .last_failed_refresh
                .and_then(|t| now.checked_duration_since(t))
            {
                Some(elapsed) => elapsed >= backoff,
                None => true,
            };
        }

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

        // Not stale yet — a within-TTL value is left alone. A cold seed
        // (`last_refreshed == None`) reads as infinitely stale.
        if let Some(last) = ts.last_refreshed
            && now
                .checked_duration_since(last)
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
            ts.last_refreshed = Some(now);
            ts.last_failed_refresh = None;
            ts.consecutive_cold_failures = 0;
            // Warm now; publish to the lock-free `is_cold` mirror. `Release`
            // pairs with the `Acquire` load, ordering it after the value swap.
            self.cold.store(false, Ordering::Release);
        } else {
            ts.last_failed_refresh = Some(now);
            // Escalate only while still cold; a warm failure keeps serving the
            // last good value and uses the warm backoff.
            if ts.last_refreshed.is_none() {
                ts.consecutive_cold_failures = ts.consecutive_cold_failures.saturating_add(1);
            }
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
        // Cheap pre-check so clearly-blocked callers don't queue on the lock.
        if !self.should_refresh_stale() {
            return false;
        }

        self.refresh_with_policy(true).await
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
        // Cheap pre-check so clearly-blocked callers don't queue on the lock.
        if !self.policy_permits_miss_refresh() {
            return false;
        }

        self.refresh_with_policy(false).await
    }

    /// Runs a blocking refresh whose policy gate is evaluated **under** the
    /// single-flight lock, claiming `last_refresh_attempt` before the factory
    /// runs. A failed fetch stores nothing — the pointer-swap dedup cannot
    /// de-duplicate it — so without the under-lock claim, every waiter queued
    /// behind a failing fetch would pass the pre-lock policy check and then
    /// re-invoke the factory in turn, bypassing `min_refresh_interval` and
    /// `failure_backoff` exactly when the upstream is struggling.
    ///
    /// The outcome is likewise recorded while the lock is still held, so a
    /// failure's `failure_backoff` blocks the queued waiters even when
    /// `min_refresh_interval` is zero (where the claimed attempt is inert).
    ///
    /// `ttl_gated` re-checks staleness under the lock too (the stale path);
    /// the miss path passes `false` — a miss is its own trigger.
    async fn refresh_with_policy(&self, ttl_gated: bool) -> bool {
        let gate = || {
            let now = Instant::now();
            let mut ts = self
                .timestamps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            if ttl_gated
                && let Some(last) = ts.last_refreshed
                && now
                    .checked_duration_since(last)
                    .is_some_and(|elapsed| elapsed < self.ttl)
            {
                return false;
            }
            if !self.policy_permits_attempt(now, &ts) {
                return false;
            }
            // Claim the attempt while still under the refresh lock so queued
            // waiters observe it the moment they acquire the lock.
            ts.last_refresh_attempt = Some(now);
            true
        };

        match self
            .inner
            .refresh_gated(gate, |success| self.record_refresh(success))
            .await
        {
            // Adopted: another task's refresh landed while we waited; it
            // records its own outcome.
            Ok(GatedRefresh::Refreshed | GatedRefresh::Adopted) => true,
            Ok(GatedRefresh::Blocked) | Err(_) => false,
        }
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
        // The seam for a future opt-in *async* mode: the elected caller could
        // hand this refresh to a runtime spawn and return immediately, serving
        // the still-in-TTL keyset. Kept as one `.await` so that stays local.
        match self.inner.try_refresh_ahead().await {
            Ok(true) => self.record_refresh(true),
            // Another caller won the single-flight; let them record the attempt.
            Ok(false) => {}
            Err(_) => self.record_refresh(false),
        }
    }

    /// Forces a refresh bypassing the scheduling policy, but still records the outcome.
    pub(crate) async fn refresh(&self) -> Result<bool, Error> {
        match self
            .inner
            .refresh_gated(|| true, |success| self.record_refresh(success))
            .await?
        {
            GatedRefresh::Refreshed => Ok(true),
            // Adopted: the concurrent refresher recorded its own outcome.
            // Blocked is unreachable with an always-true gate.
            GatedRefresh::Adopted | GatedRefresh::Blocked => Ok(false),
        }
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

    /// A factory whose first call (the initial build) succeeds and every later
    /// call fails after yielding — the yield lets concurrent refreshers queue
    /// on the single-flight lock while a failing fetch is in flight.
    fn failing_after_first(
        calls: Arc<AtomicUsize>,
    ) -> impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<usize, Error>>>>
    + MaybeSendSync
    + 'static {
        move || {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Ok(n)
                } else {
                    tokio::task::yield_now().await;
                    Err(Error::new(
                        crate::error::RetryAdvice::RETRY,
                        "upstream down",
                    ))
                }
            })
        }
    }

    /// Regression: a burst of concurrent misses against a *failing* upstream
    /// must not re-invoke the factory once per waiter. A failed fetch stores
    /// nothing, so the pointer-swap dedup can't fire; the policy gate claimed
    /// under the single-flight lock is what blocks the queue.
    #[tokio::test]
    async fn queued_misses_do_not_hammer_failing_upstream() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sr = ScheduledRefreshable::builder()
            .factory(failing_after_first(calls.clone()))
            .ttl(Duration::from_hours(1))
            .min_refresh_interval(Duration::from_hours(1))
            .failure_backoff(Duration::from_hours(1))
            .build()
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "initial build");

        let outcomes = tokio::join!(
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
        );
        let outcomes = <[bool; 5]>::from(outcomes);
        assert!(
            !outcomes.into_iter().any(|refreshed| refreshed),
            "no miss succeeds: the upstream is down"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "only one waiter reaches the failing upstream; the rest are \
             blocked by the attempt claimed under the lock"
        );
    }

    /// The under-lock gate itself, not just the cheap pre-lock check, blocks
    /// queued waiters. With `min_refresh_interval` zero the claimed attempt is
    /// inert, so every waiter passes the pre-check and queues on the
    /// single-flight lock; only the failure recorded — while the lock is still
    /// held — by the first waiter's fetch stands between the queue and the
    /// failing upstream via `failure_backoff`.
    #[tokio::test]
    async fn queued_waiters_blocked_by_failure_backoff_under_lock() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sr = ScheduledRefreshable::builder()
            .factory(failing_after_first(calls.clone()))
            .ttl(Duration::from_hours(1))
            .min_refresh_interval(Duration::ZERO)
            .failure_backoff(Duration::from_hours(1))
            .build()
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "initial build");

        let outcomes = tokio::join!(
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
            sr.try_refresh_on_miss(),
        );
        let outcomes = <[bool; 5]>::from(outcomes);
        assert!(
            !outcomes.into_iter().any(|refreshed| refreshed),
            "no miss succeeds: the upstream is down"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the failure recorded under the lock blocks every queued waiter \
             via failure_backoff"
        );
    }

    /// The gate of [`Refreshable::refresh_gated`] runs under the lock and a
    /// `false` verdict skips the factory entirely.
    #[tokio::test]
    async fn refresh_gated_blocked_skips_factory() {
        let calls = Arc::new(AtomicUsize::new(0));
        let refreshable = Refreshable::builder()
            .factory(counting_factory(calls.clone()))
            .build()
            .await
            .unwrap();

        let outcome = refreshable.refresh_gated(|| false, |_| {}).await.unwrap();
        assert_eq!(outcome, GatedRefresh::Blocked);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "factory not re-invoked");
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

    /// A factory whose first call (the initial build) fails and every later call
    /// succeeds — an upstream that is down at startup and then recovers.
    fn ok_after_first_failure(
        calls: Arc<AtomicUsize>,
    ) -> impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<usize, Error>>>>
    + MaybeSendSync
    + 'static {
        move || {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(Error::new(
                        crate::error::RetryAdvice::RETRY,
                        "upstream down at boot",
                    ))
                } else {
                    Ok(n)
                }
            })
        }
    }

    /// A failed initial fetch with a `fallback` is tolerated: construction succeeds
    /// cold, serves the placeholder, and a later refresh clears the cold state.
    #[tokio::test]
    async fn cold_start_seeds_then_recovers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sr = ScheduledRefreshable::builder()
            .factory(ok_after_first_failure(calls))
            .cold_backoff(Duration::ZERO) // no wait between cold retries in the test
            .fallback(999_usize)
            .build()
            .await
            .expect("cold start is tolerated, not fatal");
        assert!(sr.is_cold(), "no value has loaded yet");
        assert_eq!(*sr.load_full(), 999, "serving the seeded placeholder");

        assert!(
            sr.try_refresh_on_miss().await,
            "the recovered upstream loads"
        );
        assert!(!sr.is_cold(), "warm once a value has loaded");
        assert_eq!(*sr.load_full(), 1, "serving the fetched value");
    }

    /// A nonzero `cold_backoff` gates the very first cold retry: immediately
    /// after a tolerated cold build (which stamps the failure but leaves the
    /// escalation count at zero), the miss path is held off for one `cold_backoff`
    /// rather than hammering a just-failed upstream, so the source stays cold and
    /// the factory is not re-invoked.
    #[tokio::test]
    async fn cold_backoff_gates_the_first_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sr = ScheduledRefreshable::builder()
            .factory(ok_after_first_failure(Arc::clone(&calls)))
            .cold_backoff(Duration::from_secs(10)) // long enough to block an immediate retry
            .fallback(999_usize)
            .build()
            .await
            .expect("cold start is tolerated");
        assert!(sr.is_cold());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the failed build has run"
        );

        assert!(
            !sr.try_refresh_on_miss().await,
            "the cold_backoff floor has not elapsed, so the retry is held off"
        );
        assert!(sr.is_cold(), "still cold; no second fetch was attempted");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the factory was not re-invoked"
        );
    }

    /// Without a `fallback`, a failed initial fetch stays fatal (fail-fast).
    #[tokio::test]
    async fn no_fallback_keeps_initial_failure_fatal() {
        let calls = Arc::new(AtomicUsize::new(0));
        let result = ScheduledRefreshable::builder()
            .factory(ok_after_first_failure(calls))
            .build()
            .await;
        assert!(
            result.is_err(),
            "no fallback => a failed initial fetch is fatal"
        );
    }
}
