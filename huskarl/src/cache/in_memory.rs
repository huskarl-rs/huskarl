use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use bon::Builder;
use rand::RngExt as _;

use crate::{
    cache::{GrantTokenSource, RefreshTokenStore, TokenCache, TokenError, TokenSource},
    core::{
        Error,
        dpop::ResourceServerDPoP,
        platform::{Duration, MaybeSendBoxFuture},
    },
    grant::core::{OAuth2ExchangeGrant, TokenResponse},
};

/// The jitter band as a fraction of each token's lifetime, before the
/// [`refresh_jitter`](InMemoryTokenCache::refresh_jitter) cap. See
/// [Jitter](crate::cache#jitter).
const JITTER_LIFETIME_FRACTION: f64 = 0.1;

/// Ceiling on the effective [`expires_margin`](InMemoryTokenCache::expires_margin),
/// as a fraction of each token's lifetime, keeping short-lived tokens servable.
/// See [Refresh-ahead](crate::cache#refresh-ahead).
const MARGIN_LIFETIME_FRACTION: f64 = 0.5;

/// In-memory caching wrapper over a [`TokenSource`].
///
/// Adds three things on top of a source: it stores the last token, serves it
/// until it nears expiry (unless the source reports a freshly-injected token
/// that supersedes it — see
/// [`has_pending_token`](TokenSource::has_pending_token)), and coalesces
/// concurrent acquisitions behind a single lock so callers don't stampede the
/// source. All token *production* — refresh, grant exchange, external injection
/// — lives in the [`TokenSource`]; this type is solely the cache, so there is
/// exactly one way tokens enter it.
///
/// The usual source is [`GrantTokenSource`]; see
/// it for the refresh/exchange resolution order, the rejection handling, and the
/// error contract. To prime or inspect that source after it is in the cache,
/// hold it in an `Arc` and reach it via [`source`](Self::source) (or your own
/// clone).
///
/// By default a token is refreshed only once it nears expiry, blocking the
/// acquiring caller. [`refresh_ahead`](InMemoryTokenCacheBuilder::refresh_ahead)
/// and [`refresh_jitter`](InMemoryTokenCacheBuilder::refresh_jitter) move that
/// refresh earlier and off the request's critical path — see
/// [Refresh-ahead](crate::cache#refresh-ahead) and
/// [Jitter](crate::cache#jitter).
#[derive(Builder)]
pub struct InMemoryTokenCache<Src: TokenSource> {
    /// The source tokens are pulled from when the cache holds no valid token, or
    /// the source has a freshly-injected (primed) token that supersedes it.
    source: Src,
    /// How early to retire a token before its real expiry, covering clock skew
    /// and in-flight requests. Capped per token at [`MARGIN_LIFETIME_FRACTION`]
    /// of its lifetime (see [Refresh-ahead](crate::cache#refresh-ahead)).
    /// Defaults to 30s.
    #[builder(default = Duration::from_secs(30))]
    expires_margin: Duration,
    /// Default lifetime assumed for tokens that do not include an `expires_in` field.
    #[builder(default = Duration::from_hours(1))]
    default_expires_in: Duration,
    /// When set, refresh a still-valid token this far ahead of `expires_margin`,
    /// off the request's critical path. See
    /// [Refresh-ahead](crate::cache#refresh-ahead).
    refresh_ahead: Option<Duration>,
    /// Absolute cap on the per-instance jitter that de-synchronizes fleet
    /// refreshes; the band itself scales with each token's lifetime. [`None`]
    /// disables jitter. See [Jitter](crate::cache#jitter). Defaults to `Some(30s)`.
    #[builder(required, default = Some(Duration::from_secs(30)))]
    refresh_jitter: Option<Duration>,
    /// Stable per-instance position in the jitter band, a fraction in `[0, 1)`
    /// realized lazily (see [`jitter_offset`](Self::jitter_offset)).
    #[builder(skip)]
    jitter_cell: OnceLock<f64>,
    #[builder(skip)]
    cached: ArcSwapOption<TokenResponse>,
    #[builder(skip)]
    refresh_lock: tokio::sync::Mutex<()>,
}

/// A snapshot of what an [`InMemoryTokenCache`] can do right now, from
/// [`state`](InMemoryTokenCache::state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheState {
    /// A valid cached (or pending) access token is in hand — a request can be
    /// served now, with no network round-trip.
    Active,
    /// No usable access token, but the source can obtain one without interactive
    /// authorization (a stored refresh token or a configured credential).
    Restorable,
    /// No token, and no way to get one without sending the user through the
    /// interactive flow again.
    Unauthenticated,
}

impl<Src: TokenSource> core::fmt::Debug for InMemoryTokenCache<Src> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InMemoryTokenCache")
            .field("expires_margin", &self.expires_margin)
            .field("default_expires_in", &self.default_expires_in)
            .field("refresh_ahead", &self.refresh_ahead)
            .field("refresh_jitter", &self.refresh_jitter)
            .finish_non_exhaustive()
    }
}

impl<Src: TokenSource> InMemoryTokenCache<Src> {
    /// Returns a reference to the underlying token source.
    ///
    /// Use this to [`prime`](crate::cache::GrantTokenSource::prime) or inspect a
    /// [`GrantTokenSource`] after it is in the
    /// cache. When the source is wrapped in an `Arc`, keep a clone to reach it
    /// from elsewhere (e.g. a login handler) on a live instance.
    pub fn source(&self) -> &Src {
        &self.source
    }

    /// Clears the cached token and the source's persisted credential state.
    ///
    /// Use this when logging out to ensure no credentials remain. See
    /// [`TokenSource::clear`] for what the source discards.
    ///
    /// # Errors
    ///
    /// Returns an error if the source fails to clear its durable state; the
    /// in-memory token is dropped regardless.
    pub async fn logout(&self) -> Result<(), Error> {
        self.clear().await
    }

    /// This instance's stable position within its jitter band, chosen once in
    /// `[0, 1)`. Only reached when jitter is enabled.
    fn jitter_fraction(&self) -> f64 {
        *self
            .jitter_cell
            .get_or_init(|| rand::rng().random_range(0.0..1.0))
    }

    /// The jitter offset for a token of the given `lifetime`: a stable
    /// [fraction](Self::jitter_fraction) of a band that is
    /// [`JITTER_LIFETIME_FRACTION`] of the lifetime, capped at
    /// [`refresh_jitter`](Self::refresh_jitter) (a [`None`] cap disables jitter).
    /// See [Jitter](crate::cache#jitter).
    fn jitter_offset(&self, lifetime: Duration) -> Duration {
        let Some(cap) = self.refresh_jitter else {
            return Duration::ZERO;
        };
        let band = lifetime.mul_f64(JITTER_LIFETIME_FRACTION).min(cap);
        band.mul_f64(self.jitter_fraction())
    }

    /// The hard serve margin for a token of this `lifetime`:
    /// [`expires_margin`](Self::expires_margin), capped at
    /// [`MARGIN_LIFETIME_FRACTION`] of the lifetime. See
    /// [Refresh-ahead](crate::cache#refresh-ahead).
    fn effective_margin(&self, lifetime: Duration) -> Duration {
        self.expires_margin
            .min(lifetime.mul_f64(MARGIN_LIFETIME_FRACTION))
    }

    /// A cached token still valid to *serve*, judged against the
    /// [effective serve margin](Self::effective_margin).
    fn get_valid_cached(&self) -> Option<Arc<TokenResponse>> {
        self.cached.load_full().filter(|t| {
            let access_token = t.access_token();
            let margin =
                self.effective_margin(access_token.effective_lifetime(self.default_expires_in));
            !access_token.is_expired(self.default_expires_in, margin)
        })
    }

    /// Whether a still-valid token has reached its proactive-refresh trigger: the
    /// refresh-ahead margin if set, else the
    /// [effective serve margin](Self::effective_margin), brought earlier by
    /// [jitter](Self::jitter_offset). Always `false` with neither refresh-ahead
    /// nor jitter. See [Refresh-ahead](crate::cache#refresh-ahead).
    fn in_refresh_window(&self, token: &TokenResponse) -> bool {
        let access_token = token.access_token();
        let lifetime = access_token.effective_lifetime(self.default_expires_in);
        // Trigger off the same effective margin so the proactive refresh fires
        // no later than the hard cutoff; `refresh_ahead` opts out, unclamped.
        let base = self
            .refresh_ahead
            .unwrap_or_else(|| self.effective_margin(lifetime));
        let trigger = base + self.jitter_offset(lifetime);
        access_token.is_expired(self.default_expires_in, trigger)
    }

    /// Refreshes a token that is valid but past the refresh trigger (the
    /// jitter band or the refresh-ahead window), without blocking concurrent
    /// callers.
    ///
    /// One caller is elected via a non-blocking lock; the rest are handed the
    /// still-valid `current` token. Because that token still covers the request,
    /// a failed refresh is swallowed (a later call retries) — the slack is the
    /// point of refreshing early.
    async fn refresh_ahead_now(&self, current: Arc<TokenResponse>) -> Arc<TokenResponse> {
        // Non-blocking: if the lock is held, another caller is already
        // refreshing (ahead or at the hard margin). Serve the valid token.
        let Ok(_refresh_lock) = self.refresh_lock.try_lock() else {
            return current;
        };

        // Re-check under the lock: a concurrent refresh may have already moved
        // the token out of the window, or a pending token may now supersede it.
        if !self.source.has_pending_token()
            && let Some(token) = self.get_valid_cached()
            && !self.in_refresh_window(&token)
        {
            return token;
        }

        match self.source.token().await {
            Ok(token) => {
                self.cached.store(Some(token.clone()));
                token
            }
            // The current token is still valid; serve it and let a later call
            // retry rather than failing a request that needs no new token yet.
            Err(_) => current,
        }
    }
}

impl<Src: TokenSource> TokenSource for InMemoryTokenCache<Src> {
    fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, TokenError>> {
        Box::pin(async move {
            // A token freshly injected into the source (e.g. via `prime`) must
            // supersede any still-valid cached token, so don't short-circuit on
            // the cache while one is pending.
            if !self.source.has_pending_token()
                && let Some(token) = self.get_valid_cached()
            {
                // Valid, but past the refresh trigger (jitter band or
                // refresh-ahead window): refresh now on the non-blocking path so
                // other callers aren't stalled. With neither jitter nor
                // refresh-ahead this never fires — the original fast path.
                if self.in_refresh_window(&token) {
                    return Ok(self.refresh_ahead_now(token).await);
                }
                return Ok(token);
            }

            // Single-flight: concurrent callers coalesce onto one acquisition.
            let _refresh_lock = self.refresh_lock.lock().await;

            // Re-check under the lock: another caller may have consumed the
            // pending token and cached it while we waited.
            if !self.source.has_pending_token()
                && let Some(token) = self.get_valid_cached()
            {
                return Ok(token);
            }

            let token = self.source.token().await?;
            self.cached.store(Some(token.clone()));
            Ok(token)
        })
    }

    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
        self.source.resource_server_dpop()
    }

    fn invalidate(&self) {
        self.cached.store(None);
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.cached.store(None);
            self.source.clear().await
        })
    }
}

/// State reporting is available when the source is a [`GrantTokenSource`], the
/// only source that can authoritatively answer whether a token is restorable.
impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> InMemoryTokenCache<GrantTokenSource<G, S>> {
    /// Reports the cache's current [`CacheState`] — serve now, restore without
    /// interactive login, or re-authorize.
    ///
    /// [`Active`](CacheState::Active) reflects this cache's own token exactly; the
    /// [`Restorable`](CacheState::Restorable) /
    /// [`Unauthenticated`](CacheState::Unauthenticated) split comes from the
    /// source, with `max_staleness` bounding the credential check as in
    /// [`GrantTokenSource::can_restore`].
    ///
    /// # Errors
    ///
    /// Returns an error if the source fails to check its durable credential
    /// state.
    pub async fn state(&self, max_staleness: Option<Duration>) -> Result<CacheState, Error> {
        if self.source.has_pending_token() || self.get_valid_cached().is_some() {
            return Ok(CacheState::Active);
        }
        if self.source.can_restore(max_staleness).await? {
            return Ok(CacheState::Restorable);
        }
        Ok(CacheState::Unauthenticated)
    }
}

/// A caching wrapper memoizes, so it is a valid [`TokenCache`] to drive an
/// authorizer.
impl<Src: TokenSource> TokenCache for InMemoryTokenCache<Src> {}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{
        core::{RetryAdvice, platform::SystemTime, secrets::SecretString},
        grant::core::token_response::RawTokenResponse,
    };

    /// A [`TokenSource`] serving a fixed queue of results, counting calls and
    /// recording whether it was cleared. Any call beyond the queue panics.
    struct FakeSource {
        results: Mutex<std::collections::VecDeque<Result<TokenResponse, Error>>>,
        calls: AtomicUsize,
        cleared: AtomicBool,
        pending: AtomicBool,
    }

    impl FakeSource {
        fn new(results: impl IntoIterator<Item = Result<TokenResponse, Error>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                calls: AtomicUsize::new(0),
                cleared: AtomicBool::new(false),
                pending: AtomicBool::new(false),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn set_pending(&self, pending: bool) {
            self.pending.store(pending, Ordering::Relaxed);
        }
    }

    // A bearer-token fake: it does not implement `resource_server_dpop`, relying
    // on the trait's `NoDPoP` default.
    impl TokenSource for FakeSource {
        fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, TokenError>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = self
                .results
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra token() call");
            Box::pin(async move {
                // Yield once while the caller holds the refresh lock, so a
                // joined sibling is polled mid-acquisition — exercising the
                // single-flight and refresh-ahead non-blocking paths.
                tokio::task::yield_now().await;
                Ok(result.map(Arc::new)?)
            })
        }

        fn has_pending_token(&self) -> bool {
            self.pending.load(Ordering::Relaxed)
        }

        fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
            self.cleared.store(true, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    fn token(access: &str, expires_in: u64) -> TokenResponse {
        RawTokenResponse::builder()
            .access_token(SecretString::new(access))
            .token_type("bearer")
            .expires_in(expires_in)
            .build()
            .into_token_response(None, SystemTime::now())
            .expect("valid token response")
    }

    fn access_of(token: &TokenResponse) -> String {
        token
            .raw_token_response()
            .access_token
            .expose_secret()
            .to_owned()
    }

    #[tokio::test]
    async fn serves_cached_token_without_re_calling_source() {
        // Only one result queued: a second source call would panic.
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([Ok(token("t1", 3600))]))
            .build();

        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        assert_eq!(cache.source().calls(), 1);
    }

    #[tokio::test]
    async fn pending_token_supersedes_valid_cached_token() {
        // The cache warms with t1 (still valid), then the source reports a
        // freshly-injected (primed) token pending: the next call must bypass the
        // valid cache and re-pull, serving t2 instead of the shadowed t1.
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([
                Ok(token("t1", 3600)),
                Ok(token("t2", 3600)),
            ]))
            .build();

        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        cache.source().set_pending(true);
        assert_eq!(access_of(&cache.token().await.unwrap()), "t2");
        assert_eq!(cache.source().calls(), 2);
    }

    #[tokio::test]
    async fn refetches_after_expiry() {
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([
                Ok(token("expired", 0)),
                Ok(token("fresh", 3600)),
            ]))
            .build();

        // The first (already-expired) token is served once, then refetched.
        assert_eq!(access_of(&cache.token().await.unwrap()), "expired");
        assert_eq!(access_of(&cache.token().await.unwrap()), "fresh");
        assert_eq!(cache.source().calls(), 2);
    }

    #[tokio::test]
    async fn short_lived_token_is_served_not_immediately_refetched() {
        // A 20s token is shorter than the 30s `expires_margin`. Without the
        // lifetime clamp its effective margin would equal-or-exceed its life, so
        // it would be considered expired at issuance and every call would take
        // the blocking refetch path. The clamp caps the margin at half the
        // lifetime (10s here), keeping it servable from cache.
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([
                Ok(token("short", 20)),
                Ok(token("next", 20)),
            ]))
            .refresh_jitter(None)
            .build();

        assert_eq!(access_of(&cache.token().await.unwrap()), "short");
        // Served from cache, not refetched.
        assert_eq!(access_of(&cache.token().await.unwrap()), "short");
        assert_eq!(cache.source().calls(), 1);
    }

    #[tokio::test]
    async fn invalidate_forces_refetch() {
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([
                Ok(token("t1", 3600)),
                Ok(token("t2", 3600)),
            ]))
            .build();

        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        cache.invalidate();
        assert_eq!(access_of(&cache.token().await.unwrap()), "t2");
        assert_eq!(cache.source().calls(), 2);
    }

    #[tokio::test]
    async fn logout_clears_cache_and_source() {
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([
                Ok(token("t1", 3600)),
                Ok(token("t2", 3600)),
            ]))
            .build();

        cache.token().await.unwrap();
        cache.logout().await.unwrap();
        assert!(cache.source().cleared.load(Ordering::Relaxed));

        // The cached token was dropped, so the next call hits the source again.
        assert_eq!(access_of(&cache.token().await.unwrap()), "t2");
    }

    #[tokio::test]
    async fn propagates_source_error() {
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([Err(Error::new(
                RetryAdvice::No,
                "crypto failure",
            ))]))
            .build();

        let err = cache.token().await.unwrap_err();
        assert_eq!(err.as_error().retry_advice(), crate::core::RetryAdvice::No);
    }

    #[tokio::test]
    async fn concurrent_callers_coalesce_onto_one_source_call() {
        // Only one result queued: if both callers reached the source, the
        // second would panic on the empty queue.
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([Ok(token("t1", 3600))]))
            .build();

        let (a, b) = tokio::join!(cache.token(), cache.token());
        assert_eq!(access_of(&a.unwrap()), "t1");
        assert_eq!(access_of(&b.unwrap()), "t1");
        assert_eq!(cache.source().calls(), 1);
    }

    /// A `refresh_ahead` larger than the token's lifetime puts every served
    /// token in the window immediately, while a small `expires_margin` keeps it
    /// valid — a deterministic way to exercise refresh-ahead without sleeping.
    fn refresh_ahead_cache(
        results: impl IntoIterator<Item = Result<TokenResponse, Error>>,
    ) -> InMemoryTokenCache<FakeSource> {
        InMemoryTokenCache::builder()
            .source(FakeSource::new(results))
            .expires_margin(Duration::from_secs(30))
            .refresh_ahead(Duration::from_mins(2))
            // Disabled for deterministic timing; jitter is exercised separately.
            .refresh_jitter(None)
            .build()
    }

    #[tokio::test]
    async fn refresh_ahead_refreshes_a_still_valid_token() {
        // expires_in 100s: valid against the 30s hard margin, but inside the
        // 120s refresh-ahead window from the moment it is served.
        let cache = refresh_ahead_cache([Ok(token("t1", 100)), Ok(token("t2", 100))]);

        // Cold start: the slow path fetches t1.
        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        assert_eq!(cache.source().calls(), 1);

        // t1 is valid but in the window, so the next call refreshes ahead and
        // serves the fresh t2.
        assert_eq!(access_of(&cache.token().await.unwrap()), "t2");
        assert_eq!(cache.source().calls(), 2);
    }

    #[tokio::test]
    async fn refresh_ahead_failure_serves_the_valid_token() {
        // The ahead-refresh fails, but the current token still covers the
        // request: the error is swallowed and the valid token is served.
        let cache = refresh_ahead_cache([
            Ok(token("t1", 100)),
            Err(Error::new(RetryAdvice::No, "crypto failure")),
        ]);

        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        // Refresh attempted (calls == 2) but failed; t1 is served regardless.
        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        assert_eq!(cache.source().calls(), 2);
    }

    #[tokio::test]
    async fn without_refresh_ahead_a_valid_token_is_not_refreshed() {
        // Same token shape, but refresh-ahead unset: the cached token is served
        // without a second source call — the default behaviour is unchanged.
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([Ok(token("t1", 100))]))
            .expires_margin(Duration::from_secs(30))
            .refresh_jitter(None)
            .build();

        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");
        assert_eq!(cache.source().calls(), 1);
    }

    #[test]
    fn jitter_offset_is_capped_and_stable() {
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([]))
            .refresh_jitter(Some(Duration::from_secs(30)))
            .build();

        // A long-lived token's proportional band (10% = 6min) exceeds the 30s
        // cap, so the cap binds and the offset stays within it.
        let long = Duration::from_hours(1);
        let offset = cache.jitter_offset(long);
        assert!(offset <= Duration::from_secs(30), "offset within the cap");
        assert_eq!(
            offset,
            cache.jitter_offset(long),
            "offset is stable across calls"
        );
    }

    #[test]
    fn jitter_offset_scales_with_short_lifetimes() {
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([]))
            .refresh_jitter(Some(Duration::from_secs(30)))
            .build();

        // For a 60s token the proportional band (10% = 6s) is far below the 30s
        // cap, so the offset can never swallow most of the token's life the way
        // a fixed 30s offset would.
        let short = Duration::from_mins(1);
        let offset = cache.jitter_offset(short);
        assert!(
            offset <= Duration::from_secs(6),
            "offset scaled to the lifetime, not the cap"
        );
    }

    #[test]
    fn disabled_jitter_has_no_offset() {
        let cache = InMemoryTokenCache::builder()
            .source(FakeSource::new([]))
            .refresh_jitter(None)
            .build();

        assert_eq!(cache.jitter_offset(Duration::from_hours(1)), Duration::ZERO);
    }

    #[tokio::test]
    async fn refresh_ahead_does_not_block_concurrent_callers() {
        // Warm the cache with t1, then fire two concurrent in-window calls.
        // Exactly one is elected to refresh (serving t2); the other fails the
        // non-blocking lock and is served the still-valid t1.
        let cache = refresh_ahead_cache([Ok(token("t1", 100)), Ok(token("t2", 100))]);
        assert_eq!(access_of(&cache.token().await.unwrap()), "t1");

        let (a, b) = tokio::join!(cache.token(), cache.token());
        let served: std::collections::HashSet<_> =
            [access_of(&a.unwrap()), access_of(&b.unwrap())].into();

        // One refresh happened (t2 minted), one caller reused t1 — no stampede.
        assert_eq!(served, ["t1".to_owned(), "t2".to_owned()].into());
        assert_eq!(cache.source().calls(), 2);
    }
}
