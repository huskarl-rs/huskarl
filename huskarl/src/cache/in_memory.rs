use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bon::Builder;

use crate::{
    cache::{TokenCache, TokenSource},
    core::{
        Error,
        dpop::ResourceServerDPoP,
        platform::{Duration, MaybeSendBoxFuture},
    },
    grant::core::TokenResponse,
};

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
/// The usual source is [`GrantTokenSource`](crate::cache::GrantTokenSource); see
/// it for the refresh/exchange resolution order, the rejection handling, and the
/// error contract. To prime or inspect that source after it is in the cache,
/// hold it in an `Arc` and reach it via [`source`](Self::source) (or your own
/// clone).
#[derive(Builder)]
pub struct InMemoryTokenCache<Src: TokenSource> {
    /// The source tokens are pulled from when the cache holds no valid token, or
    /// the source has a freshly-injected (primed) token that supersedes it.
    source: Src,
    /// How early to consider a token expired.
    #[builder(default = Duration::from_secs(30))]
    expires_margin: Duration,
    /// Default lifetime assumed for tokens that do not include an `expires_in` field.
    #[builder(default = Duration::from_hours(1))]
    default_expires_in: Duration,
    #[builder(skip)]
    cached: ArcSwapOption<TokenResponse>,
    #[builder(skip)]
    refresh_lock: tokio::sync::Mutex<()>,
}

impl<Src: TokenSource> core::fmt::Debug for InMemoryTokenCache<Src> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InMemoryTokenCache")
            .field("expires_margin", &self.expires_margin)
            .field("default_expires_in", &self.default_expires_in)
            .finish_non_exhaustive()
    }
}

impl<Src: TokenSource> InMemoryTokenCache<Src> {
    /// Returns a reference to the underlying token source.
    ///
    /// Use this to [`prime`](crate::cache::GrantTokenSource::prime) or inspect a
    /// [`GrantTokenSource`](crate::cache::GrantTokenSource) after it is in the
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

    fn get_valid_cached(&self) -> Option<Arc<TokenResponse>> {
        self.cached.load_full().filter(|t| {
            !t.access_token()
                .is_expired(self.default_expires_in, self.expires_margin)
        })
    }
}

impl<Src: TokenSource> TokenSource for InMemoryTokenCache<Src> {
    fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
        Box::pin(async move {
            // A token freshly injected into the source (e.g. via `prime`) must
            // supersede any still-valid cached token, so don't short-circuit on
            // the cache while one is pending.
            if !self.source.has_pending_token()
                && let Some(token) = self.get_valid_cached()
            {
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
        core::{platform::SystemTime, secrets::SecretString},
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
        fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = self
                .results
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra token() call");
            Box::pin(async move { result.map(Arc::new) })
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
            .source(FakeSource::new([Err(Error::from(
                crate::core::ErrorKind::ReauthRequired,
            ))]))
            .build();

        let err = cache.token().await.unwrap_err();
        assert_eq!(err.kind(), crate::core::ErrorKind::ReauthRequired);
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
}
