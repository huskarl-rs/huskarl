use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use bon::Builder;

use crate::{
    cache::{GetTokenError, GrantParametersSource, NoSource, RefreshTokenStore, TokenSource},
    core::{
        Error, ErrorKind,
        dpop::ResourceServerDPoP,
        platform::{Duration, MaybeSendBoxFuture, SystemTime},
    },
    grant::{
        core::{OAuth2ExchangeGrant, TokenResponse},
        refresh::RefreshGrantParameters,
    },
};

/// A [`TokenSource`] that produces tokens from an `OAuth2` grant — refreshing a
/// stored refresh token, or running a fresh grant exchange.
///
/// Hand this to an [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache),
/// which adds caching, single-flight, and expiry on top. Wrap it in an `Arc` and
/// keep a clone to [`prime`](Self::prime) or inspect it after it is in the cache.
///
/// # Resolution order
///
/// Each [`token`](TokenSource::token) call resolves in strict precedence; the
/// first step that yields a token wins:
///
/// 1. **Serve a primed token** if one was handed in via [`prime`](Self::prime).
/// 2. **Refresh** using the stored refresh token, if any. On `invalid_grant` the
///    dead refresh token is discarded; transient failures keep it for a later
///    attempt.
/// 3. **Acquire parameters** from the configured [`GrantParametersSource`] and
///    run a **fresh grant exchange**. The source is consulted only here — after
///    the refresh attempt — so a usable refresh token avoids re-producing
///    parameters (e.g. re-signing a [`from_fn`](crate::cache::from_fn)
///    assertion).
///
/// A source built with no parameter source ([`NoSource`], the default) only
/// performs steps 1–2, refreshing a [`prime`](Self::prime)d token.
///
/// # When re-authorization is required
///
/// Two credentials are abandoned once they cannot succeed again, stopping futile
/// replays:
///
/// - the **refresh token** is discarded on `invalid_grant`;
/// - a **fixed parameter source** is spent on `invalid_grant` (the credential
///   is dead), provided the source opts in via
///   [`discard_after_rejection`](GrantParametersSource::discard_after_rejection)
///   (true for fixed values, false for [`from_fn`](crate::cache::from_fn), whose
///   next value may differ). Single-use sources ([`single_use`](crate::cache::single_use))
///   are consumed on first use and never replayed.
///
/// A **request-shape rejection** ([`RequestRejected`](crate::core::ErrorKind::RequestRejected):
/// `invalid_scope`, `invalid_target`, `invalid_resource`) is *not* a credential
/// failure: the source is kept and the error is surfaced unchanged, so a caller
/// can retry with a narrower request using the same credential.
///
/// A spent fixed source stays spent for the life of the source. The parameter
/// source is fixed at construction and immutable — neither [`prime`](Self::prime)
/// nor [`clear`](TokenSource::clear) revives it, because its rejected value
/// cannot become valid again. To supply a fresh credential, build a new source
/// or use a [`from_fn`](crate::cache::from_fn) parameter source, which mints a
/// new value per exchange and is never spent.
///
/// The returned error is
/// [`ReauthRequired`](crate::core::ErrorKind::ReauthRequired) **only when no
/// automatic recovery path remains** — a retryable transport failure, a retained
/// refresh token, a request-shape rejection, or a still-live dynamic source each
/// keeps its own classification instead (see [Handling
/// errors](crate::core::error#handling-errors)). The cause is always a
/// [`GetTokenError`] variant identifying which paths were exhausted.
///
/// # Backoff
///
/// A source that keeps failing non-recoverably from scratch — most often a
/// [`from_fn`](crate::cache::from_fn) re-signing against a revoked key, where
/// every fresh value is rejected with `invalid_grant` and the source is never
/// spent — would otherwise hit the signer and token endpoint on every call. A
/// breaker bounds this: after `breaker_threshold` consecutive non-recoverable
/// failures (transient and request-shape failures don't count) the source backs
/// off for `breaker_cooldown`, then allows one trial per cooldown until it
/// succeeds. Any success, or a fresh [`prime`](Self::prime), resets it. Tune both
/// knobs on the builder, or set `breaker_threshold` to `0` to disable.
///
/// The breaker gates only the **from-scratch exchange**: a refresh is still
/// attempted first on every call, so a usable refresh token always recovers.
/// While open, the from-scratch path short-circuits with
/// [`GetTokenError::Backoff`] under [`Backoff`](crate::core::ErrorKind::Backoff)
/// — without re-running the signer or the exchange — but a retained refresh token
/// whose latest attempt failed only transiently still surfaces that retryable
/// error rather than Backoff, because the refresh path can recover independently
/// of the breaker.
///
/// That [`Backoff`](crate::core::ErrorKind::Backoff) is deliberately not
/// [`ReauthRequired`](crate::core::ErrorKind::ReauthRequired): an application
/// should retry on a delay rather than bouncing the user through login. See
/// [`ErrorKind::Backoff`] for the full
/// distinction.
#[derive(Builder)]
pub struct GrantTokenSource<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    pub(crate) grant: G,
    /// Source of parameters for obtaining a token directly from the grant when
    /// no primed or refreshable token is usable.
    ///
    /// Defaults to [`NoSource`] (refresh/prime only). Build by passing a
    /// reusable parameter value directly, or with
    /// [`single_use`](crate::cache::single_use) (an authorization or device
    /// code, consumed once and never replayed) or
    /// [`from_fn`](crate::cache::from_fn) (a dynamic source minting a fresh
    /// value per exchange — e.g. a JWT-bearer assertion re-signed with a
    /// current `exp`).
    #[builder(default = Box::new(NoSource) as Box<dyn GrantParametersSource<G::Parameters>>, with = |source: impl GrantParametersSource<G::Parameters> + 'static|
        Box::new(source) as Box<dyn GrantParametersSource<G::Parameters>>)]
    grant_parameters: Box<dyn GrantParametersSource<G::Parameters>>,
    /// Set once a fixed parameter source's value is rejected by the server
    /// (`invalid_grant`): replaying the same immutable value is futile, so it is
    /// treated as exhausted. Permanent for the life of the source.
    #[builder(skip)]
    params_spent: AtomicBool,
    refresh_store: S,
    #[builder(skip = grant.dpop().to_resource_server_dpop())]
    resource_server_dpop: Arc<dyn ResourceServerDPoP>,
    /// Cached knowledge of whether a refresh token is stored.
    ///
    /// Reflects operations through this instance. Starts `false`; call
    /// [`Self::has_refresh_token`] for accurate state on cold init.
    #[builder(skip)]
    has_refresh_token_cached: AtomicBool,
    /// A token handed in via [`prime`](Self::prime), served once by the next
    /// [`token`](TokenSource::token) call.
    #[builder(skip)]
    pending: Mutex<Option<TokenResponse>>,
    /// Consecutive non-recoverable from-scratch failures tolerated before the
    /// source backs off (see [Backoff](#backoff)). `0` disables the breaker.
    /// Defaults to `3`.
    #[builder(default = 3)]
    breaker_threshold: u32,
    /// How long the source backs off once `breaker_threshold` is reached, before
    /// allowing a trial again. Defaults to 60 seconds.
    #[builder(default = Duration::from_mins(1))]
    breaker_cooldown: Duration,
    #[builder(skip)]
    breaker: Breaker,
}

/// Backoff breaker bounding a doomed from-scratch acquisition loop.
///
/// A self-contained state machine: it counts consecutive non-recoverable
/// failures and, once `threshold` of them accrue, opens for `cooldown`.
/// [`try_acquire`](Self::try_acquire) then denies permission until the cooldown
/// elapses, after which it permits one trial (half-open); any success
/// [`reset`](Self::reset)s it.
///
/// The `threshold`/`cooldown` knobs live on the owning [`GrantTokenSource`] (so
/// they sit on its builder) and are passed in per call — this type owns only the
/// runtime state and its lock. It is deliberately ignorant of the token error
/// vocabulary: the owner decides which failures count (see
/// [`counts_toward_breaker`](GrantTokenSource::counts_toward_breaker)) and which
/// error to surface when blocked.
#[derive(Default)]
struct Breaker {
    state: Mutex<BreakerState>,
}

#[derive(Default)]
struct BreakerState {
    /// Non-recoverable from-scratch failures since the last success.
    consecutive: u32,
    /// When set and not yet reached, the breaker is open (cooling down).
    open_until: Option<SystemTime>,
}

impl Breaker {
    /// Tries to acquire permission for one from-scratch attempt.
    ///
    /// Returns `true` if permitted. While cooling down it returns `false`; once
    /// the cooldown elapses it permits a single trial (half-open) — clearing
    /// `open_until` while retaining the failure count, so consuming that permit
    /// on a trial that fails non-recoverably re-opens the breaker immediately. A
    /// `threshold` of `0` disables the breaker (always permits).
    fn try_acquire(&self, threshold: u32) -> bool {
        if threshold == 0 {
            return true;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(open_until) = state.open_until {
            if SystemTime::now() < open_until {
                return false;
            }
            // Cooldown elapsed: permit one trial. The failure count is retained,
            // so a failing trial re-opens the breaker immediately.
            state.open_until = None;
        }
        true
    }

    /// Records a non-recoverable failure, opening the breaker for `cooldown`
    /// once `threshold` consecutive failures accrue. A `threshold` of `0`
    /// disables the breaker.
    fn record_failure(&self, threshold: u32, cooldown: Duration) {
        if threshold == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.consecutive = state.consecutive.saturating_add(1);
        if state.consecutive >= threshold {
            state.open_until = Some(SystemTime::now() + cooldown);
        }
    }

    /// Resets after any success (or a fresh prime).
    fn reset(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = BreakerState::default();
    }
}

#[cfg(test)]
mod breaker_tests {
    use super::Breaker;
    use crate::core::platform::Duration;

    const COOLDOWN: Duration = Duration::from_mins(1);

    #[test]
    fn opens_after_threshold_consecutive_failures() {
        let breaker = Breaker::default();
        assert!(breaker.try_acquire(3));
        breaker.record_failure(3, COOLDOWN);
        breaker.record_failure(3, COOLDOWN);
        // Below threshold: still permits.
        assert!(breaker.try_acquire(3));
        breaker.record_failure(3, COOLDOWN);
        // Threshold reached: open and cooling down — permission denied.
        assert!(!breaker.try_acquire(3));
    }

    #[test]
    fn reset_closes_an_open_breaker() {
        let breaker = Breaker::default();
        breaker.record_failure(1, COOLDOWN);
        assert!(!breaker.try_acquire(1));
        breaker.reset();
        assert!(breaker.try_acquire(1));
    }

    #[test]
    fn zero_threshold_never_opens() {
        let breaker = Breaker::default();
        for _ in 0..10 {
            breaker.record_failure(0, COOLDOWN);
        }
        assert!(breaker.try_acquire(0));
    }

    #[tokio::test]
    async fn half_opens_one_trial_after_cooldown() {
        let breaker = Breaker::default();
        breaker.record_failure(1, Duration::from_millis(10));
        assert!(!breaker.try_acquire(1));

        crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;
        // Cooldown elapsed: the gate permits one trial while retaining the
        // failure count, so a failing trial re-opens at once.
        assert!(breaker.try_acquire(1));
        breaker.record_failure(1, Duration::from_millis(10));
        assert!(!breaker.try_acquire(1));
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> core::fmt::Debug for GrantTokenSource<G, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrantTokenSource").finish_non_exhaustive()
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> TokenSource for GrantTokenSource<G, S> {
    fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
        Box::pin(async move { self.token_inner().await.map(Arc::new) })
    }

    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
        self.resource_server_dpop.as_ref()
    }

    fn has_pending_token(&self) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = None;
            self.refresh_store.clear().await?;
            self.has_refresh_token_cached
                .store(false, Ordering::Relaxed);
            self.breaker.reset();
            Ok(())
        })
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> GrantTokenSource<G, S> {
    /// Hands an externally obtained token to the source — the handoff from a
    /// login path, e.g. after an initial authorization code exchange.
    ///
    /// The token is served once by the next [`token`](TokenSource::token) call
    /// (so a cache wrapping this source serves it without a network round-trip),
    /// and its refresh token, if any, is persisted so later calls can refresh.
    ///
    /// # Errors
    ///
    /// Returns an error if persisting the refresh token to the underlying
    /// [`RefreshTokenStore`] fails.
    pub async fn prime(&self, token: TokenResponse) -> Result<(), Error> {
        if let Some(refresh_token) = token.refresh_token() {
            self.refresh_store.set(refresh_token).await?;
            self.has_refresh_token_cached.store(true, Ordering::Relaxed);
        }
        *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(token);
        // A freshly supplied credential clears any prior backoff.
        self.breaker.reset();
        Ok(())
    }

    async fn token_inner(&self) -> Result<TokenResponse, Error> {
        // A primed token is served once, ahead of any network call.
        if let Some(token) = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            self.breaker.reset();
            return Ok(token);
        }

        let refresh_error = match self.try_refresh().await {
            Ok(token) => {
                self.breaker.reset();
                return Ok(token);
            }
            Err(e) => e,
        };

        // Bound a doomed from-scratch loop: if recent attempts kept failing
        // non-recoverably (e.g. a `from_fn` re-signing against a revoked key),
        // back off instead of hitting the signer/endpoint every call. Checked
        // after try_refresh so a usable refresh token still recovers.
        //
        // The breaker gates only the from-scratch exchange; it must not mask an
        // independent recovery path. A retained refresh token whose last failure
        // was transient can still succeed on a later call, so surface that
        // (retryable) error rather than the Backoff signal. Mirrors the no-params
        // branch below.
        if !self.breaker.try_acquire(self.breaker_threshold) {
            return Err(match refresh_error {
                Some(source) if source.is_retryable() => {
                    Error::new(source.kind(), GetTokenError::RefreshFailed { source })
                }
                _ => Error::new(ErrorKind::Backoff, GetTokenError::Backoff),
            });
        }

        // Acquire parameters for a from-scratch exchange. Invoked only here —
        // after try_refresh — so a usable refresh token avoids re-minting a
        // dynamic source (e.g. re-signing a JWT-bearer assertion). A source
        // already spent by a definitive rejection yields nothing.
        let retryable = self.grant_parameters.retryable();
        let params = if self.params_spent.load(Ordering::Relaxed) {
            None
        } else {
            match self.grant_parameters.acquire().await {
                Ok(params) => params,
                // Producing the parameters failed (e.g. signing an assertion):
                // a fresh-exchange failure, combined with any refresh error.
                Err(exchange_source) => {
                    if Self::counts_toward_breaker(&exchange_source, false) {
                        self.breaker
                            .record_failure(self.breaker_threshold, self.breaker_cooldown);
                    }
                    return Err(Self::combine_exchange_error(
                        refresh_error,
                        exchange_source,
                        retryable,
                    ));
                }
            }
        };

        let Some(params) = params else {
            return Err(match refresh_error {
                // A transient refresh failure is not a reauth signal: the
                // refresh token was retained and a later call may succeed.
                // Propagate the refresh error's own retryable classification.
                Some(source) if source.is_retryable() => {
                    Error::new(source.kind(), GetTokenError::RefreshFailed { source })
                }
                Some(source) => Error::new(
                    ErrorKind::ReauthRequired,
                    GetTokenError::RefreshFailed { source },
                ),
                None => Error::new(ErrorKind::ReauthRequired, GetTokenError::NoTokenSource),
            });
        };

        match self.grant.exchange(params).await {
            Ok(token_response) => {
                self.persist_refresh_token(&token_response).await;
                self.breaker.reset();
                Ok(token_response)
            }
            Err(exchange_source) => {
                // The credential itself was rejected (`invalid_grant`):
                // replaying it is futile, so spend a fixed source — mirroring
                // try_refresh discarding a refresh token on invalid_grant. A
                // dynamic source keeps going; its next value may succeed.
                //
                // Crucially this is *not* triggered by a request-shape rejection
                // (`RequestRejected`: invalid_scope/target/resource): there the
                // credential is intact and only the request was wrong, so
                // spending it would burn a good credential and mislead the
                // caller into re-authenticating. Such errors keep their own
                // classification (via `source_retryable` below) and the caller
                // can retry with an adjusted request.
                let credential_dead = exchange_source.kind() == ErrorKind::InvalidGrant;
                let spent = credential_dead && self.grant_parameters.discard_after_rejection();
                if spent {
                    self.params_spent.store(true, Ordering::Relaxed);
                }
                // A non-recoverable failure on a still-usable (non-spent) source
                // is the doom-loop case the breaker bounds. Spent sources are
                // already permanently handled; transient and request-shape
                // failures have their own recovery (retry / adjust).
                if Self::counts_toward_breaker(&exchange_source, spent) {
                    self.breaker
                        .record_failure(self.breaker_threshold, self.breaker_cooldown);
                }
                Err(Self::combine_exchange_error(
                    refresh_error,
                    exchange_source,
                    retryable && !spent,
                ))
            }
        }
    }

    /// Combines a fresh-exchange failure with any preceding refresh failure.
    ///
    /// `source_retryable` is whether the parameter source could still succeed on
    /// a later call — a reusable or dynamic source, but not a single-use one nor
    /// a fixed source just spent by a definitive rejection. `ReauthRequired` is
    /// reported only when no automatic path remains. Several things leave one: a
    /// retryable transport failure or a request-shape rejection from the
    /// exchange (on a still-usable source), or a retained refresh token after a
    /// transient refresh failure — each can succeed on a later call (possibly
    /// with an adjusted request) without re-running the interactive flow.
    fn combine_exchange_error(
        refresh_error: Option<Error>,
        exchange_source: Error,
        source_retryable: bool,
    ) -> Error {
        // No refresh was attempted. A source that can still succeed later keeps
        // the exchange error's own classification (e.g. a retryable transport
        // failure, or an invalid_grant a dynamic source may recover from).
        // Otherwise no automatic path remains, so it is the reauth signal.
        // Either way the exchange error is wrapped as the cause, so callers can
        // downcast uniformly.
        let Some(refresh_source) = refresh_error else {
            let kind = if source_retryable {
                exchange_source.kind()
            } else {
                ErrorKind::ReauthRequired
            };
            return Error::new(
                kind,
                GetTokenError::ExchangeFailed {
                    source: exchange_source,
                },
            );
        };

        // Both a refresh and the fresh exchange failed. The exchange points to
        // its own recovery when it is a transient failure (retry) or a
        // request-shape rejection (adjust the request) — both independent of the
        // refresh outcome and preferable to forcing reauth. Otherwise a retained
        // refresh token may still succeed on a later call; failing that, no
        // automatic path remains.
        let exchange_recoverable =
            exchange_source.is_retryable() || exchange_source.kind() == ErrorKind::RequestRejected;
        let kind = if source_retryable && exchange_recoverable {
            exchange_source.kind()
        } else if refresh_source.is_retryable() {
            refresh_source.kind()
        } else {
            ErrorKind::ReauthRequired
        };
        Error::new(
            kind,
            GetTokenError::BothFailed {
                refresh_source,
                exchange_source,
            },
        )
    }

    /// Whether a from-scratch failure should count toward the backoff breaker.
    ///
    /// A spent source is already permanently handled; transient failures are the
    /// caller's to retry; request-shape rejections ([`RequestRejected`]) have a
    /// caller action (adjust the request). Everything else — a credential
    /// rejected on a still-usable source, or the signer/config failing — is a
    /// futile from-scratch repeat worth bounding.
    ///
    /// [`RequestRejected`]: crate::core::ErrorKind::RequestRejected
    fn counts_toward_breaker(err: &Error, spent: bool) -> bool {
        !spent && !err.is_retryable() && err.kind() != ErrorKind::RequestRejected
    }

    /// Returns a reference to the underlying grant.
    pub fn grant(&self) -> &G {
        &self.grant
    }

    /// Returns `true` if grant parameters are available for a fresh token exchange.
    ///
    /// For single-use parameter sources (an authorization or device code), this
    /// becomes `false` once the parameters have been consumed by an exchange
    /// attempt; for a fixed source it also becomes `false` once the parameters
    /// have been definitively rejected by the server. A [`NoSource`] source
    /// (none configured) always reports `false`.
    pub fn has_grant_parameters(&self) -> bool {
        !self.params_spent.load(Ordering::Relaxed) && self.grant_parameters.available()
    }

    /// Returns the cached knowledge of whether a refresh token is stored.
    ///
    /// This is updated by operations through this instance. On cold init (e.g. after a
    /// page reload), it starts as `false` regardless of what is in the underlying store.
    /// Call [`Self::has_refresh_token`] for accurate state when this matters.
    pub fn has_refresh_token_cached(&self) -> bool {
        self.has_refresh_token_cached.load(Ordering::Relaxed)
    }

    /// Returns whether a refresh token is currently stored.
    ///
    /// Queries the underlying store directly and updates the cached value as a side effect.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying [`RefreshTokenStore`] fails.
    pub async fn has_refresh_token(&self) -> Result<bool, Error> {
        let has = self.refresh_store.get().await?.is_some();
        self.has_refresh_token_cached.store(has, Ordering::Relaxed);
        Ok(has)
    }

    /// Attempts to refresh the token.
    ///
    /// Returns `Ok(token)` on success, `Err(Some(error))` if the store or the
    /// refresh failed, or `Err(None)` if no refresh token is available.
    ///
    /// The stored refresh token is discarded only when the server definitively
    /// rejects it with `invalid_grant` (RFC 6749 §5.2). Transient failures
    /// (network errors, 5xx responses) leave it in place for later attempts.
    async fn try_refresh(&self) -> Result<TokenResponse, Option<Error>> {
        let refresh_token = self.refresh_store.get().await.map_err(Some)?.ok_or(None)?;

        match self
            .grant
            .to_refresh_grant()
            .exchange(
                RefreshGrantParameters::builder()
                    .refresh_token(refresh_token)
                    .build(),
            )
            .await
        {
            Ok(token_response) => {
                self.persist_refresh_token(&token_response).await;
                Ok(token_response)
            }
            Err(err) => {
                if err.kind() == ErrorKind::InvalidGrant {
                    // Best-effort: the refresh error below takes precedence
                    // over a store failure on this already-failing path.
                    if self.refresh_store.clear().await.is_ok() {
                        self.has_refresh_token_cached
                            .store(false, Ordering::Relaxed);
                    }
                }
                Err(Some(err))
            }
        }
    }

    /// Persists the response's refresh token, if it carries one.
    ///
    /// When the response carries no refresh token, any previously stored refresh
    /// token is retained: per RFC 6749 §6 the authorization server may omit the
    /// refresh token from a refresh response, in which case the client keeps
    /// using the existing one. A failure to persist must not fail the
    /// acquisition; the cost is falling back to the grant parameters once this
    /// token expires.
    async fn persist_refresh_token(&self, token: &TokenResponse) {
        if let Some(refresh_token) = token.refresh_token().as_ref() {
            // Best-effort: a persist failure must not fail the acquisition (see
            // the doc comment), so the result is deliberately not propagated.
            if self.refresh_store.set(refresh_token).await.is_ok() {
                self.has_refresh_token_cached.store(true, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, StatusCode};

    use super::*;
    use crate::{
        cache::{InMemoryRefreshTokenStore, TokenSource, from_fn, single_use},
        core::{
            client_auth::NoAuth,
            http::{HttpClient, HttpResponse, Idempotency},
            platform::SystemTime,
            secrets::SecretString,
        },
        grant::{
            authorization_code::{AuthorizationCodeGrant, AuthorizationCodeGrantParameters},
            client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
            core::token_response::RawTokenResponse,
        },
        token::RefreshToken,
    };

    struct MockResponse {
        status: StatusCode,
        body: Bytes,
    }

    /// Mock HTTP client serving a fixed queue of responses; any call beyond the
    /// queue panics, proving no unexpected request was made.
    #[derive(Clone, Default)]
    struct MockHttpClient {
        responses: Arc<Mutex<VecDeque<MockResponse>>>,
    }

    impl MockHttpClient {
        fn push(&self, status: StatusCode, body: &str) {
            self.responses.lock().unwrap().push_back(MockResponse {
                status,
                body: Bytes::copy_from_slice(body.as_bytes()),
            });
        }
    }

    impl HttpClient for MockHttpClient {
        fn execute(
            &self,
            _request: http::Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra HTTP call");
            Box::pin(async move {
                let mut headers = HeaderMap::new();
                headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                Ok(HttpResponse {
                    status: response.status,
                    headers,
                    body: response.body,
                })
            })
        }
    }

    /// Cloneable handle over an [`InMemoryRefreshTokenStore`] so tests can
    /// observe the store after handing it to the source.
    #[derive(Clone, Default)]
    struct SharedRefreshStore(Arc<InMemoryRefreshTokenStore>);

    impl RefreshTokenStore for SharedRefreshStore {
        fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
            self.0.get()
        }

        fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
            self.0.set(token)
        }

        fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
            self.0.clear()
        }
    }

    fn assert_get_token_error(
        err: &Error,
        kind: ErrorKind,
        matcher: impl Fn(&GetTokenError) -> bool,
    ) {
        assert_eq!(err.kind(), kind);
        let source = std::error::Error::source(err)
            .expect("error carries a GetTokenError source")
            .downcast_ref::<GetTokenError>()
            .expect("source is a GetTokenError");
        assert!(matcher(source), "unexpected GetTokenError: {source}");
    }

    fn assert_reauth_required(err: &Error, matcher: impl Fn(&GetTokenError) -> bool) {
        assert_get_token_error(err, ErrorKind::ReauthRequired, matcher);
    }

    fn assert_backoff(err: &Error, matcher: impl Fn(&GetTokenError) -> bool) {
        assert_get_token_error(err, ErrorKind::Backoff, matcher);
    }

    /// A valid (non-expired) token carrying the given refresh token.
    fn valid_response(refresh_token: &str) -> TokenResponse {
        RawTokenResponse::builder()
            .access_token(SecretString::new("primed-access-token"))
            .token_type("bearer")
            .expires_in(3600)
            .refresh_token(SecretString::new(refresh_token))
            .build()
            .into_token_response(None, SystemTime::now())
            .expect("valid token response")
    }

    fn client_credentials_grant(http: MockHttpClient) -> ClientCredentialsGrant {
        ClientCredentialsGrant::builder()
            .client_id("client_id")
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .http_client(http)
            .build()
    }

    fn access_of(token: &TokenResponse) -> String {
        token
            .raw_token_response()
            .access_token
            .expose_secret()
            .to_owned()
    }

    /// A grant source seeded (via `prime`) with the refresh token `"rt-original"`
    /// and its pending token consumed, so the next `token` call must refresh.
    async fn primed_source(
        store: SharedRefreshStore,
        http: MockHttpClient,
    ) -> GrantTokenSource<ClientCredentialsGrant, SharedRefreshStore> {
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http))
            .refresh_store(store)
            .build();
        source.prime(valid_response("rt-original")).await.unwrap();
        // Consume the primed token so the next call exercises the refresh path.
        source.token().await.unwrap();
        source
    }

    /// Like [`primed_source`], but with reusable grant parameters as a fallback
    /// after a failed refresh.
    async fn primed_source_with_params(
        store: SharedRefreshStore,
        http: MockHttpClient,
    ) -> GrantTokenSource<ClientCredentialsGrant, SharedRefreshStore> {
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http))
            .grant_parameters(ClientCredentialsGrantParameters::new())
            .refresh_store(store)
            .build();
        source.prime(valid_response("rt-original")).await.unwrap();
        source.token().await.unwrap();
        source
    }

    async fn one_time_source(
        store: SharedRefreshStore,
        http: MockHttpClient,
    ) -> GrantTokenSource<AuthorizationCodeGrant, SharedRefreshStore> {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .client_auth(NoAuth)
            .http_client(http)
            .token_endpoint("https://as.example.com/token".parse().unwrap())
            .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        GrantTokenSource::builder()
            .grant(grant)
            .grant_parameters(single_use(
                AuthorizationCodeGrantParameters::builder()
                    .code("one-time-code")
                    .build(),
            ))
            .refresh_store(store)
            .build()
    }

    async fn stored_refresh_token(store: &SharedRefreshStore) -> Option<String> {
        store
            .get()
            .await
            .unwrap()
            .map(|t| t.token().expose_secret().to_owned())
    }

    #[tokio::test]
    async fn prime_serves_token_then_refreshes() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http.clone()))
            .refresh_store(store.clone())
            .build();

        source.prime(valid_response("rt-primed")).await.unwrap();
        assert!(source.has_refresh_token_cached());

        // The primed token is served once with no network call.
        let token = source.token().await.unwrap();
        assert_eq!(access_of(&token), "primed-access-token");
        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-primed")
        );

        // Pending consumed: the next call refreshes using the persisted token.
        http.push(
            StatusCode::OK,
            r#"{"access_token":"refreshed","token_type":"bearer","expires_in":3600}"#,
        );
        assert_eq!(access_of(&source.token().await.unwrap()), "refreshed");
    }

    #[tokio::test]
    async fn refresh_response_without_refresh_token_retains_existing() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = primed_source(store.clone(), http.clone()).await;

        http.push(
            StatusCode::OK,
            r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600}"#,
        );

        assert_eq!(
            access_of(&source.token().await.unwrap()),
            "new-access-token"
        );

        // RFC 6749 §6: no new refresh token issued means the existing one stays valid.
        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-original")
        );
        assert!(source.has_refresh_token_cached());
    }

    #[tokio::test]
    async fn refresh_response_with_rotated_refresh_token_replaces_existing() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = primed_source(store.clone(), http.clone()).await;

        http.push(
            StatusCode::OK,
            r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"rt-rotated"}"#,
        );

        source.token().await.unwrap();

        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-rotated")
        );
    }

    #[tokio::test]
    async fn transient_refresh_failure_retains_refresh_token() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = primed_source(store.clone(), http.clone()).await;

        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );

        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::RefreshFailed { .. })
        });

        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-original")
        );
        assert!(source.has_refresh_token_cached());

        http.push(
            StatusCode::OK,
            r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
        );
        assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
    }

    #[tokio::test]
    async fn invalid_grant_clears_refresh_token() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = primed_source(store.clone(), http.clone()).await;

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

        let err = source.token().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::RefreshFailed { .. }));

        assert_eq!(stored_refresh_token(&store).await, None);
        assert!(!source.has_refresh_token_cached());
    }

    #[tokio::test]
    async fn both_failed_transiently_stays_retryable() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = primed_source_with_params(store.clone(), http.clone()).await;

        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );
        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );

        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::BothFailed { .. })
        });

        http.push(
            StatusCode::OK,
            r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
        );
        assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
    }

    #[tokio::test]
    async fn both_failed_definitively_requires_reauth() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = primed_source_with_params(store.clone(), http.clone()).await;

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

        let err = source.token().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::BothFailed { .. }));
        assert_eq!(stored_refresh_token(&store).await, None);
    }

    #[tokio::test]
    async fn one_time_parameters_consumed_by_first_exchange() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = one_time_source(store, http.clone()).await;
        assert!(source.has_grant_parameters());

        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
        );
        source.token().await.unwrap();
        assert!(!source.has_grant_parameters());

        // The spent code must not be replayed: no HTTP call (empty mock would
        // panic), and the error reports that no token source remains.
        let err = source.token().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::NoTokenSource));
    }

    #[tokio::test]
    async fn one_time_parameters_not_replayed_after_failed_refresh() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = one_time_source(store.clone(), http.clone()).await;

        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":0,"refresh_token":"rt-1"}"#,
        );
        source.token().await.unwrap();

        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );
        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::RefreshFailed { .. })
        });

        assert_eq!(stored_refresh_token(&store).await.as_deref(), Some("rt-1"));
    }

    #[tokio::test]
    async fn reusable_parameters_allow_repeated_exchange() {
        let http = MockHttpClient::default();
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http.clone()))
            .grant_parameters(ClientCredentialsGrantParameters::new())
            .refresh_store(SharedRefreshStore::default())
            .build();

        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
        );
        http.push(
            StatusCode::OK,
            r#"{"access_token":"t2","token_type":"bearer","expires_in":3600}"#,
        );

        source.token().await.unwrap();
        assert_eq!(access_of(&source.token().await.unwrap()), "t2");
        assert!(source.has_grant_parameters());
    }

    #[tokio::test]
    async fn reusable_parameters_discarded_after_invalid_grant() {
        let http = MockHttpClient::default();
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http.clone()))
            .grant_parameters(ClientCredentialsGrantParameters::new())
            .refresh_store(SharedRefreshStore::default())
            .build();

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        let err = source.token().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::ExchangeFailed { .. }));

        // The rejected parameters are spent: a second call must not replay them.
        assert!(!source.has_grant_parameters());
        let err = source.token().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::NoTokenSource));
    }

    #[tokio::test]
    async fn request_rejection_retains_source_and_credential() {
        let http = MockHttpClient::default();
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http.clone()))
            .grant_parameters(ClientCredentialsGrantParameters::new())
            .refresh_store(SharedRefreshStore::default())
            .build();

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);
        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::RequestRejected, |e| {
            matches!(e, GetTokenError::ExchangeFailed { .. })
        });
        assert!(source.has_grant_parameters());

        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
        );
        assert_eq!(access_of(&source.token().await.unwrap()), "t1");
    }

    #[tokio::test]
    async fn request_rejection_survives_failed_refresh() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = primed_source_with_params(store, http.clone()).await;

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);

        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::RequestRejected, |e| {
            matches!(e, GetTokenError::BothFailed { .. })
        });
    }

    #[tokio::test]
    async fn reusable_parameters_retained_after_transient_failure() {
        let http = MockHttpClient::default();
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http.clone()))
            .grant_parameters(ClientCredentialsGrantParameters::new())
            .refresh_store(SharedRefreshStore::default())
            .build();

        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );
        let err = source.token().await.unwrap_err();
        assert!(err.is_retryable());
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::ExchangeFailed { .. })
        });
        assert!(source.has_grant_parameters());

        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
        );
        assert_eq!(access_of(&source.token().await.unwrap()), "t1");
    }

    #[tokio::test]
    async fn dynamic_source_not_discarded_after_invalid_grant() {
        let http = MockHttpClient::default();
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http.clone()))
            .grant_parameters(from_fn(|| async {
                Ok::<_, Error>(ClientCredentialsGrantParameters::new())
            }))
            .refresh_store(SharedRefreshStore::default())
            .build();

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::InvalidGrant, |e| {
            matches!(e, GetTokenError::ExchangeFailed { .. })
        });
        assert!(source.has_grant_parameters());

        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
        );
        assert_eq!(access_of(&source.token().await.unwrap()), "t1");
    }

    fn dynamic_source(
        http: MockHttpClient,
        threshold: u32,
        cooldown: std::time::Duration,
    ) -> GrantTokenSource<ClientCredentialsGrant, SharedRefreshStore> {
        GrantTokenSource::builder()
            .grant(client_credentials_grant(http))
            .grant_parameters(from_fn(|| async {
                Ok::<_, Error>(ClientCredentialsGrantParameters::new())
            }))
            .refresh_store(SharedRefreshStore::default())
            .breaker_threshold(threshold)
            .breaker_cooldown(cooldown)
            .build()
    }

    fn assert_invalid_grant(err: &Error) {
        assert_get_token_error(err, ErrorKind::InvalidGrant, |e| {
            matches!(e, GetTokenError::ExchangeFailed { .. })
        });
    }

    #[tokio::test]
    async fn breaker_trips_after_threshold_and_backs_off() {
        let http = MockHttpClient::default();
        let source = dynamic_source(http.clone(), 2, std::time::Duration::from_mins(1));

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

        // Two non-recoverable failures reach the endpoint...
        assert_invalid_grant(&source.token().await.unwrap_err());
        assert_invalid_grant(&source.token().await.unwrap_err());

        // ...then the breaker is open: the next call backs off without any HTTP
        // (the empty mock would panic if the endpoint were reached). The kind is
        // Backoff — "retry later", not ReauthRequired.
        assert_backoff(&source.token().await.unwrap_err(), |e| {
            matches!(e, GetTokenError::Backoff)
        });
    }

    #[tokio::test]
    async fn breaker_half_opens_after_cooldown() {
        let http = MockHttpClient::default();
        let source = dynamic_source(http.clone(), 1, std::time::Duration::from_millis(10));

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        assert_invalid_grant(&source.token().await.unwrap_err());

        // After the cooldown the breaker half-opens and the next call reaches the
        // endpoint again — here it succeeds, resetting the breaker.
        crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;
        http.push(
            StatusCode::OK,
            r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
        );
        assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
    }

    #[tokio::test]
    async fn breaker_resets_on_success() {
        let http = MockHttpClient::default();
        let source = dynamic_source(http.clone(), 2, std::time::Duration::from_mins(1));

        // A success between failures resets the count, so two failures spread
        // across a success never trip the (threshold 2) breaker.
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
        );
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        http.push(
            StatusCode::OK,
            r#"{"access_token":"t2","token_type":"bearer","expires_in":3600}"#,
        );

        assert_invalid_grant(&source.token().await.unwrap_err());
        assert_eq!(access_of(&source.token().await.unwrap()), "t1");
        assert_invalid_grant(&source.token().await.unwrap_err());
        // Not backed off (success reset the count): this call reaches the
        // endpoint and the queued success is consumed.
        assert_eq!(access_of(&source.token().await.unwrap()), "t2");
    }

    #[tokio::test]
    async fn breaker_disabled_with_zero_threshold() {
        let http = MockHttpClient::default();
        let source = dynamic_source(http.clone(), 0, std::time::Duration::from_mins(1));

        // Disabled: repeated failures never back off — each call reaches the
        // endpoint and surfaces InvalidGrant.
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        assert_invalid_grant(&source.token().await.unwrap_err());
        assert_invalid_grant(&source.token().await.unwrap_err());
    }

    #[tokio::test]
    async fn open_breaker_does_not_mask_retryable_refresh() {
        // A `from_fn` source (never spent by invalid_grant) trips the breaker
        // while a refresh token is retained through transient failures. Once the
        // breaker is open, a transient refresh failure must surface as a
        // retryable RefreshFailed — an independent recovery path the from-scratch
        // breaker must not mask with its Backoff signal.
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let source = GrantTokenSource::builder()
            .grant(client_credentials_grant(http.clone()))
            .grant_parameters(from_fn(|| async {
                Ok::<_, Error>(ClientCredentialsGrantParameters::new())
            }))
            .refresh_store(store.clone())
            .breaker_threshold(2)
            .build();
        source.prime(valid_response("rt-original")).await.unwrap();
        // Consume the primed token (no network) so the store holds the refresh
        // token and the breaker starts reset.
        source.token().await.unwrap();

        // Two rounds of (transient refresh, invalid_grant exchange) trip the
        // breaker; the refresh token is retained across both.
        for _ in 0..2 {
            http.push(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"temporarily_unavailable"}"#,
            );
            http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
            let err = source.token().await.unwrap_err();
            assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
                matches!(e, GetTokenError::BothFailed { .. })
            });
        }

        // Breaker is now open. Only one (transient) refresh response is queued:
        // if the gate fell through to the exchange, the empty mock would panic.
        // The surfaced error is the retryable refresh failure, not Backoff.
        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );
        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::RefreshFailed { .. })
        });
    }
}
