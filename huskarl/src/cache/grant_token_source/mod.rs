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

mod breaker;
use breaker::Breaker;

/// A [`TokenSource`] that produces tokens from an `OAuth2` grant — refreshing a
/// stored refresh token, or running a fresh grant exchange.
///
/// Hand this to an [`InMemoryTokenCache`](crate::cache::InMemoryTokenCache),
/// which adds caching, single-flight, and expiry on top. Wrap it in an `Arc` and
/// keep a clone to [`prime`](Self::prime) or inspect it after it is in the cache.
///
/// # Examples
///
/// Build a source over a grant, then put it behind a cache for an
/// [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer):
///
/// ```rust
/// # use huskarl::core::client_auth::NoAuth;
/// # use huskarl::core::http::HttpClient;
/// # use huskarl::grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters};
/// use huskarl::{
///     authorizer::HttpAuthorizer,
///     cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
/// };
/// # async fn example(http_client: impl HttpClient + 'static) {
/// # let grant = ClientCredentialsGrant::builder()
/// #     .client_id("client-id")
/// #     .client_auth(NoAuth)
/// #     .token_endpoint("https://as.example.com/token".parse().unwrap())
/// #     .http_client(http_client)
/// #     .build();
/// // `grant` is any grant, built as shown in the crate-level examples.
/// let source = GrantTokenSource::builder()
///     .grant(grant)
///     .grant_parameters(ClientCredentialsGrantParameters::builder().build())
///     .refresh_store(InMemoryRefreshTokenStore::default())
///     .build();
///
/// let authorizer = HttpAuthorizer::builder()
///     .cache(InMemoryTokenCache::builder().source(source).build())
///     .build();
/// # let _ = authorizer;
/// # }
/// ```
///
/// After an interactive login, hand the freshly obtained token to a running
/// source with [`prime`](Self::prime) instead of (or alongside) a parameter
/// source; it is served once and its refresh token persisted.
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
/// # Credential lifecycle
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
/// keeps its own classification instead (see [the error
/// model](crate::core::error)). The cause is always a
/// [`GetTokenError`] variant identifying which paths were exhausted.
///
/// # Backoff
///
/// Some sources keep failing non-recoverably from scratch — most often a
/// [`from_fn`](crate::cache::from_fn) re-signing against a revoked key: every
/// fresh value is rejected with `invalid_grant`, the source is never spent, and
/// each call hits the signer and token endpoint again. A breaker bounds this.
/// After `breaker_threshold` consecutive non-recoverable failures (transient and
/// request-shape failures don't count) the source backs off for
/// `breaker_cooldown`, then allows one trial per cooldown until it succeeds. Any
/// success, or a fresh [`prime`](Self::prime), resets it; tune both knobs on the
/// builder.
///
/// The breaker gates only the **from-scratch exchange**: a refresh is still
/// attempted first on every call, so a usable refresh token always recovers.
/// While open, the from-scratch path short-circuits with
/// [`GetTokenError::Backoff`] under [`Backoff`](crate::core::ErrorKind::Backoff),
/// without re-running the signer or the exchange. A retained refresh token whose
/// latest attempt failed only transiently still surfaces that retryable error
/// rather than `Backoff`, since the refresh path recovers independently of the
/// breaker.
///
/// That [`Backoff`](crate::core::ErrorKind::Backoff) is deliberately not
/// [`ReauthRequired`](crate::core::ErrorKind::ReauthRequired): an application
/// should retry on a delay rather than bouncing the user through login. See
/// [`ErrorKind::Backoff`] for the full
/// distinction.
#[derive(Builder)]
pub struct GrantTokenSource<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    /// The grant this source runs to obtain tokens — refreshes through its
    /// [`to_refresh_grant`](OAuth2ExchangeGrant::to_refresh_grant) form, and
    /// runs a fresh exchange through it directly. Carries its own HTTP client,
    /// client authentication, and `DPoP` binding.
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
    /// Where the refresh token is persisted between calls. Use
    /// [`InMemoryRefreshTokenStore`](crate::cache::InMemoryRefreshTokenStore)
    /// for a process-lifetime store, or supply your own
    /// [`RefreshTokenStore`] (e.g. keychain- or disk-backed) to survive
    /// restarts — on startup the source refreshes it into a fresh access token.
    refresh_store: S,
    #[builder(skip = grant.dpop().to_resource_server_dpop())]
    resource_server_dpop: Arc<dyn ResourceServerDPoP>,
    /// A token handed in via [`prime`](Self::prime), served once by the next
    /// [`token`](TokenSource::token) call.
    #[builder(skip)]
    pending: Mutex<Option<TokenResponse>>,
    /// In-memory view of whether a refresh token is stored, with the time it was
    /// last reconciled with the store. Backs staleness-bounded
    /// [`can_restore`](Self::can_restore); `None` until first reconciled.
    #[builder(skip)]
    credential_view: Mutex<Option<CredentialView>>,
    /// Consecutive non-recoverable from-scratch failures tolerated before the
    /// source backs off (see [Backoff](#backoff)). `0` disables the breaker.
    /// Defaults to `3`.
    #[builder(default = 3)]
    breaker_threshold: u32,
    /// How long the source backs off once `breaker_threshold` is reached, before
    /// allowing a trial again. Defaults to 1 minute.
    #[builder(default = Duration::from_mins(1))]
    breaker_cooldown: Duration,
    #[builder(skip)]
    breaker: Breaker,
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
            self.record_credential(false);
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
            self.record_credential(true);
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

        // Bound repeated from-scratch failures: if recent attempts kept failing
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
                // is the repeated-failure case the breaker bounds. Spent sources are
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

    /// Returns whether a refresh token is currently stored — the authoritative
    /// current state, read from the [`RefreshTokenStore`] on every call. Also
    /// refreshes the in-memory view that backs [`can_restore`](Self::can_restore).
    ///
    /// For a staleness-bounded answer that can skip the store read, or the
    /// combined cache state, use [`can_restore`](Self::can_restore) /
    /// [`InMemoryTokenCache::state`](crate::cache::InMemoryTokenCache::state).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying [`RefreshTokenStore`] fails.
    pub async fn has_refresh_token(&self) -> Result<bool, Error> {
        let has = self.refresh_store.get().await?.is_some();
        self.record_credential(has);
        Ok(has)
    }

    /// Whether a token can be produced without interactive authorization — a
    /// pending token, a usable parameter source, or a stored refresh token.
    ///
    /// `max_staleness` bounds the stored-refresh-token check against the
    /// in-memory view: `Some(d)` trusts a view reconciled within `d` (else
    /// re-reads the store), `Some(Duration::ZERO)` always re-reads, and `None`
    /// trusts any view — correct only when this source is the sole writer of its
    /// store (see
    /// [`RefreshTokenStore`](crate::cache::RefreshTokenStore#ownership-and-rotation)).
    /// The pending and parameter checks are always exact.
    ///
    /// # Errors
    ///
    /// Returns an error if reconciling with the [`RefreshTokenStore`] fails.
    pub async fn can_restore(&self, max_staleness: Option<Duration>) -> Result<bool, Error> {
        // A pending token or a usable parameter source needs no store read.
        if self.has_pending_token() || self.has_grant_parameters() {
            return Ok(true);
        }
        // Refresh-token presence: trust the in-memory view within the requested
        // staleness, else reconcile with the store (which also refreshes it).
        match self.fresh_credential_view(max_staleness) {
            Some(has) => Ok(has),
            None => self.has_refresh_token().await,
        }
    }

    /// Records the current refresh-token presence and the time it was observed,
    /// for staleness-bounded [`can_restore`](Self::can_restore).
    fn record_credential(&self, has_refresh_token: bool) {
        *self
            .credential_view
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(CredentialView {
            has_refresh_token,
            reconciled_at: SystemTime::now(),
        });
    }

    /// The in-memory refresh-token view if it is populated and fresh enough for
    /// `max_staleness`; `None` means "reconcile with the store". `None`
    /// staleness trusts any populated view (sole-owner); a populated view that
    /// is too old, or one never reconciled, returns `None`.
    fn fresh_credential_view(&self, max_staleness: Option<Duration>) -> Option<bool> {
        let view = (*self
            .credential_view
            .lock()
            .unwrap_or_else(PoisonError::into_inner))?;
        match max_staleness {
            None => Some(view.has_refresh_token),
            Some(max) => {
                let age = SystemTime::now()
                    .duration_since(view.reconciled_at)
                    .unwrap_or(Duration::MAX);
                (age <= max).then_some(view.has_refresh_token)
            }
        }
    }

    /// Attempts to refresh the token.
    ///
    /// Returns `Ok(token)` on success, `Err(Some(error))` if the store or the
    /// refresh failed, or `Err(None)` if no refresh token is available.
    ///
    /// On `invalid_grant` the stored token is discarded only after a
    /// compare-before-clear (re-read, clear only if it still holds the rejected
    /// value), so a peer's concurrently-rotated token is retried rather than
    /// clobbered; see [Sharing a store](crate::cache#sharing-a-store). Transient
    /// failures leave the token in place.
    async fn try_refresh(&self) -> Result<TokenResponse, Option<Error>> {
        // Single owner: the body runs once. The bound stops a peer rotating a
        // shared token in a tight loop from spinning us indefinitely.
        const MAX_ATTEMPTS: u32 = 3;

        for attempt in 1..=MAX_ATTEMPTS {
            let refresh_token = self.refresh_store.get().await.map_err(Some)?.ok_or(None)?;

            let err = match self
                .grant
                .to_refresh_grant()
                .exchange(
                    RefreshGrantParameters::builder()
                        .refresh_token(refresh_token.clone())
                        .build(),
                )
                .await
            {
                Ok(token_response) => {
                    self.persist_refresh_token(&token_response).await;
                    return Ok(token_response);
                }
                Err(err) => err,
            };

            if err.kind() != ErrorKind::InvalidGrant {
                return Err(Some(err));
            }

            // Compare-before-clear: re-read to see whether the rejected token is
            // still the current one before discarding it.
            match self.refresh_store.get().await {
                // A peer rotated it in while our refresh was in flight: retry
                // with the current token rather than clobbering it.
                Ok(Some(current)) if attempt < MAX_ATTEMPTS && current != refresh_token => {
                    continue;
                }
                // Store still holds the rejected token: the credential is dead,
                // so discard it. Best-effort — the refresh error takes precedence
                // over a store failure on this already-failing path.
                Ok(Some(current)) if current == refresh_token => {
                    let _ = self.refresh_store.clear().await;
                    self.record_credential(false);
                }
                // Already empty, a peer hot-rotating past our budget, or the
                // re-read failed: leave the store untouched and surface the error.
                _ => {}
            }
            return Err(Some(err));
        }

        unreachable!("the final attempt never continues, so the loop always returns");
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
                self.record_credential(true);
            }
        }
    }
}

/// In-memory record of whether a refresh token was present, and when that was
/// last confirmed against the store. Backs staleness-bounded
/// [`GrantTokenSource::can_restore`].
#[derive(Clone, Copy)]
struct CredentialView {
    has_refresh_token: bool,
    reconciled_at: SystemTime,
}

#[cfg(test)]
mod tests;
