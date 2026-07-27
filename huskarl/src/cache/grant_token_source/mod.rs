use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use bon::Builder;

use crate::{
    cache::{
        Attempt, GetTokenError, GrantParametersSource, Recovery, RefreshTokenStore, TokenError,
        TokenSource,
    },
    core::{
        Error, OAuthErrorCode, RetryAdvice,
        dpop::ResourceServerDPoP,
        error::propagation::Classification,
        platform::{Duration, Instant, MaybeSendBoxFuture},
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
/// which adds caching, single-flight, and expiry on top; [caching
/// tokens](crate::_docs::guide::caching) shows the full wiring. Keep an `Arc`
/// clone to [`prime`](Self::prime) it with a freshly obtained token after an
/// interactive login — it is served once and its refresh token persisted.
///
/// See [token source resolution](crate::_docs::explanation::token_source_resolution)
/// for the rationale behind these rules.
///
/// # Resolution order
///
/// Each [`token`](TokenSource::token) call uses the first available successful
/// path in this order:
///
/// 1. A **primed token** from [`prime`](Self::prime), if any.
/// 2. A **refresh** using the stored refresh token, if any.
/// 3. A **fresh grant exchange** using parameters from the configured
///    [`GrantParametersSource`] — consulted only here, after the refresh.
///
/// A source built with [`NoSource`](crate::cache::NoSource) performs only
/// steps 1–2.
///
/// # Credential lifecycle
///
/// An `invalid_grant` verdict discards a refresh token. It also permanently
/// spends a fixed parameter source that opts in through
/// [`discard_after_rejection`](GrantParametersSource::discard_after_rejection).
/// [`single_use`](crate::cache::single_use) sources are consumed on first use.
///
/// Request-parameter verdicts recognized by
/// [`parameters_at_fault`](crate::core::OAuthErrorCode::parameters_at_fault),
/// such as `invalid_scope`, do not discard credentials.
///
/// Failures report [`Reauthenticate`](crate::cache::Recovery::Reauthenticate)
/// only when no automatic acquisition path remains. With the `metrics` feature,
/// the attempted path is reported through the [`TokenOutcome`](crate::TokenOutcome)
/// label.
///
/// # Backoff
///
/// After `breaker_threshold` consecutive non-recoverable fresh-exchange
/// failures, the source waits for `breaker_cooldown` before allowing one trial.
/// Transient and request-shape failures do not count. Refreshes remain available,
/// and any success or [`prime`](Self::prime) resets the breaker.
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
    /// **Required** — state where tokens come from, one of:
    ///
    /// - a reusable parameter value passed directly (a fresh exchange runs
    ///   whenever needed), or [`single_use`](crate::cache::single_use) (an
    ///   authorization or device code, consumed once and never replayed) or
    ///   [`from_fn`](crate::cache::from_fn) (a dynamic source minting a fresh
    ///   value per exchange — e.g. a JWT-bearer assertion re-signed with a
    ///   current `exp`);
    /// - [`NoSource`](crate::cache::NoSource) — this source only refreshes: hand it the token response
    ///   from an interactive flow via [`prime`](Self::prime), or point
    ///   [`refresh_store`](Self::builder) at a store another component
    ///   populates.
    ///
    /// There is deliberately no default: a source with [`NoSource`](crate::cache::NoSource) that is
    /// never [`prime`](Self::prime)d (and whose store stays empty) can never
    /// produce a token, so that configuration must be chosen, not inherited.
    #[builder(with = |source: impl GrantParametersSource<G::Parameters> + 'static|
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
    /// Extra labels applied to this source's metrics.
    #[cfg(feature = "metrics")]
    #[builder(default)]
    metric_labels: Vec<::metrics::Label>,
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
    fn token(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, TokenError>> {
        Box::pin(async move {
            let token = self.token_inner().await?;
            self.emit_success();
            Ok(Arc::new(token))
        })
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

    async fn token_inner(&self) -> Result<TokenResponse, TokenError> {
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

        // Gate only fresh exchanges; a retained refresh token remains usable.
        if let Err(remaining) = self
            .breaker
            .try_acquire(self.breaker_threshold, self.breaker_cooldown)
        {
            return Err(match refresh_error {
                Some(source) if Recovery::implied_by(&source).leaves_a_live_path() => {
                    self.propagate_refresh_error(source)
                }
                // No request was made, so report policy backoff without a verdict.
                _ => self.failed(
                    Recovery::Retry {
                        after: Some(remaining),
                    },
                    RetryAdvice::retry_after(remaining).into(),
                    GetTokenError::Backoff,
                ),
            });
        }

        // Acquire parameters for a from-scratch exchange. Invoked only here —
        // after try_refresh — so a usable refresh token avoids re-minting a
        // dynamic source (e.g. re-signing a JWT-bearer assertion). A source
        // already spent by a definitive rejection yields nothing.
        let source_reusable = self.grant_parameters.retryable();
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
                    return Err(self.combine_exchange_error(
                        refresh_error,
                        exchange_source,
                        source_reusable,
                    ));
                }
            }
        };

        let Some(params) = params else {
            return Err(match refresh_error {
                // Preserve a refresh failure when its credential remains usable.
                Some(source) if Recovery::implied_by(&source).leaves_a_live_path() => {
                    self.propagate_refresh_error(source)
                }
                // Preserve the refresh classification while marking all paths exhausted.
                Some(source) => self.exhausted(
                    source.classification(),
                    GetTokenError::RefreshFailed { source },
                ),
                // Nothing was available to attempt.
                None => self.exhausted(RetryAdvice::No.into(), GetTokenError::NoTokenSource),
            });
        };

        match self.grant.exchange(params).await {
            Ok(token_response) => {
                self.persist_refresh_token(&token_response).await;
                self.breaker.reset();
                Ok(token_response)
            }
            Err(exchange_source) => {
                // Spend fixed parameters only when the server rejects the credential.
                // Request-shape verdicts leave the credential intact.
                let credential_dead = exchange_source
                    .verdict()
                    .is_some_and(|verdict| verdict.code() == &OAuthErrorCode::InvalidGrant);
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
                Err(self.combine_exchange_error(
                    refresh_error,
                    exchange_source,
                    source_reusable && !spent,
                ))
            }
        }
    }

    /// Emits a failure with the recovery selected by this token source.
    #[track_caller]
    fn failed(
        &self,
        recovery: Recovery,
        classification: Classification,
        cause: GetTokenError,
    ) -> TokenError {
        self.emit(recovery, classification, cause)
    }

    /// Emits a failure after every acquisition path has been exhausted.
    #[track_caller]
    fn exhausted(&self, classification: Classification, cause: GetTokenError) -> TokenError {
        self.emit(Recovery::Reauthenticate, classification, cause)
    }

    /// Records the metrics outcome and constructs the token error.
    #[track_caller]
    #[cfg_attr(not(feature = "metrics"), allow(clippy::unused_self))]
    fn emit(
        &self,
        recovery: Recovery,
        classification: Classification,
        cause: GetTokenError,
    ) -> TokenError {
        #[cfg(feature = "metrics")]
        {
            let mut labels = self.metric_labels.clone();
            labels.push(::metrics::Label::new("outcome", cause.outcome().as_str()));
            ::metrics::counter!("huskarl.token.acquire", labels).increment(1);
        }
        TokenError::new(recovery, Error::propagate(classification, cause))
    }

    /// Records a successful acquisition.
    #[cfg_attr(not(feature = "metrics"), allow(clippy::unused_self))]
    fn emit_success(&self) {
        #[cfg(feature = "metrics")]
        {
            let mut labels = self.metric_labels.clone();
            labels.push(::metrics::Label::new(
                "outcome",
                crate::TokenOutcome::Success.as_str(),
            ));
            ::metrics::counter!("huskarl.token.acquire", labels).increment(1);
        }
    }

    /// Combines a fresh-exchange failure with any preceding refresh failure.
    ///
    /// `source_available` indicates whether the parameter source can produce a
    /// value on a later call. Reauthentication is required only when neither
    /// the refresh nor exchange path remains viable.
    fn combine_exchange_error(
        &self,
        refresh_error: Option<Error>,
        exchange_source: Error,
        source_available: bool,
    ) -> TokenError {
        // No refresh was attempted. Preserve the exchange classification while
        // choosing recovery from whether this source can produce another value.
        let Some(refresh_source) = refresh_error else {
            let recovery = Self::recovery_with_available_source(&exchange_source);
            let classification = exchange_source.classification();
            let cause = GetTokenError::ExchangeFailed {
                source: exchange_source,
            };
            return if source_available {
                self.failed(recovery, classification, cause)
            } else {
                self.exhausted(classification, cause)
            };
        };

        // Prefer the classification of an attempt that leaves a viable path.
        let implied_exchange_recovery = Recovery::implied_by(&exchange_source);
        let exchange_recovery = if source_available {
            Self::recovery_with_available_source(&exchange_source)
        } else {
            implied_exchange_recovery
        };
        let refresh_recovery = Recovery::implied_by(&refresh_source);
        let exchange_viable = source_available && exchange_recovery.leaves_a_live_path();
        let exchange_failure_is_actionable =
            source_available && implied_exchange_recovery.leaves_a_live_path();
        let refresh_viable = refresh_recovery.leaves_a_live_path();

        // Report an attempt that leaves a path when possible. Its complete
        // classification and the source-level recovery travel independently.
        let (recovery, reported, other, reported_attempt) =
            match (exchange_failure_is_actionable, refresh_viable) {
                (false, true) => (
                    refresh_recovery,
                    refresh_source,
                    exchange_source,
                    Attempt::Refresh,
                ),
                // The exchange is viable, or nothing is; either way it is what
                // got us here.
                _ => (
                    exchange_recovery,
                    exchange_source,
                    refresh_source,
                    Attempt::Exchange,
                ),
            };
        // Preserve both retry advice and the server verdict.
        let classification = reported.classification();
        let cause = GetTokenError::BothFailed {
            reported,
            other,
            reported_attempt,
        };
        // This layer can determine whether both alternatives are exhausted.
        if exchange_viable || refresh_viable {
            self.failed(recovery, classification, cause)
        } else {
            self.exhausted(classification, cause)
        }
    }

    /// Re-wraps a refresh failure while preserving its classification and
    /// deriving recovery for the retained refresh path.
    fn propagate_refresh_error(&self, source: Error) -> TokenError {
        let recovery = Recovery::implied_by(&source);
        let classification = source.classification();
        self.failed(
            recovery,
            classification,
            GetTokenError::RefreshFailed { source },
        )
    }

    /// Recovery for a failed exchange when the parameter source can produce
    /// another value. An explicit interaction requirement still wins; a
    /// terminal failure of this value becomes a retry of token acquisition.
    fn recovery_with_available_source(error: &Error) -> Recovery {
        match Recovery::implied_by(error) {
            Recovery::Fail => Recovery::Retry { after: None },
            recovery => recovery,
        }
    }

    /// Whether a from-scratch failure should count toward the backoff breaker.
    ///
    /// A spent source is already permanently handled. Everything else — a
    /// credential rejected on a still-usable source, or the signer/config
    /// failing — is a futile from-scratch repeat worth bounding.
    fn counts_toward_breaker(err: &Error, spent: bool) -> bool {
        !spent && !Recovery::implied_by(err).leaves_a_live_path()
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
    /// have been definitively rejected by the server. A [`NoSource`](crate::cache::NoSource) source
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
            reconciled_at: Instant::now(),
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
            Some(max) => (view.reconciled_at.elapsed() <= max).then_some(view.has_refresh_token),
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

            // Only the server rejecting *this* token retires it. A code a
            // gateway echoed on a 5xx never reaches `verdict`, which would
            // otherwise clear a perfectly good refresh token over an outage —
            // and, having cleared it, leave nothing to fall back to once the
            // outage lifted.
            if !err
                .verdict()
                .is_some_and(|verdict| verdict.code() == &OAuthErrorCode::InvalidGrant)
            {
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

        // Every path returns or `continue`s under `attempt < MAX_ATTEMPTS`, so
        // the loop cannot fall through.
        #[allow(clippy::unreachable)]
        {
            unreachable!("the final attempt never continues, so the loop always returns");
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
    reconciled_at: Instant,
}

#[cfg(test)]
mod tests;
