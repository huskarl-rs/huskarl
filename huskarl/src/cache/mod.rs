//! Token sources and caching for `OAuth2` tokens.
//!
//! The usual wiring is a chain, built from the inside out: an
//! [`HttpAuthorizer`] holds an [`InMemoryTokenCache`], which wraps a
//! [`GrantTokenSource`], which runs a grant — drawing exchange parameters from a
//! [`GrantParametersSource`] and storing the refresh token in a
//! [`RefreshTokenStore`]. Most applications use the built-in at every link and
//! implement none of these traits themselves.
//!
//! # Key types
//!
//! - [`TokenSource`] — the trait that produces tokens. Everything about *how* a
//!   token is obtained — refresh, grant exchange, external injection — sits
//!   behind it, so there is one token-production concept. Caching is itself a
//!   `TokenSource`, layered on top.
//! - [`TokenCache`] — a marker for a *memoizing* [`TokenSource`]. An
//!   [`HttpAuthorizer`] requires it, so a raw producer can't be wired in by
//!   mistake and re-run on every request.
//! - [`GrantTokenSource`] — the built-in producer: refreshes a token or runs a
//!   grant exchange. The type documents the refresh/exchange resolution order,
//!   rejection handling, and error contract.
//! - [`InMemoryTokenCache`] — the built-in [`TokenCache`]: stores the last
//!   token, single-flights concurrent acquisitions, and refreshes near expiry
//!   (see [Refresh-ahead](#refresh-ahead) and [Jitter](#jitter)).
//! - [`RefreshTokenStore`] — pluggable storage for the refresh token, with
//!   [`InMemoryRefreshTokenStore`] as the default.
//! - [`GrantParametersSource`] — supplies the parameters for a from-scratch
//!   exchange. Reusable parameter types implement it directly; otherwise use
//!   [`single_use`], [`reusable`], or [`from_fn`].
//!
//! # Implementing your own
//!
//! Reach for a custom implementation when a built-in's *storage* or *production*
//! model doesn't fit:
//!
//! - [`RefreshTokenStore`] — the common one: persist refresh tokens beyond
//!   process memory (keychain, disk, database) so they survive a restart.
//! - [`TokenCache`] over a [`TokenSource`] — to memoize in a store shared across
//!   processes (e.g. Redis) rather than per-process memory. Implementing the
//!   marker is your promise that the wrapper actually caches.
//! - [`TokenSource`] alone — for a producer that isn't a grant, e.g. a channel
//!   fed by a separate task.
//! - [`GrantParametersSource`] — for parameters minted per exchange from your
//!   own source (e.g. assertions fetched from a sidecar), beyond the
//!   [`single_use`] / [`reusable`] / [`from_fn`] helpers.
//!
//! # Sharing a store
//!
//! A refresh token lives in a [`RefreshTokenStore`], and a [`GrantTokenSource`]
//! treats its store as singly owned: it assumes it is the only writer. Sharing
//! one source *instance* across tasks (via `Arc`) is always fine. Whether
//! several sources — or several processes/replicas — may share one store comes
//! down to whether the authorization server rotates refresh tokens, which
//! RFC 9700 §4.14.2 ties to the client type:
//!
//! - **Confidential clients** are not subject to the replay-detection
//!   requirement, and commonly issue long-lived, non-rotating refresh tokens.
//!   Concurrent refreshes reuse the same token, so sharing is safe.
//! - **Public clients** must let the server detect refresh-token replay by one
//!   of two means: *sender-constraining* the token (mTLS [RFC 8705] or `DPoP`
//!   [RFC 9449]) **or** *rotation* (a new refresh token on each refresh, the
//!   previous one invalidated). Sender-constraining satisfies the requirement
//!   without rotation, so a `DPoP`-bound client (which huskarl supports) can
//!   also share safely.
//! - **Public clients relying on rotation** are the one share-hostile case: two
//!   owners refreshing concurrently can each present a token the other rotated
//!   out, and reuse detection then revokes the whole family. Because that is
//!   harsh, the major providers that mandate rotation (Okta, Auth0, …) soften it
//!   with a short **grace period** in which the rotated-out token stays valid —
//!   which, with the source re-reading the store before every refresh, absorbs
//!   the brief race and lost-response retries. A provider with no grace period
//!   stays unsafe to share; use single ownership, or sender-constrain the token.
//!
//! To stay correct under sharing, a [`GrantTokenSource`] does **not** blindly
//! clear the store on `invalid_grant`: it re-reads first and discards only if
//! the store still holds the token that was rejected, so it never erases a
//! peer's freshly-rotated token. huskarl adds no cross-process rotation lock —
//! [`RefreshTokenStore::get`] / [`set`](RefreshTokenStore::set) expose no atomic
//! rotate — so for a strict, rotation-only public client, give each replica its
//! own store and credential.
//!
//! # Refresh-ahead
//!
//! The three timing knobs — [`expires_margin`](InMemoryTokenCacheBuilder::expires_margin),
//! [`refresh_ahead`](InMemoryTokenCacheBuilder::refresh_ahead), and
//! [`refresh_jitter`](InMemoryTokenCacheBuilder::refresh_jitter) — form one
//! "when to refresh" decision and share one principle: each is an *absolute*
//! value tuned for minutes-to-hours tokens, but bounded by a fraction of each
//! token's own lifetime so very short-lived tokens degrade smoothly. The hard
//! margin is capped at half a token's life (a 20s token is still served ~10s,
//! not retired at issuance into a blocking refetch loop) and the jitter band
//! scales to ~10% of it (see [Jitter](#jitter)); for normal lifetimes the clamps
//! are inert.
//!
//! By default a token is refreshed only once it reaches the hard
//! [`expires_margin`](InMemoryTokenCacheBuilder::expires_margin), where the
//! acquiring caller blocks on the source. Set
//! [`refresh_ahead`](InMemoryTokenCacheBuilder::refresh_ahead) to a *larger*
//! margin to refresh proactively while the token is still valid: the request that
//! observes the window refreshes it *without blocking other callers* — one is
//! elected via a non-blocking lock, the rest are served the still-valid token,
//! and a failed attempt is non-fatal because that token still covers it. This
//! needs no background task and works anywhere, including serverless — the work
//! is driven by the request that observes the window, just moved earlier while
//! the token has slack.
//!
//! For strictly synchronous-at-margin behaviour (block only at `expires_margin`,
//! never refresh early), leave `refresh_ahead` unset **and** set `refresh_jitter`
//! to [`None`] — the default jitter triggers an early refresh on its own.
//!
//! # Jitter
//!
//! A fleet of independent instances deployed together mints tokens at about the
//! same time with the same lifetime, so without jitter they all hit the refresh
//! trigger at once and stampede the token endpoint (the single-flight lock only
//! coalesces callers *within* one process). Each instance instead picks a stable
//! random point in its band — once, never changed — and brings its trigger
//! forward by that much.
//!
//! The band is proportional to the token's lifetime, capped at
//! [`refresh_jitter`](InMemoryTokenCacheBuilder::refresh_jitter) (default
//! `Some(30s)`; [`None`] disables it). Scaling to the lifetime stops a fixed
//! offset — a rounding error on a 1h token — from swallowing most of a 60s
//! token's life, mirroring how certificate-rotation systems renew at a random
//! fraction of the credential's lifetime. A jittered refresh runs on the same
//! non-blocking, failure-tolerant path as [refresh-ahead](#refresh-ahead), so it
//! only moves *when* a refresh starts, never how long a token is served.
//!
//! [RFC 8705]: https://www.rfc-editor.org/rfc/rfc8705
//! [RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449
//! [`HttpAuthorizer`]: crate::authorizer::HttpAuthorizer

mod grant_parameters;
mod grant_token_source;
mod in_memory;
mod token_source;

use std::sync::{Arc, PoisonError, RwLock};

pub use grant_parameters::{
    FromFn, GrantParametersSource, NoSource, Reusable, SingleUse, from_fn, reusable, single_use,
};
pub use grant_token_source::{GrantTokenSource, GrantTokenSourceBuilder};
pub use in_memory::{CacheState, InMemoryTokenCache, InMemoryTokenCacheBuilder};
use snafu::Snafu;
pub use token_source::TokenSource;

use crate::{
    core::{
        Error,
        platform::{MaybeSendBoxFuture, MaybeSendSync},
    },
    token::RefreshToken,
};

/// Marker for a [`TokenSource`] that memoizes tokens — caches and
/// single-flights them rather than re-producing on every call — and so is safe
/// to drive an [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer).
///
/// It adds no methods of its own: the token-production surface is
/// [`TokenSource`], and the authorizer consumes `Arc<dyn TokenCache>`. The
/// built-in implementation is [`InMemoryTokenCache`]. Implement it on your own
/// memoizing wrapper over a [`TokenSource`] (e.g. a distributed cache);
/// implementing it is a promise that the wrapper caches, which is why the
/// authorizer requires it — a raw producer like
/// [`GrantTokenSource`] is *not* a `TokenCache`, so it can't be wired in by
/// mistake and re-run on every request.
///
/// Token *injection* (the former `prime`) is a source concern — see
/// [`GrantTokenSource::prime`].
pub trait TokenCache: TokenSource {}

impl<T: TokenCache + ?Sized> TokenCache for &T {}
impl<T: TokenCache + ?Sized> TokenCache for Box<T> {}
impl<T: TokenCache + ?Sized> TokenCache for Arc<T> {}

/// Source vocabulary for token acquisition failures.
///
/// Carried as the source of errors returned by
/// [`TokenSource::token`] when both the cache and its fallbacks
/// were exhausted. The error kind is
/// [`ErrorKind::ReauthRequired`](crate::core::ErrorKind::ReauthRequired)
/// only when no automatic recovery path remains. When one does, a non-reauth
/// kind is kept: the underlying retryable classification (e.g. a retained
/// refresh token after a transient failure), or
/// [`ErrorKind::Backoff`](crate::core::ErrorKind::Backoff) while the source is
/// cooling down. Match on the error kind rather than downcasting to this type.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum GetTokenError {
    /// Token refresh failed and no grant parameters were available to fall back to.
    #[snafu(display("token refresh failed and no grant parameters were available: {source}"))]
    RefreshFailed {
        /// The underlying refresh error.
        source: Error,
    },
    /// Token refresh failed and the subsequent fresh exchange also failed.
    #[snafu(display(
        "token refresh failed and exchange also failed: refresh={refresh_source}, exchange={exchange_source}"
    ))]
    BothFailed {
        /// The error from the failed refresh attempt.
        refresh_source: Error,
        /// The error from the failed exchange attempt.
        exchange_source: Error,
    },
    /// A from-scratch exchange failed and no refresh token was available to
    /// fall back to.
    #[snafu(display("token exchange failed and no refresh token was available: {source}"))]
    ExchangeFailed {
        /// The underlying exchange error.
        source: Error,
    },
    /// No refresh token is stored and no grant parameters were provided —
    /// there is no way to obtain a token.
    #[snafu(display("no refresh token is stored and no grant parameters were provided"))]
    NoTokenSource,
    /// The token source is backing off after repeated non-recoverable
    /// from-scratch failures. Reported under
    /// [`Backoff`](crate::core::ErrorKind::Backoff) — a "retry later,
    /// automatically" signal; see that kind for how it differs from
    /// [`ReauthRequired`](crate::core::ErrorKind::ReauthRequired) and from a
    /// retryable transport failure.
    #[snafu(display("token source backed off after repeated failures; retry after cooldown"))]
    Backoff,
}

#[cfg(test)]
mod tests {
    use crate::{
        cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
        core::{client_auth::NoAuth, http::HttpClient},
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    };

    struct NoHttp;

    impl HttpClient for NoHttp {
        fn execute(
            &self,
            _request: http::Request<bytes::Bytes>,
            _idempotency: crate::core::http::Idempotency,
        ) -> crate::core::platform::MaybeSendBoxFuture<
            '_,
            Result<crate::core::http::HttpResponse, crate::core::Error>,
        > {
            unreachable!("test only builds the cache, no HTTP expected")
        }
    }

    #[test]
    fn test_setup() {
        let source = GrantTokenSource::builder()
            .grant(
                ClientCredentialsGrant::builder()
                    .client_id("client_id")
                    .client_auth(NoAuth)
                    .token_endpoint("https://blah".parse().unwrap())
                    .http_client(NoHttp)
                    .build(),
            )
            .grant_parameters(
                ClientCredentialsGrantParameters::builder()
                    .scopes(["read", "write"])
                    .build(),
            )
            .refresh_store(InMemoryRefreshTokenStore::default())
            .build();
        let _cache = InMemoryTokenCache::builder().source(source).build();
    }
}

/// A store for refresh tokens — [`get`](Self::get) / [`set`](Self::set) /
/// [`clear`](Self::clear).
///
/// Dyn-capable: implement it on your own store type (for example a keychain- or
/// disk-backed store) and hand it to a cache builder. The built-in is
/// [`InMemoryRefreshTokenStore`].
///
/// A [`GrantTokenSource`] treats its store as singly owned. Sharing one store
/// across owners or processes is safe *except* for rotation-only public clients
/// — see [Sharing a store](self#sharing-a-store) before sharing.
pub trait RefreshTokenStore: MaybeSendSync {
    /// Returns the current refresh token, if one exists.
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>>;
    /// Sets the current refresh token.
    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>>;
    /// Clears the current refresh token.
    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>>;
}

macro_rules! forward_refresh_token_store {
    ($wrapper:ty) => {
        impl<T: RefreshTokenStore + ?Sized> RefreshTokenStore for $wrapper {
            fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
                (**self).get()
            }

            fn set<'a>(
                &'a self,
                token: &'a RefreshToken,
            ) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
                (**self).set(token)
            }

            fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
                (**self).clear()
            }
        }
    };
}

forward_refresh_token_store!(&T);
forward_refresh_token_store!(Box<T>);
forward_refresh_token_store!(std::sync::Arc<T>);

/// An in-memory store for refresh tokens.
#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenStore {
    refresh_token: RwLock<Option<RefreshToken>>,
}

impl RefreshTokenStore for InMemoryRefreshTokenStore {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        Box::pin(async {
            Ok(self
                .refresh_token
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone())
        })
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async {
            *self
                .refresh_token
                .write()
                .unwrap_or_else(PoisonError::into_inner) = Some(token.clone());
            Ok(())
        })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async {
            *self
                .refresh_token
                .write()
                .unwrap_or_else(PoisonError::into_inner) = None;
            Ok(())
        })
    }
}
