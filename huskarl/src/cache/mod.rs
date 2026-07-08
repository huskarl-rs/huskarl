//! Token sources and caching for `OAuth2` tokens.
//!
//! The usual wiring is a chain, built from the inside out: an
//! [`HttpAuthorizer`] holds an [`InMemoryTokenCache`], which wraps a
//! [`GrantTokenSource`], which runs a grant — drawing exchange parameters from a
//! [`GrantParametersSource`] and storing the refresh token in a
//! [`RefreshTokenStore`]. Most applications use the built-in at every link and
//! implement none of these traits themselves. See [caching tokens and wiring an
//! authorizer](crate::_docs::guide::caching) for the full setup.
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
//!   token, single-flights concurrent acquisitions, and refreshes near expiry.
//! - [`RefreshTokenStore`] — pluggable storage for the refresh token, with
//!   [`InMemoryRefreshTokenStore`] as the default.
//! - [`GrantParametersSource`] — supplies the parameters for a from-scratch
//!   exchange. Reusable parameter types implement it directly; otherwise use
//!   [`single_use`], [`reusable`], or [`from_fn`].
//!
//! # Further reading
//!
//! - [Caching tokens and wiring an authorizer](crate::_docs::guide::caching) —
//!   building the chain and implementing your own store, cache, or parameter
//!   source.
//! - [Sharing a refresh token store](crate::_docs::explanation::sharing_a_token_store)
//!   — when a [`RefreshTokenStore`] can be shared across sources or processes.
//! - [Refresh timing](crate::_docs::explanation::refresh_timing) — how
//!   refresh-ahead and jitter decide when the cache refreshes.
//!
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
    /// No refresh token is stored and the source has no grant parameters
    /// ([`NoSource`]) — there is no way to obtain a token until one is
    /// supplied.
    #[snafu(display(
        "no refresh token is stored and the source has no grant parameters — hand an \
         interactive flow's token response to `GrantTokenSource::prime()`, or configure \
         `grant_parameters` on the source"
    ))]
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
                    .scope(bon::vec!["read", "write"])
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
/// — see [sharing a token store](crate::_docs::explanation::sharing_a_token_store)
/// before sharing.
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
