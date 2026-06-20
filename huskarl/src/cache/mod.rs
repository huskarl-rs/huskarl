//! Token sources and caching for `OAuth2` tokens.
//!
//! Tokens are produced by a [`TokenSource`] — usually a [`GrantTokenSource`],
//! which refreshes or runs a grant exchange. [`InMemoryTokenCache`] wraps a
//! source to add caching, single-flight, and expiry, and is the built-in
//! [`TokenCache`]: the marker an [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer)
//! requires so a non-memoizing source can't be wired in by mistake.

mod grant_parameters;
mod grant_token_source;
mod in_memory;
mod token_source;

use std::sync::{Arc, PoisonError, RwLock};

pub use grant_parameters::{
    FromFn, GrantParametersSource, NoSource, Reusable, SingleUse, from_fn, reusable, single_use,
};
pub use grant_token_source::{GrantTokenSource, GrantTokenSourceBuilder};
pub use in_memory::{InMemoryTokenCache, InMemoryTokenCacheBuilder};
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
    /// The token source is backing off after repeated non-recoverable failures.
    ///
    /// A later call (after the cooldown) may succeed once the underlying cause
    /// is fixed — e.g. a revoked signing key is rotated. Reported under
    /// [`Backoff`](crate::core::ErrorKind::Backoff): no token can be obtained
    /// right now, but this is a "retry later, automatically" signal — *not*
    /// [`ReauthRequired`](crate::core::ErrorKind::ReauthRequired), so callers
    /// should retry on a delay rather than re-running the interactive flow.
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

/// A store for refresh tokens.
///
/// This trait is dyn-capable: implement it on your store type (for example a
/// keychain- or disk-backed store) and hand it to a cache builder.
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
