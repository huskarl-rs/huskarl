//! Cache for `OAuth2` tokens.
//!
//! A cache for `OAuth2` tokens that supports retrieving tokens, attempting to refresh them,
//! and allows priming with a valid [`TokenResponse`].

mod in_memory;

use std::sync::{Arc, PoisonError, RwLock};

pub use in_memory::{InMemoryTokenCache, InMemoryTokenCacheBuilder};
use snafu::Snafu;

use crate::{
    core::{
        Error,
        dpop::ResourceServerDPoP,
        platform::{MaybeSendBoxFuture, MaybeSendSync},
    },
    grant::core::TokenResponse,
    token::RefreshToken,
};

/// A cache for OAuth tokens that supports retrieving tokens, attempting to refresh them,
/// and allows priming with a valid [`TokenResponse`].
///
/// This trait is dyn-capable: implement it on your cache type and the library
/// consumes it as `Arc<dyn TokenCache>`.
pub trait TokenCache: MaybeSendSync {
    /// Retrieves the token response from the cache, refreshing it if necessary and possible.
    ///
    /// # Errors
    ///
    /// Returns an error of kind
    /// [`ErrorKind::ReauthRequired`](crate::core::ErrorKind::ReauthRequired)
    /// only when no token can be obtained without re-running the interactive
    /// flow (see [`GetTokenError`] for the cases). Transient failures (e.g. a
    /// retryable transport error during refresh) keep their own
    /// classification — a later call may succeed, so they are not a reauth
    /// signal. Other kinds propagate from the underlying exchange.
    fn get_token_response(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>>;

    /// Returns a reference to the resource server `DPoP` proof implementation.
    ///
    /// Use [`NoDPoP`](crate::core::dpop::NoDPoP) when the grant does not use `DPoP`.
    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP;

    /// Primes the cache with a valid [`TokenResponse`].
    ///
    /// # Errors
    ///
    /// Returns an error if persisting the response's refresh token to the
    /// underlying [`RefreshTokenStore`] fails.
    fn prime(&self, response: Arc<TokenResponse>) -> MaybeSendBoxFuture<'_, Result<(), Error>>;

    /// Invalidates the cache, forcing a refresh on the next [`TokenCache::get_token_response`] call.
    fn invalidate(&self);
}

impl<T: TokenCache + ?Sized> TokenCache for &T {
    fn get_token_response(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
        (**self).get_token_response()
    }

    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
        (**self).resource_server_dpop()
    }

    fn prime(&self, response: Arc<TokenResponse>) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        (**self).prime(response)
    }

    fn invalidate(&self) {
        (**self).invalidate();
    }
}

impl<T: TokenCache + ?Sized> TokenCache for Box<T> {
    fn get_token_response(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
        (**self).get_token_response()
    }

    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
        (**self).resource_server_dpop()
    }

    fn prime(&self, response: Arc<TokenResponse>) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        (**self).prime(response)
    }

    fn invalidate(&self) {
        (**self).invalidate();
    }
}

impl<T: TokenCache + ?Sized> TokenCache for Arc<T> {
    fn get_token_response(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
        (**self).get_token_response()
    }

    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
        (**self).resource_server_dpop()
    }

    fn prime(&self, response: Arc<TokenResponse>) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        (**self).prime(response)
    }

    fn invalidate(&self) {
        (**self).invalidate();
    }
}

/// Source vocabulary for token acquisition failures.
///
/// Carried as the source of errors returned by
/// [`TokenCache::get_token_response`] when both the cache and its fallbacks
/// were exhausted. The error kind is
/// [`ErrorKind::ReauthRequired`](crate::core::ErrorKind::ReauthRequired)
/// unless an automatic recovery path remains (e.g. a retained refresh token
/// after a transient failure), in which case the underlying retryable
/// classification is kept — match on the error kind rather than downcasting
/// to this type.
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
    /// No refresh token is stored and no grant parameters were provided —
    /// there is no way to obtain a token.
    #[snafu(display("no refresh token is stored and no grant parameters were provided"))]
    NoTokenSource,
}

#[cfg(test)]
mod tests {
    use crate::{
        cache::{InMemoryRefreshTokenStore, InMemoryTokenCache},
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
        let _cache = InMemoryTokenCache::builder()
            .grant(
                ClientCredentialsGrant::builder()
                    .client_id("client_id")
                    .client_auth(NoAuth)
                    .token_endpoint("https://blah")
                    .unwrap()
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
