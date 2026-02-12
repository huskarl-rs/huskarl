//! Cache for `OAuth2` tokens.
//!
//! A cache for `OAuth2` tokens that supports retrieving tokens, attempting to refresh them,
//! and allows priming with a valid [`TokenResponse`].

mod in_memory;

use std::sync::{Arc, PoisonError};

use crate::core::{dpop::ResourceServerDPoP, http::HttpClient, platform::MaybeSend};
use huskarl_core::{platform::MaybeSendSync, token::RefreshToken};
use snafu::prelude::*;
use std::sync::RwLock;

use crate::grant::core::TokenResponse;
pub use in_memory::{InMemoryTokenCache, InMemoryTokenCacheBuilder};

/// A cache for OAuth tokens that supports retrieving tokens, attempting to refresh them,
/// and allows priming with a valid [`TokenResponse`].
pub trait TokenCache {
    /// The error type returned by the token cache for a failed request.
    type Error<C: HttpClient>: crate::core::Error + 'static;

    /// The `DPoP` proof implementation used for resource server requests.
    ///
    /// Use [`NoDPoP`](crate::core::dpop::NoDPoP) when the grant does not use `DPoP`.
    type DPoP: ResourceServerDPoP;

    /// Retrieves a token from the cache, refreshing it if necessary and possible.
    fn get_token<C: HttpClient>(
        &self,
        http_client: &C,
    ) -> impl Future<Output = Result<Arc<TokenResponse>, GetTokenError<Self::Error<C>>>> + MaybeSend;

    /// Retrieves the full token response from the cache, refreshing it if necessary and possible.
    ///
    /// This is useful when you need to inspect fields beyond the access token itself,
    /// such as provider-specific extensions returned by the token endpoint.
    fn get_token_response<C: HttpClient>(
        &self,
        http_client: &C,
    ) -> impl Future<Output = Result<Arc<TokenResponse>, GetTokenError<Self::Error<C>>>> + MaybeSend
    {
        self.get_token(http_client)
    }

    /// Returns a reference to the resource server `DPoP` proof implementation.
    fn resource_server_dpop(&self) -> &Self::DPoP;

    /// Primes the cache with a valid [`TokenResponse`].
    fn prime(&self, response: TokenResponse) -> impl Future<Output = ()> + MaybeSend;

    /// Invalidates the cache, forcing a refresh on the next [`TokenCache::get_token`] call.
    fn invalidate(&self);
}

/// Errors that can occur when getting a token from the cache.
#[derive(Debug, Snafu)]
pub enum GetTokenError<E: crate::core::Error + 'static> {
    /// Token refresh failed and no grant parameters were available to fall back to.
    RefreshFailed {
        /// The underlying refresh error.
        source: E,
    },
    /// Token refresh failed and the subsequent fresh exchange also failed.
    #[snafu(display(
        "Token refresh failed and exchange also failed: refresh={refresh_source}, exchange={exchange_source}"
    ))]
    BothFailed {
        /// The error from the failed refresh attempt.
        refresh_source: E,
        /// The error from the failed exchange attempt.
        exchange_source: E,
    },
    /// No refresh token was available and the fresh exchange failed.
    ExchangeFailed {
        /// The underlying exchange error.
        source: E,
    },
    /// No refresh token is stored and no grant parameters were provided —
    /// there is no way to obtain a token.
    NoTokenSource,
}

impl<E: crate::core::Error + 'static> crate::core::Error for GetTokenError<E> {
    fn is_retryable(&self) -> bool {
        match self {
            GetTokenError::RefreshFailed { source } | GetTokenError::ExchangeFailed { source } => {
                source.is_retryable()
            }
            GetTokenError::BothFailed {
                exchange_source, ..
            } => exchange_source.is_retryable(),
            GetTokenError::NoTokenSource => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use huskarl_core::{client_auth::NoAuth, dpop::NoDPoP};

    use crate::{
        cache::{InMemoryRefreshTokenStore, InMemoryTokenCache},
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    };

    #[test]
    fn test_setup() {
        let _cache = InMemoryTokenCache::builder()
            .grant(
                ClientCredentialsGrant::builder()
                    .client_id("client_id")
                    .client_auth(NoAuth)
                    .token_endpoint("https://blah")
                    .unwrap()
                    .dpop(NoDPoP)
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
pub trait RefreshTokenStore: MaybeSendSync {
    /// Returns the current refresh token, if one exists.
    fn get(&self) -> impl Future<Output = Option<RefreshToken>> + MaybeSend;
    /// Sets the current refresh token.
    fn set(&self, token: &RefreshToken) -> impl Future<Output = ()> + MaybeSend;
    /// Clears the current refresh token.
    fn clear(&self) -> impl Future<Output = ()> + MaybeSend;
}

/// An in-memory store for refresh tokens.
#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenStore {
    refresh_token: RwLock<Option<RefreshToken>>,
}

impl RefreshTokenStore for InMemoryRefreshTokenStore {
    async fn get(&self) -> Option<RefreshToken> {
        self.refresh_token
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn set(&self, token: &RefreshToken) {
        *self
            .refresh_token
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(token.clone());
    }
    async fn clear(&self) {
        *self
            .refresh_token
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}
