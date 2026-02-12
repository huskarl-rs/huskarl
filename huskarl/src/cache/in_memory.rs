use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use arc_swap::ArcSwapOption;
use bon::Builder;
use huskarl_core::http::HttpClient;

use crate::{
    cache::{GetTokenError, RefreshTokenStore, TokenCache},
    core::{dpop::AuthorizationServerDPoP, platform::Duration},
    grant::{
        core::{ExchangeError, OAuth2ExchangeGrant, TokenResponse},
        refresh::RefreshGrantParameters,
    },
};

/// Implements an `OAuth2` token cache that stores a [`TokenResponse`] and refreshes
/// it when it expires or is invalidated.
#[derive(Builder)]
#[builder(state_mod(name = "in_memory_token_cache_builder"))]
pub struct InMemoryTokenCache<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    pub(crate) grant: G,
    grant_parameters: Option<G::Parameters>,
    refresh_store: S,
    /// How early to consider a token expired. Shared between [`Self::get_token`] and [`Self::token_expiry`].
    #[builder(default = Duration::from_secs(30))]
    expires_margin: Duration,
    #[builder(skip = grant.dpop().to_resource_server_dpop())]
    resource_server_dpop: <G::DPoP as AuthorizationServerDPoP>::ResourceServerDPoP,
    #[builder(skip)]
    cached: ArcSwapOption<TokenResponse>,
    #[builder(skip)]
    refresh_lock: tokio::sync::Mutex<()>,
    /// Default lifetime assumed for tokens that do not include an `expires_in` field.
    #[builder(default = Duration::from_hours(1))]
    default_expires_in: Duration,
    /// Cached knowledge of whether a refresh token is stored.
    ///
    /// Reflects operations through this instance. Starts `false`; call
    /// [`Self::has_refresh_token`] for accurate state on cold init.
    #[builder(skip)]
    has_refresh_token_cached: AtomicBool,
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> core::fmt::Debug for InMemoryTokenCache<G, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InMemoryTokenCache")
            .field("expires_margin", &self.expires_margin)
            .field("default_expires_in", &self.default_expires_in)
            .finish_non_exhaustive()
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> TokenCache for InMemoryTokenCache<G, S>
where
    G::Parameters: Clone,
{
    type Error<C: HttpClient> = ExchangeError<C, G>;
    type DPoP = <G::DPoP as AuthorizationServerDPoP>::ResourceServerDPoP;

    fn resource_server_dpop(&self) -> &Self::DPoP {
        &self.resource_server_dpop
    }

    async fn get_token<C: HttpClient>(
        &self,
        http_client: &C,
    ) -> Result<Arc<TokenResponse>, GetTokenError<Self::Error<C>>> {
        let maybe_cached_token = self.cached.load_full();
        let mut best_error: Option<Self::Error<C>> = None;

        if let Some(cached_token) = maybe_cached_token
            && !cached_token.is_expired(self.default_expires_in, self.expires_margin)
        {
            return Ok(cached_token);
        }

        let _refresh_lock = self.refresh_lock.lock().await;

        let maybe_cached_token = self.cached.load_full();

        if let Some(cached_token) = maybe_cached_token
            && !cached_token.is_expired(self.default_expires_in, self.expires_margin)
        {
            return Ok(cached_token);
        }

        if let Some(refresh_token) = self.refresh_store.get().await {
            let token_response = self
                .grant
                .to_refresh_grant()
                .exchange(
                    http_client,
                    RefreshGrantParameters::builder()
                        .refresh_token(refresh_token)
                        .build(),
                )
                .await;

            match token_response {
                Ok(token_response) => {
                    let token_response = Arc::new(token_response);

                    self.store_token_response(token_response.clone()).await;

                    return Ok(token_response);
                }
                Err(err) => {
                    self.refresh_store.clear().await;
                    self.has_refresh_token_cached
                        .store(false, Ordering::Relaxed);
                    best_error = Some(err);
                }
            }
        }

        if let Some(params) = self.grant_parameters.clone() {
            match self.grant.exchange(http_client, params).await {
                Ok(token_response) => {
                    let token_response = Arc::new(token_response);
                    self.store_token_response(token_response.clone()).await;
                    Ok(token_response)
                }
                Err(exchange_source) => Err(match best_error {
                    Some(refresh_source) => GetTokenError::BothFailed {
                        refresh_source,
                        exchange_source,
                    },
                    None => GetTokenError::ExchangeFailed {
                        source: exchange_source,
                    },
                }),
            }
        } else {
            match best_error {
                Some(source) => Err(GetTokenError::RefreshFailed { source }),
                None => Err(GetTokenError::NoTokenSource),
            }
        }
    }

    async fn prime(&self, response: TokenResponse) {
        if let Some(refresh_token) = &response.refresh_token {
            self.refresh_store.set(refresh_token).await;
            self.has_refresh_token_cached.store(true, Ordering::Relaxed);
        }

        self.cached.store(Some(Arc::new(response)));
    }

    fn invalidate(&self) {
        self.cached.store(None);
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> InMemoryTokenCache<G, S> {
    /// Returns a reference to the underlying grant.
    pub fn grant(&self) -> &G {
        &self.grant
    }

    /// Returns the effective expiry time and current validity of the cached access token.
    ///
    /// Returns `(expires_at, is_valid)` where `expires_at` is `received_at + expires_in - margin`
    /// and `is_valid` is whether `now < expires_at`. Returns `None` if there is no cached token.
    ///
    /// The margin used here is the same as the one used by [`TokenCache::get_token`], so `is_valid` and
    /// `get_token`'s cache check agree on whether a refresh is needed.
    pub fn token_expiry(&self) -> Option<(crate::core::platform::SystemTime, bool)> {
        let token = self.cached.load_full()?;
        let expiry = token.effective_expiry(self.default_expires_in, self.expires_margin);
        let is_valid = crate::core::platform::SystemTime::now() < expiry;
        Some((expiry, is_valid))
    }

    /// Returns `true` if grant parameters were supplied, enabling fresh token exchanges.
    pub fn has_grant_parameters(&self) -> bool {
        self.grant_parameters.is_some()
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
    pub async fn has_refresh_token(&self) -> bool {
        let has = self.refresh_store.get().await.is_some();
        self.has_refresh_token_cached.store(has, Ordering::Relaxed);
        has
    }

    /// Clears the cached token and the stored refresh token.
    ///
    /// Use this when logging out to ensure no credentials remain.
    pub async fn logout(&self) {
        self.invalidate();
        self.refresh_store.clear().await;
        self.has_refresh_token_cached
            .store(false, Ordering::Relaxed);
    }

    async fn store_token_response(&self, token: Arc<TokenResponse>) {
        self.cached.store(Some(token.clone()));

        if let Some(refresh_token) = token.refresh_token.as_ref() {
            self.refresh_store.set(refresh_token).await;
            self.has_refresh_token_cached.store(true, Ordering::Relaxed);
        } else {
            self.refresh_store.clear().await;
            self.has_refresh_token_cached
                .store(false, Ordering::Relaxed);
        }
    }
}
