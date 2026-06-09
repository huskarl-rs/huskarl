use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use arc_swap::ArcSwapOption;
use bon::Builder;

use crate::{
    cache::{GetTokenError, RefreshTokenStore, TokenCache},
    core::{dpop::AuthorizationServerDPoP, http::HttpClient, platform::Duration},
    grant::{
        core::{ExchangeError, OAuth2ExchangeGrant, TokenResponse},
        refresh::RefreshGrantParameters,
    },
};

/// Implements an `OAuth2` token cache that stores a [`TokenResponse`] and refreshes
/// it when it expires or is invalidated.
#[derive(Builder)]
pub struct InMemoryTokenCache<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    pub(crate) grant: G,
    grant_parameters: Option<G::Parameters>,
    refresh_store: S,
    /// How early to consider a token expired. Used by [`Self::get_token_response`].
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

    async fn get_token_response<C: HttpClient>(
        &self,
        http_client: &C,
    ) -> Result<Arc<TokenResponse>, GetTokenError<Self::Error<C>>> {
        if let Some(token) = self.get_valid_cached() {
            return Ok(token);
        }

        let _refresh_lock = self.refresh_lock.lock().await;

        if let Some(token) = self.get_valid_cached() {
            return Ok(token);
        }

        let refresh_error = match self.try_refresh(http_client).await {
            Ok(token) => return Ok(token),
            Err(e) => e,
        };

        let Some(params) = self.grant_parameters.clone() else {
            return match refresh_error {
                Some(source) => Err(GetTokenError::RefreshFailed { source }),
                None => Err(GetTokenError::NoTokenSource),
            };
        };

        match self.grant.exchange(http_client, params).await {
            Ok(token_response) => {
                let token_response = Arc::new(token_response);
                self.store_token_response(token_response.clone()).await;
                Ok(token_response)
            }
            Err(exchange_source) => Err(match refresh_error {
                Some(refresh_source) => GetTokenError::BothFailed {
                    refresh_source,
                    exchange_source,
                },
                None => GetTokenError::ExchangeFailed {
                    source: exchange_source,
                },
            }),
        }
    }

    async fn prime(&self, response: Arc<TokenResponse>) {
        if let Some(refresh_token) = response.refresh_token() {
            self.refresh_store.set(refresh_token).await;
            self.has_refresh_token_cached.store(true, Ordering::Relaxed);
        }

        self.cached.store(Some(response));
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

    fn get_valid_cached(&self) -> Option<Arc<TokenResponse>> {
        self.cached.load_full().filter(|t| {
            !t.access_token()
                .is_expired(self.default_expires_in, self.expires_margin)
        })
    }

    /// Attempts to refresh the token.
    ///
    /// Returns `Ok(token)` on success, `Err(Some(error))` if refresh failed,
    /// or `Err(None)` if no refresh token is available.
    ///
    /// The stored refresh token is discarded only when the server definitively
    /// rejects it with `invalid_grant` (RFC 6749 §5.2). Transient failures
    /// (network errors, 5xx responses) leave it in place for later attempts.
    async fn try_refresh<C: HttpClient>(
        &self,
        http_client: &C,
    ) -> Result<Arc<TokenResponse>, Option<ExchangeError<C, G>>> {
        let refresh_token = self.refresh_store.get().await.ok_or(None)?;

        match self
            .grant
            .to_refresh_grant()
            .exchange(
                http_client,
                RefreshGrantParameters::builder()
                    .refresh_token(refresh_token)
                    .build(),
            )
            .await
        {
            Ok(token_response) => {
                let token_response = Arc::new(token_response);
                self.store_token_response(token_response.clone()).await;
                Ok(token_response)
            }
            Err(err) => {
                if err.is_invalid_grant() {
                    self.refresh_store.clear().await;
                    self.has_refresh_token_cached
                        .store(false, Ordering::Relaxed);
                }
                Err(Some(err))
            }
        }
    }

    /// Caches the token response, storing its refresh token if one is present.
    ///
    /// When the response carries no refresh token, any previously stored refresh
    /// token is retained: per RFC 6749 §6 the authorization server may omit the
    /// refresh token from a refresh response, in which case the client keeps
    /// using the existing one.
    async fn store_token_response(&self, token: Arc<TokenResponse>) {
        self.cached.store(Some(token.clone()));

        if let Some(refresh_token) = token.refresh_token().as_ref() {
            self.refresh_store.set(refresh_token).await;
            self.has_refresh_token_cached.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, StatusCode};

    use super::*;
    use crate::{
        cache::InMemoryRefreshTokenStore,
        core::{
            client_auth::NoAuth, dpop::NoDPoP, http::HttpResponse, platform::SystemTime,
            secrets::SecretString,
        },
        grant::{
            client_credentials::ClientCredentialsGrant, core::token_response::RawTokenResponse,
        },
        token::RefreshToken,
    };

    struct MockResponse {
        status: StatusCode,
        body: Bytes,
    }

    impl HttpResponse for MockResponse {
        type Error = Infallible;

        fn status(&self) -> StatusCode {
            self.status
        }

        fn headers(&self) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            headers
        }

        async fn body(self) -> Result<Bytes, Infallible> {
            Ok(self.body)
        }
    }

    /// Mock HTTP client that returns a preconfigured response once.
    struct MockHttpClient {
        response: std::sync::Mutex<Option<MockResponse>>,
    }

    impl MockHttpClient {
        fn new(status: StatusCode, body: &str) -> Self {
            Self {
                response: std::sync::Mutex::new(Some(MockResponse {
                    status,
                    body: Bytes::copy_from_slice(body.as_bytes()),
                })),
            }
        }
    }

    impl HttpClient for MockHttpClient {
        type Response = MockResponse;
        type Error = Infallible;
        type ResponseError = Infallible;

        async fn execute(
            &self,
            _request: http::Request<Bytes>,
        ) -> Result<MockResponse, Infallible> {
            Ok(self
                .response
                .lock()
                .unwrap()
                .take()
                .expect("MockHttpClient can only be called once"))
        }
    }

    /// Cloneable handle over an [`InMemoryRefreshTokenStore`] so tests can
    /// observe the store after handing it to the cache.
    #[derive(Clone, Default)]
    struct SharedRefreshStore(Arc<InMemoryRefreshTokenStore>);

    impl RefreshTokenStore for SharedRefreshStore {
        async fn get(&self) -> Option<RefreshToken> {
            self.0.get().await
        }

        async fn set(&self, token: &RefreshToken) {
            self.0.set(token).await;
        }

        async fn clear(&self) {
            self.0.clear().await;
        }
    }

    /// Builds a cache primed with an already-expired access token and the
    /// refresh token `"rt-original"`, so the next `get_token_response` call
    /// must attempt a refresh.
    async fn primed_cache(
        store: SharedRefreshStore,
    ) -> InMemoryTokenCache<ClientCredentialsGrant<NoAuth, NoDPoP>, SharedRefreshStore> {
        let cache = InMemoryTokenCache::builder()
            .grant(
                ClientCredentialsGrant::builder()
                    .client_id("client_id")
                    .client_auth(NoAuth)
                    .token_endpoint("https://as.example.com/token")
                    .unwrap()
                    .dpop(NoDPoP)
                    .build(),
            )
            .refresh_store(store)
            .build();

        let expired = RawTokenResponse::builder()
            .access_token(SecretString::new("expired-access-token"))
            .token_type("bearer")
            .expires_in(0)
            .refresh_token(SecretString::new("rt-original"))
            .build()
            .into_token_response(None, SystemTime::now())
            .expect("valid token response");
        cache.prime(Arc::new(expired)).await;

        cache
    }

    async fn stored_refresh_token(store: &SharedRefreshStore) -> Option<String> {
        store
            .get()
            .await
            .map(|t| t.token().expose_secret().to_owned())
    }

    #[tokio::test]
    async fn refresh_response_without_refresh_token_retains_existing() {
        let store = SharedRefreshStore::default();
        let cache = primed_cache(store.clone()).await;

        let http = MockHttpClient::new(
            StatusCode::OK,
            r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600}"#,
        );

        let token = cache.get_token_response(&http).await.unwrap();
        assert_eq!(
            token.raw_token_response().access_token.expose_secret(),
            "new-access-token"
        );

        // RFC 6749 §6: no new refresh token issued means the existing one stays valid.
        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-original")
        );
        assert!(cache.has_refresh_token_cached());
    }

    #[tokio::test]
    async fn refresh_response_with_rotated_refresh_token_replaces_existing() {
        let store = SharedRefreshStore::default();
        let cache = primed_cache(store.clone()).await;

        let http = MockHttpClient::new(
            StatusCode::OK,
            r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"rt-rotated"}"#,
        );

        cache.get_token_response(&http).await.unwrap();

        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-rotated")
        );
    }

    #[tokio::test]
    async fn transient_refresh_failure_retains_refresh_token() {
        let store = SharedRefreshStore::default();
        let cache = primed_cache(store.clone()).await;

        let http = MockHttpClient::new(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );

        let err = cache.get_token_response(&http).await.unwrap_err();
        assert!(matches!(err, GetTokenError::RefreshFailed { .. }));

        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-original")
        );
        assert!(cache.has_refresh_token_cached());
    }

    #[tokio::test]
    async fn invalid_grant_clears_refresh_token() {
        let store = SharedRefreshStore::default();
        let cache = primed_cache(store.clone()).await;

        let http = MockHttpClient::new(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

        let err = cache.get_token_response(&http).await.unwrap_err();
        assert!(matches!(err, GetTokenError::RefreshFailed { .. }));

        assert_eq!(stored_refresh_token(&store).await, None);
        assert!(!cache.has_refresh_token_cached());
    }
}
