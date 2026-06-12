use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use arc_swap::ArcSwapOption;
use bon::Builder;

use crate::{
    cache::{GetTokenError, RefreshTokenStore, TokenCache},
    core::{
        Error, ErrorKind,
        dpop::ResourceServerDPoP,
        platform::{Duration, MaybeSendBoxFuture},
    },
    grant::{
        core::{OAuth2ExchangeGrant, TokenResponse},
        refresh::RefreshGrantParameters,
    },
};

/// Implements an `OAuth2` token cache that stores a [`TokenResponse`] and refreshes
/// it when it expires or is invalidated.
#[derive(Builder)]
pub struct InMemoryTokenCache<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    pub(crate) grant: G,
    /// Parameters used to obtain a token directly from the grant when no
    /// cached token or refresh token is usable.
    ///
    /// For grants whose parameters are single-use
    /// ([`OAuth2ExchangeGrant::reusable_parameters`] is `false`, e.g. an
    /// authorization code or device code), these are consumed by the first
    /// exchange attempt and never replayed: re-submitting a redeemed code
    /// always fails and may cause the authorization server to revoke the
    /// tokens it previously issued for it (RFC 6749 §4.1.2).
    #[builder(default, with = |params: G::Parameters| Mutex::new(Some(params)))]
    grant_parameters: Mutex<Option<G::Parameters>>,
    refresh_store: S,
    /// How early to consider a token expired. Used by [`Self::get_token_response`].
    #[builder(default = Duration::from_secs(30))]
    expires_margin: Duration,
    #[builder(skip = grant.dpop().to_resource_server_dpop())]
    resource_server_dpop: Arc<dyn ResourceServerDPoP>,
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
    fn get_token_response(&self) -> MaybeSendBoxFuture<'_, Result<Arc<TokenResponse>, Error>> {
        Box::pin(self.get_token_response_inner())
    }

    fn resource_server_dpop(&self) -> &dyn ResourceServerDPoP {
        self.resource_server_dpop.as_ref()
    }

    fn prime(&self, response: Arc<TokenResponse>) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            if let Some(refresh_token) = response.refresh_token() {
                self.refresh_store.set(refresh_token).await?;
                self.has_refresh_token_cached.store(true, Ordering::Relaxed);
            }

            self.cached.store(Some(response));
            Ok(())
        })
    }

    fn invalidate(&self) {
        self.cached.store(None);
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> InMemoryTokenCache<G, S>
where
    G::Parameters: Clone,
{
    async fn get_token_response_inner(&self) -> Result<Arc<TokenResponse>, Error> {
        if let Some(token) = self.get_valid_cached() {
            return Ok(token);
        }

        let _refresh_lock = self.refresh_lock.lock().await;

        if let Some(token) = self.get_valid_cached() {
            return Ok(token);
        }

        let refresh_error = match self.try_refresh().await {
            Ok(token) => return Ok(token),
            Err(e) => e,
        };

        let params = {
            let mut guard = self
                .grant_parameters
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if self.grant.reusable_parameters() {
                guard.clone()
            } else {
                // Single-use parameters (e.g. an authorization code) are
                // consumed by this one attempt, succeed or fail; replaying
                // them is futile and hazardous (RFC 6749 §4.1.2).
                guard.take()
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
                let token_response = Arc::new(token_response);
                self.store_token_response(token_response.clone()).await;
                Ok(token_response)
            }
            Err(exchange_source) => Err(match refresh_error {
                Some(refresh_source) => {
                    // ReauthRequired only when no automatic path remains. A
                    // retryable exchange with reusable parameters, or a
                    // retryable refresh (the refresh token was retained), can
                    // both succeed on a later call without re-running the
                    // interactive flow.
                    let kind = if self.grant.reusable_parameters() && exchange_source.is_retryable()
                    {
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
                // No refresh was attempted: surface the exchange error with
                // its own classification (e.g. a retryable transport failure).
                None => exchange_source,
            }),
        }
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> InMemoryTokenCache<G, S> {
    /// Returns a reference to the underlying grant.
    pub fn grant(&self) -> &G {
        &self.grant
    }

    /// Returns `true` if grant parameters are available for a fresh token exchange.
    ///
    /// For grants with single-use parameters
    /// ([`OAuth2ExchangeGrant::reusable_parameters`] is `false`), this becomes
    /// `false` once the parameters have been consumed by an exchange attempt.
    pub fn has_grant_parameters(&self) -> bool {
        self.grant_parameters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
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

    /// Clears the cached token and the stored refresh token.
    ///
    /// Use this when logging out to ensure no credentials remain.
    ///
    /// # Errors
    ///
    /// Returns an error if clearing the underlying [`RefreshTokenStore`]
    /// fails; the in-memory token is dropped regardless.
    pub async fn logout(&self) -> Result<(), Error> {
        self.invalidate();
        self.refresh_store.clear().await?;
        self.has_refresh_token_cached
            .store(false, Ordering::Relaxed);
        Ok(())
    }

    fn get_valid_cached(&self) -> Option<Arc<TokenResponse>> {
        self.cached.load_full().filter(|t| {
            !t.access_token()
                .is_expired(self.default_expires_in, self.expires_margin)
        })
    }

    /// Attempts to refresh the token.
    ///
    /// Returns `Ok(token)` on success, `Err(Some(error))` if the store or the
    /// refresh failed, or `Err(None)` if no refresh token is available.
    ///
    /// The stored refresh token is discarded only when the server definitively
    /// rejects it with `invalid_grant` (RFC 6749 §5.2). Transient failures
    /// (network errors, 5xx responses) leave it in place for later attempts.
    async fn try_refresh(&self) -> Result<Arc<TokenResponse>, Option<Error>> {
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
                let token_response = Arc::new(token_response);
                self.store_token_response(token_response.clone()).await;
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

    /// Caches the token response, storing its refresh token if one is present.
    ///
    /// When the response carries no refresh token, any previously stored refresh
    /// token is retained: per RFC 6749 §6 the authorization server may omit the
    /// refresh token from a refresh response, in which case the client keeps
    /// using the existing one.
    async fn store_token_response(&self, token: Arc<TokenResponse>) {
        self.cached.store(Some(token.clone()));

        if let Some(refresh_token) = token.refresh_token().as_ref() {
            // The exchange succeeded and the token is already cached, so a
            // failure to persist the refresh token must not fail the
            // acquisition; the cost is falling back to the grant parameters
            // once this token expires.
            if self.refresh_store.set(refresh_token).await.is_ok() {
                self.has_refresh_token_cached.store(true, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, StatusCode};

    use super::*;
    use crate::{
        cache::InMemoryRefreshTokenStore,
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

    /// Mock HTTP client serving a fixed queue of responses; any call beyond
    /// the queue panics, proving no unexpected request was made. Cloneable
    /// handle over a shared queue so tests can push responses after handing
    /// the client to a grant.
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
    /// observe the store after handing it to the cache.
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

    /// Asserts the error has the given kind and wraps the given
    /// [`GetTokenError`] case.
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

    /// Asserts the error wraps the given [`GetTokenError`] case under
    /// [`ErrorKind::ReauthRequired`].
    fn assert_reauth_required(err: &Error, matcher: impl Fn(&GetTokenError) -> bool) {
        assert_get_token_error(err, ErrorKind::ReauthRequired, matcher);
    }

    /// An already-expired access token carrying the refresh token
    /// `"rt-original"`.
    fn expired_response() -> Arc<TokenResponse> {
        let expired = RawTokenResponse::builder()
            .access_token(SecretString::new("expired-access-token"))
            .token_type("bearer")
            .expires_in(0)
            .refresh_token(SecretString::new("rt-original"))
            .build()
            .into_token_response(None, SystemTime::now())
            .expect("valid token response");
        Arc::new(expired)
    }

    fn client_credentials_grant(http: MockHttpClient) -> ClientCredentialsGrant {
        ClientCredentialsGrant::builder()
            .client_id("client_id")
            .client_auth(NoAuth)
            .token_endpoint("https://as.example.com/token")
            .unwrap()
            .http_client(http)
            .build()
    }

    /// Builds a cache primed with an already-expired access token and the
    /// refresh token `"rt-original"`, so the next `get_token_response` call
    /// must attempt a refresh.
    async fn primed_cache(
        store: SharedRefreshStore,
        http: MockHttpClient,
    ) -> InMemoryTokenCache<ClientCredentialsGrant, SharedRefreshStore> {
        let cache = InMemoryTokenCache::builder()
            .grant(client_credentials_grant(http))
            .refresh_store(store)
            .build();
        cache.prime(expired_response()).await.unwrap();
        cache
    }

    /// Like [`primed_cache`], but with reusable grant parameters available as
    /// an exchange fallback after a failed refresh.
    async fn primed_cache_with_params(
        store: SharedRefreshStore,
        http: MockHttpClient,
    ) -> InMemoryTokenCache<ClientCredentialsGrant, SharedRefreshStore> {
        let cache = InMemoryTokenCache::builder()
            .grant(client_credentials_grant(http))
            .grant_parameters(ClientCredentialsGrantParameters::new())
            .refresh_store(store)
            .build();
        cache.prime(expired_response()).await.unwrap();
        cache
    }

    async fn stored_refresh_token(store: &SharedRefreshStore) -> Option<String> {
        store
            .get()
            .await
            .unwrap()
            .map(|t| t.token().expose_secret().to_owned())
    }

    #[tokio::test]
    async fn refresh_response_without_refresh_token_retains_existing() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let cache = primed_cache(store.clone(), http.clone()).await;

        http.push(
            StatusCode::OK,
            r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600}"#,
        );

        let token = cache.get_token_response().await.unwrap();
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
        let http = MockHttpClient::default();
        let cache = primed_cache(store.clone(), http.clone()).await;

        http.push(
            StatusCode::OK,
            r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"rt-rotated"}"#,
        );

        cache.get_token_response().await.unwrap();

        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-rotated")
        );
    }

    #[tokio::test]
    async fn transient_refresh_failure_retains_refresh_token() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let cache = primed_cache(store.clone(), http.clone()).await;

        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );

        // Not a reauth signal: the refresh token is retained and a later call
        // can succeed, so the retryable transport classification is kept.
        let err = cache.get_token_response().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::RefreshFailed { .. })
        });

        assert_eq!(
            stored_refresh_token(&store).await.as_deref(),
            Some("rt-original")
        );
        assert!(cache.has_refresh_token_cached());

        // The advertised retry path works: the next call refreshes with the
        // retained token and succeeds.
        http.push(
            StatusCode::OK,
            r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
        );
        let token = cache.get_token_response().await.unwrap();
        assert_eq!(
            token.raw_token_response().access_token.expose_secret(),
            "recovered"
        );
    }

    #[tokio::test]
    async fn invalid_grant_clears_refresh_token() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let cache = primed_cache(store.clone(), http.clone()).await;

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

        let err = cache.get_token_response().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::RefreshFailed { .. }));

        assert_eq!(stored_refresh_token(&store).await, None);
        assert!(!cache.has_refresh_token_cached());
    }

    /// Transient failures of both the refresh and the fallback exchange stay
    /// retryable for a grant with reusable parameters: a later call can
    /// succeed without re-running any interactive flow.
    #[tokio::test]
    async fn both_failed_transiently_stays_retryable() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let cache = primed_cache_with_params(store.clone(), http.clone()).await;

        // Refresh attempt, then the fallback exchange, both 503.
        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );
        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );

        let err = cache.get_token_response().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::BothFailed { .. })
        });

        // The advertised retry path works: the retained refresh token is
        // tried first and succeeds.
        http.push(
            StatusCode::OK,
            r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
        );
        let token = cache.get_token_response().await.unwrap();
        assert_eq!(
            token.raw_token_response().access_token.expose_secret(),
            "recovered"
        );
    }

    /// When both paths fail definitively, no automatic recovery remains and
    /// the error is the reauth signal.
    #[tokio::test]
    async fn both_failed_definitively_requires_reauth() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let cache = primed_cache_with_params(store.clone(), http.clone()).await;

        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

        let err = cache.get_token_response().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::BothFailed { .. }));
        assert_eq!(stored_refresh_token(&store).await, None);
    }

    /// Builds a cache around an authorization code grant (single-use
    /// parameters) holding the code `"one-time-code"`.
    async fn one_time_cache(
        store: SharedRefreshStore,
        http: MockHttpClient,
    ) -> InMemoryTokenCache<AuthorizationCodeGrant, SharedRefreshStore> {
        let grant = AuthorizationCodeGrant::builder()
            .client_id("client")
            .client_auth(NoAuth)
            .http_client(http)
            .token_endpoint("https://as.example.com/token")
            .unwrap()
            .authorization_endpoint("https://as.example.com/authorize")
            .unwrap()
            .redirect_uri("http://127.0.0.1/cb")
            .build()
            .await
            .unwrap();

        InMemoryTokenCache::builder()
            .grant(grant)
            .grant_parameters(
                AuthorizationCodeGrantParameters::builder()
                    .code("one-time-code")
                    .build(),
            )
            .refresh_store(store)
            .build()
    }

    #[tokio::test]
    async fn one_time_parameters_consumed_by_first_exchange() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let cache = one_time_cache(store, http.clone()).await;
        assert!(cache.has_grant_parameters());

        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
        );
        cache.get_token_response().await.unwrap();
        assert!(!cache.has_grant_parameters());

        // With the cached token invalidated and no refresh token, the spent
        // code must not be replayed: no HTTP call (empty mock would panic),
        // and the error reports that no token source remains.
        cache.invalidate();
        let err = cache.get_token_response().await.unwrap_err();
        assert_reauth_required(&err, |e| matches!(e, GetTokenError::NoTokenSource));
    }

    #[tokio::test]
    async fn one_time_parameters_not_replayed_after_failed_refresh() {
        let store = SharedRefreshStore::default();
        let http = MockHttpClient::default();
        let cache = one_time_cache(store.clone(), http.clone()).await;

        // First acquisition redeems the code for an already-expired access
        // token plus a refresh token.
        http.push(
            StatusCode::OK,
            r#"{"access_token":"t1","token_type":"bearer","expires_in":0,"refresh_token":"rt-1"}"#,
        );
        cache.get_token_response().await.unwrap();

        // The next call must refresh. When the refresh fails, the spent code
        // must not be replayed as a fallback (a second request would exhaust
        // the mock and panic); the refresh error is surfaced instead — as
        // retryable, since the retained refresh token makes a retry viable.
        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );
        let err = cache.get_token_response().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::RefreshFailed { .. })
        });

        // The transiently-failed refresh token is retained for later retries.
        assert_eq!(stored_refresh_token(&store).await.as_deref(), Some("rt-1"));
    }

    #[tokio::test]
    async fn reusable_parameters_allow_repeated_exchange() {
        let http = MockHttpClient::default();
        let cache = InMemoryTokenCache::builder()
            .grant(
                ClientCredentialsGrant::builder()
                    .client_id("client")
                    .client_auth(NoAuth)
                    .token_endpoint("https://as.example.com/token")
                    .unwrap()
                    .http_client(http.clone())
                    .build(),
            )
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

        cache.get_token_response().await.unwrap();
        cache.invalidate();
        let token = cache.get_token_response().await.unwrap();
        assert_eq!(
            token.raw_token_response().access_token.expose_secret(),
            "t2"
        );
        assert!(cache.has_grant_parameters());
    }
}
