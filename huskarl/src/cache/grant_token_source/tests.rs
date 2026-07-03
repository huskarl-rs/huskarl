use std::{collections::VecDeque, sync::Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};

use super::*;
use crate::{
    cache::{InMemoryRefreshTokenStore, NoSource, TokenSource, from_fn, single_use},
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

/// Mock HTTP client serving a fixed queue of responses; any call beyond the
/// queue panics, proving no unexpected request was made.
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
/// observe the store after handing it to the source.
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

/// A store whose `get()` results are scripted, to simulate a peer rotating the
/// token between our refresh attempt and the compare-before-clear re-read.
/// Records whether `clear()` was ever called.
#[derive(Clone, Default)]
struct ScriptedStore {
    gets: Arc<Mutex<VecDeque<Option<RefreshToken>>>>,
    last: Arc<Mutex<Option<RefreshToken>>>,
    cleared: Arc<AtomicBool>,
}

impl ScriptedStore {
    fn script(gets: impl IntoIterator<Item = Option<RefreshToken>>) -> Self {
        Self {
            gets: Arc::new(Mutex::new(gets.into_iter().collect())),
            last: Arc::new(Mutex::new(None)),
            cleared: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl RefreshTokenStore for ScriptedStore {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        let next = self.gets.lock().unwrap().pop_front();
        let value = next.unwrap_or_else(|| self.last.lock().unwrap().clone());
        Box::pin(async move { Ok(value) })
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        *self.last.lock().unwrap() = Some(token.clone());
        Box::pin(async { Ok(()) })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        self.cleared.store(true, Ordering::Relaxed);
        *self.last.lock().unwrap() = None;
        Box::pin(async { Ok(()) })
    }
}

fn refresh_token(value: &str) -> RefreshToken {
    RefreshToken::new(SecretString::new(value), None)
}

fn assert_get_token_error(err: &Error, kind: ErrorKind, matcher: impl Fn(&GetTokenError) -> bool) {
    assert_eq!(err.kind(), kind);
    let source = std::error::Error::source(err)
        .expect("error carries a GetTokenError source")
        .downcast_ref::<GetTokenError>()
        .expect("source is a GetTokenError");
    assert!(matcher(source), "unexpected GetTokenError: {source}");
}

fn assert_reauth_required(err: &Error, matcher: impl Fn(&GetTokenError) -> bool) {
    assert_get_token_error(err, ErrorKind::ReauthRequired, matcher);
}

fn assert_backoff(err: &Error, matcher: impl Fn(&GetTokenError) -> bool) {
    assert_get_token_error(err, ErrorKind::Backoff, matcher);
}

/// A valid (non-expired) token carrying the given refresh token.
fn valid_response(refresh_token: &str) -> TokenResponse {
    RawTokenResponse::builder()
        .access_token(SecretString::new("primed-access-token"))
        .token_type("bearer")
        .expires_in(3600)
        .refresh_token(SecretString::new(refresh_token))
        .build()
        .into_token_response(None, SystemTime::now())
        .expect("valid token response")
}

/// An already-expired token carrying the given refresh token.
fn expired_response_with_refresh(refresh_token: &str) -> TokenResponse {
    RawTokenResponse::builder()
        .access_token(SecretString::new("expired-access-token"))
        .token_type("bearer")
        .expires_in(0)
        .refresh_token(SecretString::new(refresh_token))
        .build()
        .into_token_response(None, SystemTime::now())
        .expect("valid token response")
}

fn client_credentials_grant(http: MockHttpClient) -> ClientCredentialsGrant {
    ClientCredentialsGrant::builder()
        .client_id("client_id")
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .http_client(http)
        .build()
}

fn access_of(token: &TokenResponse) -> String {
    token
        .raw_token_response()
        .access_token
        .expose_secret()
        .to_owned()
}

/// A grant source seeded (via `prime`) with the refresh token `"rt-original"`
/// and its pending token consumed, so the next `token` call must refresh.
async fn primed_source(
    store: SharedRefreshStore,
    http: MockHttpClient,
) -> GrantTokenSource<ClientCredentialsGrant, SharedRefreshStore> {
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http))
        .grant_parameters(NoSource)
        .refresh_store(store)
        .build();
    source.prime(valid_response("rt-original")).await.unwrap();
    // Consume the primed token so the next call exercises the refresh path.
    source.token().await.unwrap();
    source
}

/// Like [`primed_source`], but with reusable grant parameters as a fallback
/// after a failed refresh.
async fn primed_source_with_params(
    store: SharedRefreshStore,
    http: MockHttpClient,
) -> GrantTokenSource<ClientCredentialsGrant, SharedRefreshStore> {
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http))
        .grant_parameters(ClientCredentialsGrantParameters::new())
        .refresh_store(store)
        .build();
    source.prime(valid_response("rt-original")).await.unwrap();
    source.token().await.unwrap();
    source
}

async fn one_time_source(
    store: SharedRefreshStore,
    http: MockHttpClient,
) -> GrantTokenSource<AuthorizationCodeGrant, SharedRefreshStore> {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(http)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    GrantTokenSource::builder()
        .grant(grant)
        .grant_parameters(single_use(
            AuthorizationCodeGrantParameters::builder()
                .code("one-time-code")
                .build(),
        ))
        .refresh_store(store)
        .build()
}

async fn stored_refresh_token(store: &SharedRefreshStore) -> Option<String> {
    store
        .get()
        .await
        .unwrap()
        .map(|t| t.token().expose_secret().to_owned())
}

#[tokio::test]
async fn prime_serves_token_then_refreshes() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(NoSource)
        .refresh_store(store.clone())
        .build();

    source.prime(valid_response("rt-primed")).await.unwrap();
    assert!(source.has_refresh_token().await.unwrap());

    // The primed token is served once with no network call.
    let token = source.token().await.unwrap();
    assert_eq!(access_of(&token), "primed-access-token");
    assert_eq!(
        stored_refresh_token(&store).await.as_deref(),
        Some("rt-primed")
    );

    // Pending consumed: the next call refreshes using the persisted token.
    http.push(
        StatusCode::OK,
        r#"{"access_token":"refreshed","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "refreshed");
}

#[tokio::test]
async fn refresh_response_without_refresh_token_retains_existing() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source(store.clone(), http.clone()).await;

    http.push(
        StatusCode::OK,
        r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600}"#,
    );

    assert_eq!(
        access_of(&source.token().await.unwrap()),
        "new-access-token"
    );

    // RFC 6749 §6: no new refresh token issued means the existing one stays valid.
    assert_eq!(
        stored_refresh_token(&store).await.as_deref(),
        Some("rt-original")
    );
    assert!(source.has_refresh_token().await.unwrap());
}

#[tokio::test]
async fn refresh_response_with_rotated_refresh_token_replaces_existing() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source(store.clone(), http.clone()).await;

    http.push(
        StatusCode::OK,
        r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"rt-rotated"}"#,
    );

    source.token().await.unwrap();

    assert_eq!(
        stored_refresh_token(&store).await.as_deref(),
        Some("rt-rotated")
    );
}

#[tokio::test]
async fn transient_refresh_failure_retains_refresh_token() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source(store.clone(), http.clone()).await;

    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );

    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
        matches!(e, GetTokenError::RefreshFailed { .. })
    });

    assert_eq!(
        stored_refresh_token(&store).await.as_deref(),
        Some("rt-original")
    );
    assert!(source.has_refresh_token().await.unwrap());

    http.push(
        StatusCode::OK,
        r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
}

#[tokio::test]
async fn invalid_grant_clears_refresh_token() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source(store.clone(), http.clone()).await;

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

    let err = source.token().await.unwrap_err();
    assert_reauth_required(&err, |e| matches!(e, GetTokenError::RefreshFailed { .. }));

    assert_eq!(stored_refresh_token(&store).await, None);
    assert!(!source.has_refresh_token().await.unwrap());
}

#[tokio::test]
async fn invalid_grant_with_rotated_token_retries_without_clearing() {
    // A peer sharing the store rotates rt-original → rt-peer while our refresh
    // is in flight, so the compare-before-clear re-read sees a changed token
    // and must retry with it rather than clobber it.
    let store = ScriptedStore::script([
        Some(refresh_token("rt-original")), // attempt 1 refreshes with this
        Some(refresh_token("rt-peer")),     // re-read after invalid_grant: rotated
        Some(refresh_token("rt-peer")),     // attempt 2 refreshes with the new one
    ]);
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(NoSource)
        .refresh_store(store.clone())
        .build();

    // Attempt 1 is rejected; attempt 2 (with the rotated token) succeeds.
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(
        StatusCode::OK,
        r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
    );

    assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
    assert!(
        !store.cleared.load(Ordering::Relaxed),
        "a peer's rotated-in token must not be cleared"
    );
}

#[tokio::test]
async fn can_restore_reflects_credentials() {
    let http = MockHttpClient::default();

    // A configured parameter source is restorable without any store read.
    let with_params = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(ClientCredentialsGrantParameters::new())
        .refresh_store(SharedRefreshStore::default())
        .build();
    assert!(with_params.can_restore(Some(Duration::ZERO)).await.unwrap());

    // Nothing usable: no params, no refresh token, no pending token.
    let empty = GrantTokenSource::builder()
        .grant(client_credentials_grant(http))
        .grant_parameters(NoSource)
        .refresh_store(SharedRefreshStore::default())
        .build();
    assert!(!empty.can_restore(Some(Duration::ZERO)).await.unwrap());
}

#[tokio::test]
async fn can_restore_trusts_cached_view_within_staleness() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http))
        .grant_parameters(NoSource)
        .refresh_store(store.clone())
        .build();

    // Priming records "refresh token present" in the in-memory view; consume
    // the pending token so can_restore reflects the stored token, not pending.
    source.prime(valid_response("rt")).await.unwrap();
    source.token().await.unwrap();

    // A peer clears the shared store behind the source's back: the view is stale.
    store.clear().await.unwrap();

    // `None` trusts the view however stale, so it still reports restorable...
    assert!(source.can_restore(None).await.unwrap());
    // ...while a zero staleness bound forces a re-read and sees the truth.
    assert!(!source.can_restore(Some(Duration::ZERO)).await.unwrap());
}

#[tokio::test]
async fn cache_state_reports_active_restorable_unauthenticated() {
    use crate::cache::{CacheState, InMemoryTokenCache};

    // Active: a primed token is ready to serve.
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(MockHttpClient::default()))
        .grant_parameters(NoSource)
        .refresh_store(SharedRefreshStore::default())
        .build();
    source.prime(valid_response("rt")).await.unwrap();
    let active = InMemoryTokenCache::builder().source(source).build();
    assert_eq!(active.state(None).await.unwrap(), CacheState::Active);

    // Restorable: the cached token has expired, but a stored refresh token can
    // get a new one without interactive login.
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(MockHttpClient::default()))
        .grant_parameters(NoSource)
        .refresh_store(SharedRefreshStore::default())
        .build();
    source
        .prime(expired_response_with_refresh("rt"))
        .await
        .unwrap();
    let restorable = InMemoryTokenCache::builder().source(source).build();
    restorable.token().await.unwrap(); // consume the expired pending token
    assert_eq!(
        restorable.state(None).await.unwrap(),
        CacheState::Restorable
    );

    // Unauthenticated: nothing cached, no credential, no parameter source.
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(MockHttpClient::default()))
        .grant_parameters(NoSource)
        .refresh_store(SharedRefreshStore::default())
        .build();
    let empty = InMemoryTokenCache::builder().source(source).build();
    assert_eq!(
        empty.state(None).await.unwrap(),
        CacheState::Unauthenticated
    );
}

#[tokio::test]
async fn both_failed_transiently_stays_retryable() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source_with_params(store.clone(), http.clone()).await;

    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );
    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );

    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
        matches!(e, GetTokenError::BothFailed { .. })
    });

    http.push(
        StatusCode::OK,
        r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
}

#[tokio::test]
async fn both_failed_definitively_requires_reauth() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source_with_params(store.clone(), http.clone()).await;

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

    let err = source.token().await.unwrap_err();
    assert_reauth_required(&err, |e| matches!(e, GetTokenError::BothFailed { .. }));
    assert_eq!(stored_refresh_token(&store).await, None);
}

#[tokio::test]
async fn one_time_parameters_consumed_by_first_exchange() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = one_time_source(store, http.clone()).await;
    assert!(source.has_grant_parameters());

    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
    );
    source.token().await.unwrap();
    assert!(!source.has_grant_parameters());

    // The spent code must not be replayed: no HTTP call (empty mock would
    // panic), and the error reports that no token source remains.
    let err = source.token().await.unwrap_err();
    assert_reauth_required(&err, |e| matches!(e, GetTokenError::NoTokenSource));
}

#[tokio::test]
async fn one_time_parameters_not_replayed_after_failed_refresh() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = one_time_source(store.clone(), http.clone()).await;

    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":0,"refresh_token":"rt-1"}"#,
    );
    source.token().await.unwrap();

    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );
    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
        matches!(e, GetTokenError::RefreshFailed { .. })
    });

    assert_eq!(stored_refresh_token(&store).await.as_deref(), Some("rt-1"));
}

#[tokio::test]
async fn reusable_parameters_allow_repeated_exchange() {
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
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

    source.token().await.unwrap();
    assert_eq!(access_of(&source.token().await.unwrap()), "t2");
    assert!(source.has_grant_parameters());
}

#[tokio::test]
async fn reusable_parameters_discarded_after_invalid_grant() {
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(ClientCredentialsGrantParameters::new())
        .refresh_store(SharedRefreshStore::default())
        .build();

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    let err = source.token().await.unwrap_err();
    assert_reauth_required(&err, |e| matches!(e, GetTokenError::ExchangeFailed { .. }));

    // The rejected parameters are spent: a second call must not replay them.
    assert!(!source.has_grant_parameters());
    let err = source.token().await.unwrap_err();
    assert_reauth_required(&err, |e| matches!(e, GetTokenError::NoTokenSource));
}

#[tokio::test]
async fn request_rejection_retains_source_and_credential() {
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(ClientCredentialsGrantParameters::new())
        .refresh_store(SharedRefreshStore::default())
        .build();

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);
    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, ErrorKind::RequestRejected, |e| {
        matches!(e, GetTokenError::ExchangeFailed { .. })
    });
    assert!(source.has_grant_parameters());

    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "t1");
}

#[tokio::test]
async fn request_rejection_survives_failed_refresh() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source_with_params(store, http.clone()).await;

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);

    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, ErrorKind::RequestRejected, |e| {
        matches!(e, GetTokenError::BothFailed { .. })
    });
}

#[tokio::test]
async fn reusable_parameters_retained_after_transient_failure() {
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(ClientCredentialsGrantParameters::new())
        .refresh_store(SharedRefreshStore::default())
        .build();

    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );
    let err = source.token().await.unwrap_err();
    assert!(err.is_retryable());
    assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
        matches!(e, GetTokenError::ExchangeFailed { .. })
    });
    assert!(source.has_grant_parameters());

    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "t1");
}

#[tokio::test]
async fn dynamic_source_not_discarded_after_invalid_grant() {
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(from_fn(|| async {
            Ok::<_, Error>(ClientCredentialsGrantParameters::new())
        }))
        .refresh_store(SharedRefreshStore::default())
        .build();

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, ErrorKind::InvalidGrant, |e| {
        matches!(e, GetTokenError::ExchangeFailed { .. })
    });
    assert!(source.has_grant_parameters());

    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "t1");
}

fn dynamic_source(
    http: MockHttpClient,
    threshold: u32,
    cooldown: std::time::Duration,
) -> GrantTokenSource<ClientCredentialsGrant, SharedRefreshStore> {
    GrantTokenSource::builder()
        .grant(client_credentials_grant(http))
        .grant_parameters(from_fn(|| async {
            Ok::<_, Error>(ClientCredentialsGrantParameters::new())
        }))
        .refresh_store(SharedRefreshStore::default())
        .breaker_threshold(threshold)
        .breaker_cooldown(cooldown)
        .build()
}

fn assert_invalid_grant(err: &Error) {
    assert_get_token_error(err, ErrorKind::InvalidGrant, |e| {
        matches!(e, GetTokenError::ExchangeFailed { .. })
    });
}

#[tokio::test]
async fn breaker_trips_after_threshold_and_backs_off() {
    let http = MockHttpClient::default();
    let source = dynamic_source(http.clone(), 2, std::time::Duration::from_mins(1));

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

    // Two non-recoverable failures reach the endpoint...
    assert_invalid_grant(&source.token().await.unwrap_err());
    assert_invalid_grant(&source.token().await.unwrap_err());

    // ...then the breaker is open: the next call backs off without any HTTP
    // (the empty mock would panic if the endpoint were reached). The kind is
    // Backoff — "retry later", not ReauthRequired.
    assert_backoff(&source.token().await.unwrap_err(), |e| {
        matches!(e, GetTokenError::Backoff)
    });
}

#[tokio::test]
async fn breaker_half_opens_after_cooldown() {
    let http = MockHttpClient::default();
    let source = dynamic_source(http.clone(), 1, std::time::Duration::from_millis(10));

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    assert_invalid_grant(&source.token().await.unwrap_err());

    // After the cooldown the breaker half-opens and the next call reaches the
    // endpoint again — here it succeeds, resetting the breaker.
    crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;
    http.push(
        StatusCode::OK,
        r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
}

#[tokio::test]
async fn breaker_resets_on_success() {
    let http = MockHttpClient::default();
    let source = dynamic_source(http.clone(), 2, std::time::Duration::from_mins(1));

    // A success between failures resets the count, so two failures spread
    // across a success never trip the (threshold 2) breaker.
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
    );
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(
        StatusCode::OK,
        r#"{"access_token":"t2","token_type":"bearer","expires_in":3600}"#,
    );

    assert_invalid_grant(&source.token().await.unwrap_err());
    assert_eq!(access_of(&source.token().await.unwrap()), "t1");
    assert_invalid_grant(&source.token().await.unwrap_err());
    // Not backed off (success reset the count): this call reaches the
    // endpoint and the queued success is consumed.
    assert_eq!(access_of(&source.token().await.unwrap()), "t2");
}

#[tokio::test]
async fn breaker_disabled_with_zero_threshold() {
    let http = MockHttpClient::default();
    let source = dynamic_source(http.clone(), 0, std::time::Duration::from_mins(1));

    // Disabled: repeated failures never back off — each call reaches the
    // endpoint and surfaces InvalidGrant.
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    assert_invalid_grant(&source.token().await.unwrap_err());
    assert_invalid_grant(&source.token().await.unwrap_err());
}

#[tokio::test]
async fn open_breaker_does_not_mask_retryable_refresh() {
    // A `from_fn` source (never spent by invalid_grant) trips the breaker
    // while a refresh token is retained through transient failures. Once the
    // breaker is open, a transient refresh failure must surface as a
    // retryable RefreshFailed — an independent recovery path the from-scratch
    // breaker must not mask with its Backoff signal.
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(from_fn(|| async {
            Ok::<_, Error>(ClientCredentialsGrantParameters::new())
        }))
        .refresh_store(store.clone())
        .breaker_threshold(2)
        .build();
    source.prime(valid_response("rt-original")).await.unwrap();
    // Consume the primed token (no network) so the store holds the refresh
    // token and the breaker starts reset.
    source.token().await.unwrap();

    // Two rounds of (transient refresh, invalid_grant exchange) trip the
    // breaker; the refresh token is retained across both.
    for _ in 0..2 {
        http.push(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"temporarily_unavailable"}"#,
        );
        http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        let err = source.token().await.unwrap_err();
        assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
            matches!(e, GetTokenError::BothFailed { .. })
        });
    }

    // Breaker is now open. Only one (transient) refresh response is queued:
    // if the gate fell through to the exchange, the empty mock would panic.
    // The surfaced error is the retryable refresh failure, not Backoff.
    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );
    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, ErrorKind::Transport { retryable: true }, |e| {
        matches!(e, GetTokenError::RefreshFailed { .. })
    });
}
