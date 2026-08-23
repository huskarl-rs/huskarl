use std::{collections::VecDeque, sync::Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};

use super::*;
use crate::{
    cache::{InMemoryRefreshTokenStore, NoSource, TokenSource, from_fn, single_use},
    core::{
        OAuthError,
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

fn assert_get_token_error(err: &TokenError, advice: RetryAdvice) {
    assert_eq!(err.as_error().retry_advice(), advice, "advice");
}

/// Asserts on the remedy alone: the error carries whichever underlying failure
/// exhausted the source, so pinning more would test the upstream failure rather
/// than the source's own verdict.
fn assert_reauth_required(err: &TokenError) {
    assert_eq!(err.recovery(), Recovery::Reauthenticate, "recovery");
}

/// A source in cooldown reports a retry that *carries* the remaining interval,
/// so assert the shape rather than a wall-clock value.
fn assert_backoff(err: &TokenError) {
    assert!(
        matches!(err.recovery(), Recovery::Retry { after: Some(_) }),
        "expected a retry carrying a cooldown, got {:?}",
        err.recovery()
    );
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
        r#"{"access_token":"new-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"rt-rotated"}"#);

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
    assert_get_token_error(&err, RetryAdvice::RETRY);

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

/// A refresh the AS answered `invalid_scope` is a live path, not an exhausted
/// one: RFC 6749 §6 permits `scope` on a refresh request, and only
/// `invalid_grant` retires the stored token — so the credential is still there
/// and narrowing the request is something the caller can do unaided.
///
/// Judging a refresh by `RetryAdvice` alone reported `Reauthenticate` here,
/// sending a user to log in over a scope. Both alternatives now ask the same
/// question, so neither is held to a stricter standard than the other.
#[tokio::test]
async fn request_shaped_refresh_failure_is_adjustable_not_exhausted() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    // `NoSource`: the refresh token is the only path, so if it is judged
    // exhausted there is nothing else to mask the verdict.
    let source = primed_source(store.clone(), http.clone()).await;

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);

    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, RetryAdvice::No);
    assert_eq!(err.recovery(), Recovery::AdjustRequest);

    // The verdict survives, which is what tells the caller *what* to adjust.
    assert_eq!(
        err.verdict().map(|v| v.code().as_str()),
        Some("invalid_scope")
    );

    // And the claim the recovery rests on: the credential was never retired.
    assert_eq!(
        stored_refresh_token(&store).await.as_deref(),
        Some("rt-original")
    );
    http.push(
        StatusCode::OK,
        r#"{"access_token":"narrowed","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "narrowed");
}

/// The same rule where both alternatives failed, and the mirror of
/// `request_rejection_survives_failed_refresh`: there the adjustable code came
/// from the exchange, here from the refresh. The two must answer alike.
#[tokio::test]
async fn request_shaped_refresh_failure_survives_a_dead_exchange() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source_with_params(store.clone(), http.clone()).await;

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, RetryAdvice::No);
    assert_eq!(err.recovery(), Recovery::AdjustRequest);
    // The reported failure is the live path's, not the dead exchange's, so the
    // code names the thing the caller can actually change.
    assert_eq!(
        err.verdict().map(|v| v.code().as_str()),
        Some("invalid_scope")
    );
    assert_eq!(
        stored_refresh_token(&store).await.as_deref(),
        Some("rt-original")
    );
}

#[tokio::test]
async fn invalid_grant_clears_refresh_token() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source(store.clone(), http.clone()).await;

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

    let err = source.token().await.unwrap_err();
    assert_reauth_required(&err);

    // Exhaustion overrides the *advice* and nothing else. The refresh failure's
    // whole classification still travels outward, so a caller at the top can
    // still see what the server decided and on what response — rebuilding this
    // layer from the advice alone left a rejection that never said what was
    // rejected, and an `http_status` of `None` on a failure that plainly had
    // one.
    assert!(
        err.verdict()
            .is_some_and(|v| v.code() == &OAuthErrorCode::InvalidGrant),
        "the server's verdict must survive exhaustion: {err:?}"
    );

    assert_eq!(stored_refresh_token(&store).await, None);
    assert!(!source.has_refresh_token().await.unwrap());
}

/// The status-over-body rule, at the site where getting it wrong costs most.
/// RFC 6749 §5.2 puts error codes on 4xx, so `invalid_grant` in a gateway's
/// 503 body is an echo and not a verdict on this token. Clearing it would
/// retire a working credential over an outage — and leave nothing to fall
/// back to once the outage lifted.
#[tokio::test]
async fn invalid_grant_echoed_on_a_5xx_retains_the_refresh_token() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = primed_source(store.clone(), http.clone()).await;

    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"invalid_grant"}"#,
    );

    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, RetryAdvice::RETRY);

    assert_eq!(
        stored_refresh_token(&store).await.as_deref(),
        Some("rt-original")
    );

    // And it is still there to succeed with once the outage lifts.
    http.push(
        StatusCode::OK,
        r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
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
    assert_get_token_error(&err, RetryAdvice::RETRY);

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
    assert_reauth_required(&err);
    assert_eq!(stored_refresh_token(&store).await, None);
}

/// **The invariant the four-way match in `combine_exchange_error` exists to
/// hold.** [`Recovery::Reauthenticate`] claims every alternative is spent, so it
/// may be reported only where neither is — and where one survives, the remedy
/// must be that survivor's own, or a caller with a path left is sent to fetch a
/// human anyway.
///
/// A table over the cross-product rather than a scenario per arm. It separates
/// an attempt's actionable classification from a source that can mint a
/// different credential, while preserving an explicit server demand for human
/// interaction. Driven directly because the property belongs to the combining
/// rule, not to any particular pair of responses.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the cross-product and its expected decision table belong together"
)]
fn reauthentication_is_reported_only_when_neither_alternative_is_viable() {
    fn rejected(code: &str) -> Error {
        Error::propagate(
            crate::core::error::propagation::Classification::judged(
                RetryAdvice::No,
                OAuthError::new(code),
            ),
            "the token endpoint",
        )
    }

    /// One failure an attempt can end in, and whether it leaves a path of its
    /// own. Built per use, since an `Error` is consumed by the combine.
    #[derive(Clone, Copy)]
    struct Failure {
        label: &'static str,
        build: fn() -> Error,
        implied_recovery: Recovery,
        live: bool,
        source_can_recover: bool,
    }

    let failures = [
        Failure {
            label: "a transport timeout",
            build: || Error::new(RetryAdvice::RETRY, "the endpoint timed out"),
            implied_recovery: Recovery::Retry { after: None },
            live: true,
            source_can_recover: true,
        },
        Failure {
            label: "an invalid_scope rejection",
            build: || rejected("invalid_scope"),
            implied_recovery: Recovery::AdjustRequest,
            live: true,
            source_can_recover: true,
        },
        Failure {
            label: "an invalid_grant rejection",
            build: || rejected("invalid_grant"),
            implied_recovery: Recovery::Fail,
            live: false,
            source_can_recover: true,
        },
        Failure {
            label: "a login_required rejection",
            build: || rejected("login_required"),
            implied_recovery: Recovery::Reauthenticate,
            live: false,
            source_can_recover: false,
        },
    ];

    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(MockHttpClient::default()))
        .grant_parameters(ClientCredentialsGrantParameters::new())
        .refresh_store(SharedRefreshStore::default())
        .build();

    for exchange in failures {
        for refresh in failures {
            for source_available in [true, false] {
                // A rejected exchange is a path only while the parameter source
                // could produce something different next time; a retained
                // refresh token needs no such permission.
                let anything_left =
                    (source_available && exchange.source_can_recover) || refresh.live;
                let expected_attempt = if !(source_available && exchange.live) && refresh.live {
                    Attempt::Refresh
                } else {
                    Attempt::Exchange
                };
                let expected_recovery = if anything_left {
                    match expected_attempt {
                        Attempt::Refresh => refresh.implied_recovery,
                        Attempt::Exchange
                            if source_available && exchange.implied_recovery == Recovery::Fail =>
                        {
                            Recovery::Retry { after: None }
                        }
                        Attempt::Exchange => exchange.implied_recovery,
                    }
                } else {
                    Recovery::Reauthenticate
                };
                let err = source.combine_exchange_error(
                    Some((refresh.build)()),
                    (exchange.build)(),
                    source_available,
                );
                let case = format!(
                    "exchange: {}, refresh: {}, source_available: {source_available}",
                    exchange.label, refresh.label
                );

                assert_eq!(err.recovery(), expected_recovery, "wrong recovery — {case}");

                let acquisition_cause = err
                    .as_error()
                    .cause()
                    .downcast_ref::<GetTokenError>()
                    .expect("combine produces a GetTokenError");
                let GetTokenError::BothFailed {
                    reported_attempt, ..
                } = acquisition_cause
                else {
                    panic!("combine with two failures must report BothFailed — {case}")
                };
                assert_eq!(
                    *reported_attempt, expected_attempt,
                    "wrong attempt selected for reporting — {case}"
                );
            }
        }
    }
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
    assert_reauth_required(&err);
}

/// Retry advice describes the failed HTTP operation; recovery describes the
/// token source after its one-time parameters have been consumed. Preserve both
/// facts even when they differ.
#[tokio::test]
async fn exhausted_one_time_source_preserves_underlying_retry_advice() {
    let http = MockHttpClient::default();
    let source = one_time_source(SharedRefreshStore::default(), http.clone()).await;

    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );
    let err = source.token().await.unwrap_err();

    assert_eq!(err.recovery(), Recovery::Reauthenticate);
    assert_eq!(err.as_error().retry_advice(), RetryAdvice::RETRY);
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
    assert_get_token_error(&err, RetryAdvice::RETRY);

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
    assert_reauth_required(&err);

    // The rejected parameters are spent: a second call must not replay them.
    assert!(!source.has_grant_parameters());
    let err = source.token().await.unwrap_err();
    assert_reauth_required(&err);
}

/// The same echo at the exchange. Spending the source here would turn one
/// gateway outage into a permanent `NoTokenSource` and send the caller to
/// re-authenticate over a credential nothing ever judged.
#[tokio::test]
async fn invalid_grant_echoed_on_a_5xx_retains_the_parameters() {
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(ClientCredentialsGrantParameters::new())
        .refresh_store(SharedRefreshStore::default())
        .build();

    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"invalid_grant"}"#,
    );
    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, RetryAdvice::RETRY);
    assert_eq!(
        err.recovery(),
        Recovery::Retry { after: None },
        "an outage is something to wait out, not to re-authenticate over"
    );

    // Not spent: the next call replays them and succeeds once the AS is back.
    assert!(source.has_grant_parameters());
    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "t1");
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
    assert_get_token_error(&err, RetryAdvice::No);
    // The scope, not the credential, is what the server named — so the caller
    // is told to adjust rather than to re-authenticate.
    assert_eq!(err.recovery(), Recovery::AdjustRequest);
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
    assert_get_token_error(&err, RetryAdvice::No);
    assert_eq!(err.recovery(), Recovery::AdjustRequest);
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
    assert_get_token_error(&err, RetryAdvice::RETRY);
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
    // Not `Reauthenticate`. The next call in this very test succeeds without
    // any user involvement, so demanding an interactive login here would send
    // a human through a flow one automatic attempt short of working.
    assert_get_token_error(&err, RetryAdvice::No);
    assert!(
        err.verdict()
            .is_some_and(|v| v.code() == &OAuthErrorCode::InvalidGrant)
    );
    assert!(source.has_grant_parameters());

    http.push(
        StatusCode::OK,
        r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "t1");
}

/// A rejected refresh does not turn a subsequent rejection of one dynamically
/// minted credential into exhaustion. The next mint can still succeed.
#[tokio::test]
async fn dynamic_source_survives_invalid_grant_after_failed_refresh() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(from_fn(|| async {
            Ok::<_, Error>(ClientCredentialsGrantParameters::new())
        }))
        .refresh_store(store)
        .build();
    source.prime(valid_response("rt-original")).await.unwrap();
    source.token().await.unwrap();

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    let err = source.token().await.unwrap_err();
    assert_eq!(err.recovery(), Recovery::Retry { after: None });
    assert!(
        err.verdict()
            .is_some_and(|v| v.code() == &OAuthErrorCode::InvalidGrant)
    );
    assert!(source.has_grant_parameters());

    http.push(
        StatusCode::OK,
        r#"{"access_token":"recovered","token_type":"bearer","expires_in":3600}"#,
    );
    assert_eq!(access_of(&source.token().await.unwrap()), "recovered");
}

/// A parameter source can know a retry interval that the token source cannot
/// reconstruct, such as a KMS throttle returned over gRPC. Preserve it through
/// combination with a failed refresh.
#[tokio::test]
async fn parameter_source_retry_delay_survives_failed_refresh() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let delay = Duration::from_secs(17);
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(from_fn(move || async move {
            Err::<ClientCredentialsGrantParameters, _>(Error::new(
                RetryAdvice::retry_after(delay),
                "the KMS is throttling signing requests",
            ))
        }))
        .refresh_store(store)
        .build();
    source.prime(valid_response("rt-original")).await.unwrap();
    source.token().await.unwrap();

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    let err = source.token().await.unwrap_err();

    assert_eq!(err.recovery(), Recovery::Retry { after: Some(delay) });
    assert_eq!(
        err.as_error().retry_advice(),
        RetryAdvice::retry_after(delay)
    );
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

/// A rejected credential on a source that is *not* spent — every caller of
/// this helper uses a dynamic source, so the source survives the rejection.
///
/// Not `Reauthenticate`: no user can fix a signer that keeps producing
/// assertions the server rejects, and the source may yet recover on its own
/// (a rotated key, a corrected clock). Once the breaker trips, that "later,
/// automatically" becomes explicit as a `Retry` carrying the cooldown — see
/// `assert_backoff`.
fn assert_invalid_grant(err: &TokenError) {
    assert_get_token_error(err, RetryAdvice::No);
    assert_eq!(err.recovery(), Recovery::Retry { after: None });
    assert!(
        err.verdict()
            .is_some_and(|v| v.code() == &OAuthErrorCode::InvalidGrant),
        "the server's verdict must survive to the caller: {err:?}"
    );
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
    // (the empty mock would panic if the endpoint were reached). The recovery
    // is a Retry carrying the cooldown — "retry later", not Reauthenticate.
    assert_backoff(&source.token().await.unwrap_err());
}

/// Captures the `outcome` label of every `huskarl.token.acquire` increment.
///
/// Hand-rolled rather than pulled from `metrics-util`: it is a dozen lines, and
/// a test-only dependency for one assertion is a poor trade.
#[cfg(feature = "metrics")]
#[derive(Clone, Default)]
struct OutcomeRecorder(Arc<Mutex<Vec<String>>>);

#[cfg(feature = "metrics")]
struct RecordOutcome {
    sink: Arc<Mutex<Vec<String>>>,
    outcome: String,
}

#[cfg(feature = "metrics")]
impl ::metrics::CounterFn for RecordOutcome {
    fn increment(&self, _by: u64) {
        self.sink.lock().unwrap().push(self.outcome.clone());
    }

    fn absolute(&self, _value: u64) {}
}

#[cfg(feature = "metrics")]
impl ::metrics::Recorder for OutcomeRecorder {
    fn describe_counter(
        &self,
        _: ::metrics::KeyName,
        _: Option<::metrics::Unit>,
        _: ::metrics::SharedString,
    ) {
    }

    fn describe_gauge(
        &self,
        _: ::metrics::KeyName,
        _: Option<::metrics::Unit>,
        _: ::metrics::SharedString,
    ) {
    }

    fn describe_histogram(
        &self,
        _: ::metrics::KeyName,
        _: Option<::metrics::Unit>,
        _: ::metrics::SharedString,
    ) {
    }

    fn register_counter(
        &self,
        key: &::metrics::Key,
        _: &::metrics::Metadata<'_>,
    ) -> ::metrics::Counter {
        if key.name() != "huskarl.token.acquire" {
            return ::metrics::Counter::noop();
        }
        let outcome = key
            .labels()
            .find(|label| label.key() == "outcome")
            .map(|label| label.value().to_owned())
            .unwrap_or_default();
        ::metrics::Counter::from_arc(Arc::new(RecordOutcome {
            sink: Arc::clone(&self.0),
            outcome,
        }))
    }

    fn register_gauge(&self, _: &::metrics::Key, _: &::metrics::Metadata<'_>) -> ::metrics::Gauge {
        ::metrics::Gauge::noop()
    }

    fn register_histogram(
        &self,
        _: &::metrics::Key,
        _: &::metrics::Metadata<'_>,
    ) -> ::metrics::Histogram {
        ::metrics::Histogram::noop()
    }
}

/// **Every failure exit records an outcome, the breaker's included.**
///
/// The one that mattered was dark: the backoff path returned
/// `TokenError::from(..)` directly rather than through the emitting exit, so
/// `TokenOutcome::Backoff` — the condition a dashboard most needs, a source
/// that has stopped trying — could never be observed. The table pinning
/// `GetTokenError::Backoff` to that label passed throughout, because it calls
/// `outcome()` itself instead of reaching it down a path that emits.
///
/// A plain `#[test]` driving a current-thread runtime, because the recorder
/// guard is thread-local and everything must stay on one thread.
#[cfg(feature = "metrics")]
#[test]
fn every_failure_exit_records_its_outcome() {
    let recorder = OutcomeRecorder::default();
    let seen = ::metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let http = MockHttpClient::default();
                let source = dynamic_source(http.clone(), 2, std::time::Duration::from_mins(1));
                http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
                http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);

                source.token().await.unwrap_err();
                source.token().await.unwrap_err();
                // The breaker is now open, so this one reaches no endpoint —
                // the empty mock would panic if it did.
                source.token().await.unwrap_err();
            });
        recorder.0.lock().unwrap().clone()
    });

    assert_eq!(seen.len(), 3, "one record per failure, got {seen:?}");
    assert_eq!(
        seen.last().map(String::as_str),
        Some(crate::TokenOutcome::Backoff.as_str()),
        "the backed-off exit records too, got {seen:?}"
    );
}

#[cfg(feature = "metrics")]
#[test]
fn successful_acquisitions_record_success_outcomes() {
    let recorder = OutcomeRecorder::default();
    let seen = ::metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let store = SharedRefreshStore::default();
                let http = MockHttpClient::default();
                let source = GrantTokenSource::builder()
                    .grant(client_credentials_grant(http.clone()))
                    .grant_parameters(from_fn(|| async {
                        Ok::<_, Error>(ClientCredentialsGrantParameters::new())
                    }))
                    .refresh_store(store)
                    .build();

                source.prime(valid_response("rt-original")).await.unwrap();
                source.token().await.unwrap();

                http.push(
                    StatusCode::OK,
                    r#"{"access_token":"refreshed","token_type":"bearer","expires_in":3600}"#,
                );
                source.token().await.unwrap();

                source.clear().await.unwrap();
                http.push(
                    StatusCode::OK,
                    r#"{"access_token":"exchanged","token_type":"bearer","expires_in":3600}"#,
                );
                source.token().await.unwrap();
            });
        recorder.0.lock().unwrap().clone()
    });

    assert_eq!(
        seen,
        vec![crate::TokenOutcome::Success.as_str(); 3],
        "pending, refresh, and exchange successes must all be emitted"
    );
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
        assert_get_token_error(&err, RetryAdvice::RETRY);
    }

    // Breaker is now open. Only one (transient) refresh response is queued:
    // if the gate fell through to the exchange, the empty mock would panic.
    // The surfaced error is the retryable refresh failure, not Backoff.
    http.push(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"temporarily_unavailable"}"#,
    );
    let err = source.token().await.unwrap_err();
    assert_get_token_error(&err, RetryAdvice::RETRY);
}

#[tokio::test]
async fn open_breaker_does_not_mask_adjustable_refresh() {
    let store = SharedRefreshStore::default();
    let http = MockHttpClient::default();
    let source = GrantTokenSource::builder()
        .grant(client_credentials_grant(http.clone()))
        .grant_parameters(from_fn(|| async {
            Ok::<_, Error>(ClientCredentialsGrantParameters::new())
        }))
        .refresh_store(store)
        .breaker_threshold(1)
        .build();
    source.prime(valid_response("rt-original")).await.unwrap();
    source.token().await.unwrap();

    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
    let err = source.token().await.unwrap_err();
    assert_eq!(err.recovery(), Recovery::AdjustRequest);

    // The breaker is open, so only refresh is attempted. Its request-shape
    // verdict remains the actionable result rather than being replaced by
    // Backoff.
    http.push(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#);
    let err = source.token().await.unwrap_err();
    assert_eq!(err.recovery(), Recovery::AdjustRequest);
    assert_eq!(
        err.verdict().map(|verdict| verdict.code().as_str()),
        Some("invalid_scope")
    );
}

/// A session-bound grant powers the whole source chain: the internally-built
/// refresh request signs with the session key (via `to_refresh_grant`), and
/// the source's resource-server `DPoP` proves against the issued token — the
/// two things an unbound `SessionKeyedDPoP` template cannot do.
#[cfg(not(target_family = "wasm"))]
#[tokio::test]
async fn session_bound_grant_powers_source_dpop_and_refresh() {
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

    use crate::{core::dpop::SessionKeyedDPoP, grant::refresh::RefreshGrant, token::AccessToken};

    let http = MockHttpClient::default();
    let grant = RefreshGrant::builder()
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .client_id("client")
        .http_client(http.clone())
        .client_auth(NoAuth)
        .dpop(SessionKeyedDPoP::new())
        .build()
        .with_session_dpop_key(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
        .unwrap();

    let store = SharedRefreshStore::default();
    store.set(&refresh_token("the-rt")).await.unwrap();
    let source = GrantTokenSource::builder()
        .grant(grant)
        .grant_parameters(NoSource)
        .refresh_store(store)
        .build();

    // Refresh path: the DPoP proof on the token request comes from the bound
    // session key; with no key bound this call fails before any HTTP.
    http.push(
        StatusCode::OK,
        r#"{"access_token":"at","token_type":"DPoP"}"#,
    );
    let token = source.token().await.unwrap();
    let AccessToken::DPoP(at) = token.access_token() else {
        panic!("expected a DPoP-bound access token");
    };

    // Resource-server path: the captured proof object holds the session key,
    // and its proof thumbprint-matches the token's jkt.
    let proof = source
        .resource_server_dpop()
        .proof(
            &http::Method::GET,
            &"https://rs.example.com/resource".parse().unwrap(),
            at.token(),
            at.jkt(),
        )
        .await
        .unwrap();
    assert!(
        proof.is_some(),
        "session-bound RS DPoP must produce a proof"
    );
}
