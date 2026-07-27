//! Scratch downstream consumer for huskarl.

use std::sync::{
    Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{Recovery, RefreshTokenStore, TokenError},
    core::{Error, RetryAdvice, platform::MaybeSendBoxFuture},
    token::RefreshToken,
    userinfo::UserInfoClient,
};

pub struct AppState {
    pub authorizer: HttpAuthorizer,
    pub userinfo: Option<UserInfoClient>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("login required")]
    LoginRequired,
    #[error("temporarily unavailable")]
    RetryLater(Option<huskarl::core::platform::Duration>, TokenError),
    #[error("the request needs adjusting")]
    AdjustRequest(TokenError),
    #[error("authorization failed")]
    Auth(#[from] TokenError),
}

pub async fn authorized_headers(
    state: &AppState,
    method: &http::Method,
    uri: &http::Uri,
) -> Result<http::HeaderMap, AppError> {
    match state.authorizer.get_headers(method, uri).await {
        Ok(headers) => Ok(headers),
        // One match over what to do. The token source decided this while it
        // still held the alternatives; nothing here re-derives it.
        Err(err) => match err.recovery() {
            Recovery::Reauthenticate => Err(AppError::LoginRequired),
            // One arm, not two: a cooldown is a retry that carries a delay.
            Recovery::Retry { after } => Err(AppError::RetryLater(after, err)),
            Recovery::AdjustRequest => Err(AppError::AdjustRequest(err)),
            _ => Err(AppError::Auth(err)),
        },
    }
}

#[derive(Debug, Default)]
pub struct KeychainStore {
    token: Mutex<Option<RefreshToken>>,
    locked: AtomicBool,
}

#[derive(Debug, thiserror::Error)]
#[error("keychain is locked")]
pub struct KeychainLocked;

/// How long this store says to wait — the interval a leaf component knows and
/// the stack above it does not.
pub const KEYCHAIN_RELOCK: huskarl::core::platform::Duration =
    huskarl::core::platform::Duration::from_secs(42);

impl KeychainStore {
    /// Simulates the keychain becoming unavailable.
    pub fn lock(&self) {
        self.locked.store(true, Ordering::Relaxed);
    }

    fn ensure_unlocked(&self) -> Result<(), Error> {
        if self.locked.load(Ordering::Relaxed) {
            // A locked keychain is transient, and this component happens to
            // know how long: the OS relocks on a fixed timer. Stands in for any
            // leaf that can name an interval — a KMS returning `Retry-After`.
            Err(Error::new(
                RetryAdvice::retry_after(KEYCHAIN_RELOCK),
                KeychainLocked,
            ))
        } else {
            Ok(())
        }
    }
}

impl RefreshTokenStore for KeychainStore {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        Box::pin(async {
            self.ensure_unlocked()?;
            Ok(self
                .token
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone())
        })
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            self.ensure_unlocked()?;
            *self.token.lock().unwrap_or_else(PoisonError::into_inner) = Some(token.clone());
            Ok(())
        })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async {
            self.ensure_unlocked()?;
            *self.token.lock().unwrap_or_else(PoisonError::into_inner) = None;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc};

    use bytes::Bytes;
    use huskarl::{
        cache::{GrantTokenSource, InMemoryTokenCache, NoSource},
        core::{
            client_auth::NoAuth,
            http::{HttpClient, HttpResponse, Idempotency},
            platform::SystemTime,
            secrets::SecretString,
        },
        grant::{
            client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
            core::RawTokenResponse,
        },
        prelude::*,
    };

    use super::*;

    /// Minimal downstream HTTP client: a queue of canned JSON responses.
    #[derive(Debug, Clone, Default)]
    struct MockHttp {
        responses: Arc<Mutex<VecDeque<(u16, &'static str)>>>,
    }

    impl MockHttp {
        fn push(&self, status: u16, body: &'static str) {
            self.responses
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back((status, body));
        }
    }

    impl HttpClient for MockHttp {
        fn execute(
            &self,
            _request: http::Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            let (status, body) = self
                .responses
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .expect("unexpected HTTP call");
            Box::pin(async move {
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
                Ok(HttpResponse {
                    status: http::StatusCode::from_u16(status).expect("valid status"),
                    headers,
                    body: Bytes::from_static(body.as_bytes()),
                })
            })
        }
    }

    fn grant(http: MockHttp) -> ClientCredentialsGrant {
        ClientCredentialsGrant::builder()
            .client_id("downstream-app")
            .client_auth(NoAuth)
            .token_endpoint(
                "https://as.example.com/token"
                    .parse()
                    .expect("valid endpoint URL"),
            )
            .http_client(http)
            .build()
    }

    fn app_state(http: MockHttp, store: KeychainStore) -> AppState {
        let source = GrantTokenSource::builder()
            .grant(grant(http))
            .grant_parameters(ClientCredentialsGrantParameters::builder().build())
            .refresh_store(store)
            .build();
        let cache = InMemoryTokenCache::builder().source(source).build();

        AppState {
            authorizer: HttpAuthorizer::builder().cache(cache).build(),
            userinfo: None,
        }
    }

    #[tokio::test]
    async fn exchange_and_authorize_via_app_state() {
        let http = MockHttp::default();
        http.push(
            200,
            r#"{"access_token":"tok-1","token_type":"bearer","expires_in":3600}"#,
        );

        let state = app_state(http, KeychainStore::default());
        let uri: http::Uri = "https://api.example.com/resource".parse().unwrap();
        let headers = authorized_headers(&state, &http::Method::GET, &uri)
            .await
            .unwrap();

        let auth = headers
            .get(http::header::AUTHORIZATION)
            .expect("Authorization header")
            .to_str()
            .unwrap();
        assert!(
            auth.to_ascii_lowercase().starts_with("bearer ") && auth.ends_with("tok-1"),
            "unexpected Authorization header: {auth}"
        );
    }

    #[tokio::test]
    async fn no_token_source_maps_to_login_required() {
        let source = GrantTokenSource::builder()
            .grant(grant(MockHttp::default())) // no responses queued: must not be called
            .grant_parameters(NoSource)
            .refresh_store(KeychainStore::default())
            .build();
        let cache = InMemoryTokenCache::builder().source(source).build();
        let state = AppState {
            authorizer: HttpAuthorizer::builder().cache(cache).build(),
            userinfo: None,
        };

        let uri: http::Uri = "https://api.example.com/resource".parse().unwrap();
        let err = authorized_headers(&state, &http::Method::GET, &uri)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::LoginRequired), "got {err:?}");
    }

    /// Does an interval named by a user-supplied leaf survive the whole stack
    /// — store, token source, cache, authorizer — to the caller?
    #[tokio::test]
    async fn leaf_supplied_retry_delay_reaches_the_caller() {
        let store = KeychainStore::default();
        store.lock();
        // `NoSource`: no from-scratch exchange to fall through to, so the
        // store's own verdict is the outcome rather than being combined with
        // an exchange failure.
        let source = GrantTokenSource::builder()
            .grant(grant(MockHttp::default()))
            .grant_parameters(NoSource)
            .refresh_store(store)
            .build();
        let cache = InMemoryTokenCache::builder().source(source).build();
        let state = AppState {
            authorizer: HttpAuthorizer::builder().cache(cache).build(),
            userinfo: None,
        };
        let uri: http::Uri = "https://api.example.com/resource".parse().unwrap();

        let err = authorized_headers(&state, &http::Method::GET, &uri)
            .await
            .expect_err("a locked keychain must fail");

        match err {
            AppError::RetryLater(after, _) => assert_eq!(
                after,
                Some(KEYCHAIN_RELOCK),
                "the leaf's interval must reach the caller intact"
            ),
            other => panic!("expected RetryLater, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn locked_keychain_failure_propagates_through_prime() {
        let response = RawTokenResponse::builder()
            .access_token(SecretString::new("tok-1"))
            .token_type("bearer")
            .expires_in(3600)
            .refresh_token(SecretString::new("rt-1"))
            .build()
            .into_token_response(None, SystemTime::now())
            .expect("valid token response");

        let store = KeychainStore::default();
        store.lock();
        let source = GrantTokenSource::builder()
            .grant(grant(MockHttp::default()))
            .grant_parameters(NoSource)
            .refresh_store(store)
            .build();

        let err = source.prime(response).await.unwrap_err();
        // The keychain named an interval, and `prime` must not flatten it.
        assert_eq!(
            err.retry_advice(),
            RetryAdvice::retry_after(KEYCHAIN_RELOCK)
        );
        assert!(
            err.cause().downcast_ref::<KeychainLocked>().is_some(),
            "source should be the downstream KeychainLocked: {err:?}"
        );
    }

    #[tokio::test]
    async fn exchange_then_prime_persists_refresh_token() {
        let http = MockHttp::default();
        http.push(
            200,
            r#"{"access_token":"tok-1","token_type":"bearer","expires_in":3600,"refresh_token":"rt-1"}"#,
        );
        let response = grant(http.clone())
            .exchange(ClientCredentialsGrantParameters::builder().build())
            .await
            .unwrap();

        let store = Arc::new(KeychainStore::default());
        let source = GrantTokenSource::builder()
            .grant(grant(http))
            .grant_parameters(NoSource)
            .refresh_store(store.clone())
            .build();

        source.prime(response).await.unwrap();
        let stored = store.get().await.unwrap().expect("refresh token persisted");
        assert_eq!(stored.token().expose_secret(), "rt-1");
    }
}
