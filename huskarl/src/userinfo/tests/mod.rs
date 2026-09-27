use super::*;
use crate::{
    core::{
        EndpointUrl, OAuthErrorCode, RetryAdvice,
        crypto::{
            KeyMatchStrength,
            verifier::{JwsVerifier, KeyMatch, VerifyError},
        },
        dpop::NoDPoP,
        http::HttpResponse,
        platform::MaybeSendBoxFuture,
        secrets::SecretString,
    },
    token::BearerAccessToken,
};

/// Mock HTTP client that serves preconfigured responses in order.
struct MockHttpClient {
    responses: std::sync::Mutex<std::collections::VecDeque<HttpResponse>>,
    calls: std::sync::atomic::AtomicUsize,
}

impl MockHttpClient {
    fn new(response: HttpResponse) -> Self {
        Self::sequence(vec![response])
    }

    fn sequence(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses.into()),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl HttpClient for MockHttpClient {
    fn execute(
        &self,
        _request: http::Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("MockHttpClient ran out of responses");
        Box::pin(async move { Ok(response) })
    }
}

// Extracts the typed cause without depending on display text.
fn userinfo_source(err: &Error) -> &UserInfoError {
    err.cause()
        .downcast_ref::<UserInfoError>()
        .expect("carries a UserInfoError")
}

fn bearer_token(token: &str) -> AccessToken {
    AccessToken::Bearer(BearerAccessToken::new(
        SecretString::new(token),
        crate::core::platform::SystemTime::now(),
        None,
    ))
}

fn json_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h
}

fn client() -> UserInfoClient {
    UserInfoClient {
        userinfo_endpoint: "https://op.example.com/userinfo"
            .parse::<EndpointUrl>()
            .unwrap(),
        mtls_userinfo_endpoint: None,
        dpop: Arc::new(NoDPoP),
        jwt_validator: None,
        require_signed_response: false,
    }
}

/// Mock JWS verifier that accepts any signature.
#[derive(Debug)]
struct AcceptAllVerifier;

impl JwsVerifier for AcceptAllVerifier {
    fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        Some(KeyMatchStrength::ByAlgorithm)
    }

    fn verify<'a>(
        &'a self,
        _input: &'a [u8],
        _signature: &'a [u8],
        _key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Factory yielding [`AcceptAllVerifier`], standing in for a JWKS-backed one.
struct AcceptAllFactory;

impl JwsVerifierFactory for AcceptAllFactory {
    fn build(
        &self,
        _jwks_uri: Option<&EndpointUrl>,
        _platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        Box::pin(async { Ok(Arc::new(AcceptAllVerifier) as _) })
    }
}

/// Builds an authorization code grant, optionally carrying a JWS verifier.
///
/// The HTTP client is never exercised — these tests build a `UserInfo`
/// client from the grant rather than running a token exchange.
async fn code_grant(
    with_verifier: bool,
) -> crate::grant::authorization_code::AuthorizationCodeGrant {
    crate::grant::authorization_code::AuthorizationCodeGrant::builder()
        .client_id("my-client")
        .issuer("https://op.example.com")
        .http_client(MockHttpClient::sequence(vec![]))
        .client_auth(crate::core::client_auth::NoAuth)
        .token_endpoint("https://op.example.com/token".parse().unwrap())
        .authorization_endpoint("https://op.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .maybe_jws_verifier_factory(with_verifier.then_some(AcceptAllFactory))
        .build()
        .await
        .unwrap()
}

fn userinfo_metadata() -> AuthorizationServerMetadata {
    serde_json::from_value(serde_json::json!({
        "issuer": "https://op.example.com",
        "authorization_endpoint": "https://op.example.com/authorize",
        "token_endpoint": "https://op.example.com/token",
        "userinfo_endpoint": "https://op.example.com/userinfo",
        "response_types_supported": ["code"],
    }))
    .unwrap()
}

mod basic;
mod classification;
mod jwt;
