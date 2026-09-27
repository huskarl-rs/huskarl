use super::*;

#[test]
fn a_jwt_infrastructure_failure_preserves_its_classification() {
    let source = Error::new(crate::core::RetryAdvice::RETRY, "the JTI store");
    let err = Error::from(UserInfoError::JwtValidation {
        source: JwtValidationError::JtiCheck { source },
    });

    assert_eq!(err.retry_advice(), crate::core::RetryAdvice::RETRY);
}

// Resource-server challenges use the shared typed verdict representation.
#[test]
fn a_challenge_becomes_the_verdict() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "www-authenticate",
        HeaderValue::from_static(r#"Bearer error="insufficient_scope""#),
    );
    let err = Error::from(UserInfoError::BadStatus {
        status: StatusCode::FORBIDDEN,
        headers,
        body: TruncatedBody::new(""),
    });
    assert!(
        err.verdict()
            .is_some_and(|v| v.code() == &crate::core::OAuthErrorCode::InsufficientScope)
    );
}

// An `invalid_token` challenge is a verdict on the access token.
#[tokio::test]
async fn invalid_token_challenge_is_a_dead_credential() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "www-authenticate",
        HeaderValue::from_static(r#"Bearer error="invalid_token", error_description="expired""#),
    );
    let http = MockHttpClient::sequence(vec![HttpResponse {
        status: StatusCode::UNAUTHORIZED,
        headers,
        body: Bytes::new(),
    }]);

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(
        err.verdict()
            .is_some_and(|v| v.code() == &OAuthErrorCode::InvalidToken)
    );
}

#[tokio::test]
async fn oauth_verdict_ignores_non_oauth_authentication_schemes() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static(
            r#"Basic realm="legacy", error="invalid_grant", Bearer error="invalid_token""#,
        ),
    );
    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::UNAUTHORIZED,
        headers,
        body: Bytes::new(),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();
    assert_eq!(
        err.verdict().map(OAuthError::code),
        Some(&OAuthErrorCode::InvalidToken)
    );
}

#[tokio::test]
async fn oauth_verdict_preserves_challenge_diagnostics() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static(
            r#"DPoP error="invalid_token", error_description="proof expired", error_uri="https://rs.example.com/errors/proof""#,
        ),
    );
    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::UNAUTHORIZED,
        headers,
        body: Bytes::new(),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();
    let verdict = err.verdict().expect("DPoP challenge carries a verdict");
    assert_eq!(verdict.description(), Some("proof expired"));
    assert_eq!(verdict.uri(), Some("https://rs.example.com/errors/proof"));
}

// A bare 401 does not establish why authentication failed.
#[tokio::test]
async fn a_bare_401_stays_protocol() {
    let http = MockHttpClient::sequence(vec![HttpResponse {
        status: StatusCode::UNAUTHORIZED,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    }]);

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(err.verdict().is_none());
    assert_eq!(err.retry_advice(), crate::core::RetryAdvice::No);
}

// A transient response preserves its retry interval.
#[tokio::test]
async fn a_5xx_is_a_retryable_server_condition() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("10"));
    let http = MockHttpClient::sequence(vec![HttpResponse {
        status: StatusCode::SERVICE_UNAVAILABLE,
        headers,
        body: Bytes::new(),
    }]);

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert_eq!(
        err.retry_advice(),
        RetryAdvice::retry_after(crate::core::platform::Duration::from_secs(10))
    );
}
