#![cfg(not(target_family = "wasm"))]

use httpmock::prelude::*;
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::{
    core::{IntoEndpointUrl, client_auth::NoAuth, jwt::validator::ClaimCheck},
    validator::introspection::{IntrospectionValidateError, IntrospectionValidator},
};

async fn validator_for(
    server: &MockServer,
    path: &str,
    audience: ClaimCheck,
) -> IntrospectionValidator {
    let http_client = ReqwestClient::builder().build().await.unwrap();

    IntrospectionValidator::builder()
        .client_id("my-resource-server")
        .introspection_endpoint(
            format!("http://{}{}", server.address(), path)
                .into_endpoint_url()
                .unwrap(),
        )
        .audience(audience)
        .client_auth(NoAuth)
        .http_client(http_client)
        .build()
        .await
        .unwrap()
}

fn bearer_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer token-abc"),
    );
    headers
}

async fn validate(
    validator: &IntrospectionValidator,
) -> Result<
    Option<huskarl_resource_server::validator::ValidatedRequest<()>>,
    IntrospectionValidateError,
> {
    validator
        .validate_request(
            &bearer_headers(),
            &http::Method::GET,
            &"https://api.example.com/data".parse().unwrap(),
            None,
        )
        .await
        .outcome
}

#[tokio::test]
async fn matching_audience_is_accepted() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/introspect");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"active": true, "aud": "api://rs1", "sub": "user-123"}"#);
    });

    let validator = validator_for(
        &server,
        "/introspect",
        ClaimCheck::required_value("api://rs1"),
    )
    .await;

    let validated = validate(&validator)
        .await
        .expect("token should validate")
        .expect("token should be present");
    assert_eq!(validated.audience, vec!["api://rs1".to_string()]);
    assert_eq!(validated.subject.as_deref(), Some("user-123"));
    mock.assert();
}

#[tokio::test]
async fn wrong_audience_is_rejected() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/introspect");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"active": true, "aud": ["api://other"], "sub": "user-123"}"#);
    });

    // The token introspects as active, but it was minted for a different
    // resource served by the same authorization server (RFC 7662 §4).
    let validator = validator_for(
        &server,
        "/introspect",
        ClaimCheck::required_value("api://rs1"),
    )
    .await;

    let err = validate(&validator).await.unwrap_err();
    assert!(matches!(
        err,
        IntrospectionValidateError::Audience { ref actual, .. }
            if actual == &["api://other".to_string()]
    ));
}

#[tokio::test]
async fn missing_audience_is_rejected_when_required() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/introspect");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"active": true, "sub": "user-123"}"#);
    });

    let validator = validator_for(
        &server,
        "/introspect",
        ClaimCheck::required_value("api://rs1"),
    )
    .await;

    let err = validate(&validator).await.unwrap_err();
    assert!(matches!(err, IntrospectionValidateError::Audience { .. }));
}

#[tokio::test]
async fn no_check_accepts_missing_audience() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/introspect");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"active": true, "sub": "user-123"}"#);
    });

    // Explicit opt-out for deployments where the AS scopes tokens to a single
    // resource or omits `aud` from introspection responses.
    let validator = validator_for(&server, "/introspect", ClaimCheck::NoCheck).await;

    let validated = validate(&validator)
        .await
        .expect("token should validate")
        .expect("token should be present");
    assert_eq!(validated.subject.as_deref(), Some("user-123"));
}
