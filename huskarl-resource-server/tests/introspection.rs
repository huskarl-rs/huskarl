#![cfg(not(target_family = "wasm"))]

use httpmock::prelude::*;
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::{
    core::{EndpointUrl, client_auth::NoAuth, jwt::validator::ClaimCheck},
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
                .parse::<EndpointUrl>()
                .unwrap(),
        )
        .aud(audience)
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
        when.method(POST)
            .path("/introspect")
            .form_urlencoded_tuple("token", "token-abc")
            .form_urlencoded_tuple("token_type_hint", "access_token");
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
    assert_eq!(validated.aud, vec!["api://rs1".to_string()]);
    assert_eq!(validated.sub.as_deref(), Some("user-123"));
    mock.assert();
}

/// RFC 9396 §9.2: `authorization_details` is not a registered introspection
/// field, so a caller captures it by typing it in their own `Claims`, where it
/// arrives via the flattened claims.
#[tokio::test]
async fn authorization_details_flow_into_typed_claims() {
    use huskarl_resource_server::core::AuthorizationDetail;

    #[derive(serde::Deserialize, Clone)]
    struct RarClaims {
        authorization_details: Option<Vec<AuthorizationDetail>>,
    }

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/introspect");
        then.status(200).header("content-type", "application/json").body(
            r#"{"active": true, "aud": "api://rs1", "authorization_details": [{"type": "payment_initiation", "actions": ["initiate"]}]}"#,
        );
    });

    let http_client = ReqwestClient::builder().build().await.unwrap();
    let validator = IntrospectionValidator::builder()
        .with_claims::<RarClaims>()
        .client_id("my-resource-server")
        .introspection_endpoint(
            format!("http://{}/introspect", server.address())
                .parse::<EndpointUrl>()
                .unwrap(),
        )
        .aud(ClaimCheck::required_value("api://rs1"))
        .client_auth(NoAuth)
        .http_client(http_client)
        .build()
        .await
        .unwrap();

    let validated = validator
        .validate_request(
            &bearer_headers(),
            &http::Method::GET,
            &"https://api.example.com/data".parse().unwrap(),
            None,
        )
        .await
        .outcome
        .expect("token should validate")
        .expect("token should be present");

    let details = validated
        .claims
        .authorization_details
        .as_deref()
        .expect("authorization_details present in typed claims");
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].r#type, "payment_initiation");
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
    assert_eq!(validated.sub.as_deref(), Some("user-123"));
}
