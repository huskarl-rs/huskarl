#![cfg(not(target_family = "wasm"))]

mod common;

use std::collections::HashMap;

use common::{CcSetup, cc_setup};
use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::client_auth::ClientSecret,
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
};
use huskarl_resource_server::{
    core::jwt::validator::ClaimCheck, validator::introspection::IntrospectionValidator,
};
use huskarl_testkit::PlainSecret;
use rstest::rstest;

/// Introspection of a client-credentials access token against a real Keycloak.
///
/// Creates a fresh realm with a single confidential client, exchanges for a token,
/// then validates it via token introspection (RFC 7662) instead of local JWT verification.
#[rstest]
#[tokio::test]
#[cfg_attr(
    not(feature = "keycloak-tests"),
    ignore = "requires Keycloak: cd integration && mise run keycloak:up"
)]
async fn introspection_validates_active_token(
    #[future]
    #[with("huskarl-introspect")]
    cc_setup: CcSetup,
) {
    let CcSetup {
        realm,
        client,
        http,
        metadata,
    } = cc_setup.await;

    // Obtain an access token via client credentials grant.
    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(&client.client_id)
        .http_client(http.clone())
        .client_auth(ClientSecret::new(PlainSecret::new(&client.secret)))
        .build();

    let authorizer = HttpAuthorizer::builder()
        .cache(
            InMemoryTokenCache::builder()
                .source(
                    GrantTokenSource::builder()
                        .grant(grant)
                        .grant_parameters(ClientCredentialsGrantParameters::new())
                        .refresh_store(InMemoryRefreshTokenStore::default())
                        .build(),
                )
                .build(),
        )
        .build();

    let request_method = Method::GET;
    let request_uri = "https://test".parse().expect("parse uri");

    let headers = authorizer
        .get_headers(&request_method, &request_uri)
        .await
        .expect("get headers");

    // Build introspection validator — the same client authenticates to the
    // introspection endpoint using its own credentials.
    let introspection_endpoint = metadata
        .introspection_endpoint
        .expect("Keycloak should expose introspection_endpoint in OIDC metadata");

    let validator = IntrospectionValidator::builder()
        .with_claims::<HashMap<String, serde_json::Value>>()
        .client_id(&client.client_id)
        .issuer(realm.issuer())
        .introspection_endpoint(introspection_endpoint)
        .audience(ClaimCheck::required_value("huskarl-rs"))
        .client_auth(ClientSecret::new(PlainSecret::new(&client.secret)))
        .http_client(http.clone())
        .build()
        .await
        .expect("create introspection validator");

    let validated = validator
        .validate_request(&headers, &request_method, &request_uri, None)
        .await
        .outcome
        .expect("introspection should succeed")
        .expect("token should be present and active");

    // Keycloak returns the internal user UUID as `sub` in introspection responses.
    assert!(
        validated.subject.is_some(),
        "expected subject to be present, got None"
    );
    assert_eq!(validated.issuer.as_deref(), Some(realm.issuer().as_str()),);
    assert!(
        validated.audience.contains(&"huskarl-rs".to_owned()),
        "expected audience to contain 'huskarl-rs', got {:?}",
        validated.audience
    );
    // No JWT introspection response was requested.
    assert!(validated.introspection_jwt.is_none());
}
