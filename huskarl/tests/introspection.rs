#![cfg(not(target_family = "wasm"))]

use std::collections::HashMap;

use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::{client_auth::ClientSecret, dpop::NoDPoP, server_metadata::AuthorizationServerMetadata},
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::validator::{
    dpop_nonce::NoNonceCheck, introspection::IntrospectionValidator,
};
use huskarl_testkit::{ClientConfig, GrantConfig, KeycloakAdmin, PlainSecret};

/// Introspection of a client-credentials access token against a real Keycloak.
///
/// Creates a fresh realm with a single confidential client, exchanges for a token,
/// then validates it via token introspection (RFC 7662) instead of local JWT verification.
#[tokio::test]
#[cfg_attr(
    not(feature = "keycloak-tests"),
    ignore = "requires Keycloak: cd integration && mise run keycloak:up"
)]
async fn introspection_validates_active_token() {
    let admin = KeycloakAdmin::local();
    let realm = admin.create_realm().await.expect("create realm");

    let config = ClientConfig::builder()
        .client_id("huskarl-introspect")
        .secret("test-secret")
        .grant(GrantConfig::client_credentials())
        .audience("huskarl-rs")
        .build();

    let client = realm.create_client(&config).await.expect("create client");

    let http: ReqwestClient = reqwest::Client::new().into();
    let server_metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http)
        .issuer(realm.issuer())
        .call()
        .await
        .expect("fetch server metadata");

    // Obtain an access token via client credentials grant.
    let grant = ClientCredentialsGrant::builder_from_metadata(&server_metadata)
        .client_id(&client.client_id)
        .client_auth(ClientSecret::new(PlainSecret::new(&client.secret)))
        .dpop(NoDPoP)
        .build();

    let authorizer = HttpAuthorizer::builder()
        .cache(
            InMemoryTokenCache::builder()
                .grant(grant)
                .grant_parameters(ClientCredentialsGrantParameters::new())
                .refresh_store(InMemoryRefreshTokenStore::default())
                .build(),
        )
        .build();

    let request_method = Method::GET;
    let request_uri = "https://test".parse().expect("parse uri");

    let headers = authorizer
        .get_headers(&http, &request_method, &request_uri)
        .await
        .expect("get headers");

    // Build introspection validator — the same client authenticates to the
    // introspection endpoint using its own credentials.
    let introspection_endpoint = server_metadata
        .introspection_endpoint
        .expect("Keycloak should expose introspection_endpoint in OIDC metadata");

    let validator = IntrospectionValidator::builder()
        .with_claims::<HashMap<String, serde_json::Value>>()
        .client_id(&client.client_id)
        .issuer(realm.issuer())
        .introspection_endpoint(introspection_endpoint)
        .client_auth(ClientSecret::new(PlainSecret::new(&client.secret)))
        .dpop_nonce_checker(NoNonceCheck)
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
