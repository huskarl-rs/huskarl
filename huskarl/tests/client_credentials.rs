#![cfg(not(target_family = "wasm"))]

use std::sync::Arc;

use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::{
        client_auth::ClientSecret, dpop::NoDPoP, jwk::JwksSource,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::{
    core::jwt::validator::ClaimCheck,
    validator::{custom::CustomValidator, dpop_nonce::NoNonceCheck},
};
use huskarl_testkit::{ClientConfig, GrantConfig, KeycloakAdmin, PlainSecret};

/// Full client credentials flow against a real Keycloak: create a fresh realm and client,
/// exchange for a token, verify. The realm is deleted automatically when the test ends.
#[tokio::test]
#[cfg_attr(
    not(feature = "keycloak-tests"),
    ignore = "requires Keycloak: cd integration && mise run up"
)]
async fn client_credentials_exchange() {
    let admin = KeycloakAdmin::local();
    let realm = admin.create_realm().await.expect("create realm");

    let config = ClientConfig::builder()
        .client_id("huskarl-cc")
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

    let grant = ClientCredentialsGrant::builder_from_metadata(&server_metadata)
        .client_id(&client.client_id)
        .client_auth(ClientSecret::new(PlainSecret::new(&client.secret)))
        .dpop(NoDPoP)
        .build();

    let validator = CustomValidator::builder_from_metadata(&server_metadata)
        .audience(ClaimCheck::required_value("huskarl-rs"))
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http.clone()).build(),
        ))
        .dpop_nonce_checker(NoNonceCheck)
        .build()
        .await
        .expect("create validator");

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
    let request_uri = "https://test".parse().expect("url");

    let headers = authorizer
        .get_headers(&http, &request_method, &request_uri)
        .await
        .unwrap();

    assert!(
        validator
            .validate_request(
                &headers,
                &Method::GET,
                &"https://test".parse().expect("url"),
                None
            )
            .await
            .outcome
            .unwrap()
            .is_some()
    );
}
