#![cfg(not(target_family = "wasm"))]

mod common;

use std::sync::Arc;

use common::{CcSetup, cc_setup};
use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::{client_auth::ClientSecret, jwk::JwksSource},
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
};
use huskarl_resource_server::{
    core::jwt::validator::ClaimCheck, validator::custom::CustomValidator,
};
use huskarl_testkit::PlainSecret;
use rstest::rstest;

/// Full client credentials flow against a real Keycloak: create a fresh realm and client,
/// exchange for a token, verify. The realm is deleted automatically when the test ends.
#[rstest]
#[tokio::test]
#[cfg_attr(
    not(feature = "keycloak-tests"),
    ignore = "requires Keycloak: cd integration && mise run keycloak:up"
)]
async fn client_credentials_exchange(#[future] cc_setup: CcSetup) {
    // `realm` is bound (not used directly) so it lives until the test ends.
    let CcSetup {
        realm: _realm,
        client,
        http,
        metadata,
    } = cc_setup.await;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(&client.client_id)
        .http_client(http.clone())
        .client_auth(ClientSecret::new(PlainSecret::new(&client.secret)))
        .build();

    let validator = CustomValidator::builder_from_metadata(&metadata)
        .audience(ClaimCheck::required_value("huskarl-rs"))
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http.clone()).build(),
        ))
        .build()
        .await
        .expect("create validator");

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
    let request_uri = "https://test".parse().expect("url");

    let headers = authorizer
        .get_headers(&request_method, &request_uri)
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
