use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::{client_auth::ClientSecret, dpop::NoDPoP},
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
};
use huskarl_core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::validator::custom::{AccessTokenValidationRules, CustomValidator};
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
    let server_metadata = AuthorizationServerMetadata::builder()
        .issuer(realm.issuer())
        .http_client(&http)
        .build()
        .await
        .expect("fetch server metadata");

    let grant = ClientCredentialsGrant::builder_from_metadata(&server_metadata)
        .client_id(&client.client_id)
        .client_auth(ClientSecret::new(PlainSecret::new(&client.secret)))
        .dpop(NoDPoP)
        .build();

    let validator = CustomValidator::builder_from_metadata(&server_metadata)
        .audience("huskarl-rs")
        .jws_verifier_factory(JwksSource::builder().http_client(http.clone()).build())
        .rules(AccessTokenValidationRules::builder().build())
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
            .unwrap()
            .is_some()
    );
}
