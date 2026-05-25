#![cfg(not(target_family = "wasm"))]

use std::{path::Path, sync::Arc};

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
use huskarl_reqwest::{ReqwestClient, mtls::MtlsPem};
use huskarl_resource_server::{
    core::jwt::validator::ClaimCheck,
    validator::{custom::CustomValidator, dpop_nonce::NoNonceCheck},
};
use huskarl_testkit::{ClientConfig, GrantConfig, KeycloakAdmin, PlainSecret};

fn certs_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../integration/keycloak/certs")
}

/// Full client credentials flow with mTLS certificate binding against a real Keycloak.
///
/// Creates a fresh realm and an mTLS-bound client, obtains a token over the HTTPS endpoint
/// (presenting the test client certificate), then validates it with the resource server
/// validator passing the same certificate's DER bytes.
#[tokio::test]
#[cfg_attr(
    not(feature = "keycloak-tests"),
    ignore = "requires Keycloak: cd integration && mise run up"
)]
async fn client_credentials_mtls_binding() {
    let admin = KeycloakAdmin::local();
    let realm = admin.create_realm().await.expect("create realm");

    let config = ClientConfig::builder()
        .client_id("huskarl-mtls")
        .secret("test-secret")
        .grant(GrantConfig::client_credentials())
        .audience("huskarl-rs")
        .mtls_bound(true)
        .build();

    realm.create_client(&config).await.expect("create client");

    let certs = certs_dir();
    let ca_pem = std::fs::read(certs.join("ca.pem")).expect("read ca.pem");
    let client_identity_pem = std::fs::read_to_string(certs.join("client-identity.pem"))
        .expect("read client-identity.pem");
    let client_cert_pem =
        std::fs::read_to_string(certs.join("client.pem")).expect("read client.pem");

    // DER bytes of the client cert — passed to validate_request for cnf.x5t#S256 binding check.
    let client_cert_der = pem::parse(client_cert_pem)
        .expect("parse client.pem")
        .into_contents();

    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).expect("parse CA cert");

    // Build an mTLS-capable HTTP client: trust only the test CA, present the client cert.
    let http: ReqwestClient = ReqwestClient::builder()
        .mtls(MtlsPem::new(PlainSecret::new(client_identity_pem)))
        .root_certificates(vec![ca_cert])
        .build()
        .await
        .expect("build mTLS client");

    // Fetch metadata via the HTTPS issuer — Keycloak's iss claim will reflect this URL,
    // so the validator must be configured with the same issuer.
    let server_metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http)
        .issuer(realm.mtls_issuer())
        .call()
        .await
        .expect("fetch server metadata");

    let grant = ClientCredentialsGrant::builder_from_metadata(&server_metadata)
        .client_id(&config.client_id)
        .client_auth(ClientSecret::new(PlainSecret::new(&config.secret)))
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

    // Validate with the client cert DER — the cnf.x5t#S256 binding check must pass.
    assert!(
        validator
            .validate_request(
                &headers,
                &Method::GET,
                &"https://test".parse().expect("url"),
                Some(&client_cert_der),
            )
            .await
            .outcome
            .unwrap()
            .is_some()
    );
}
