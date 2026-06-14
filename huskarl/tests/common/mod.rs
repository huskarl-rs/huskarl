//! Shared setup for the Keycloak-backed integration tests.
//!
//! Each `tests/*.rs` file is compiled as its own crate, so this module is
//! included via `mod common;` wherever it is needed.
//!
//! Only the *concrete-typed* part of the setup lives here — creating a fresh
//! realm, a confidential client, an HTTP client, and fetching server metadata.
//! Building the grant/authorizer is left inline in each test because those
//! builder types are deeply generic and awkward to name in a shared signature.
//! The mTLS test is intentionally not built on this fixture: it needs an
//! mTLS-bound HTTP client and the HTTPS (`mtls_issuer`) endpoint.
#![allow(dead_code)] // each test crate uses only the parts it needs

use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl_reqwest::ReqwestClient;
use huskarl_testkit::{ClientConfig, CreatedClient, GrantConfig, KeycloakAdmin, TestRealm};
use rstest::fixture;

/// A fresh Keycloak realm with one confidential client-credentials client, a
/// plain HTTP client, and the realm's fetched server metadata.
///
/// `realm` is held by the caller so the realm survives until the test ends —
/// `TestRealm`'s `Drop` deletes it.
pub struct CcSetup {
    pub realm: TestRealm,
    pub client: CreatedClient,
    pub http: ReqwestClient,
    pub metadata: AuthorizationServerMetadata,
}

/// Creates a fresh realm with a client-credentials client (audience
/// `huskarl-rs`) and fetches its server metadata over plain HTTP.
///
/// Pass the client id with `#[with("...")]`; it defaults to `huskarl-cc`.
#[fixture]
pub async fn cc_setup(#[default("huskarl-cc")] client_id: &str) -> CcSetup {
    let admin = KeycloakAdmin::local();
    let realm = admin.create_realm().await.expect("create realm");

    let config = ClientConfig::builder()
        .client_id(client_id)
        .secret("test-secret")
        .grant(GrantConfig::client_credentials())
        .audience("huskarl-rs")
        .build();

    let client = realm.create_client(&config).await.expect("create client");

    let http: ReqwestClient = reqwest::Client::new().into();
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http)
        .issuer(realm.issuer())
        .call()
        .await
        .expect("fetch server metadata");

    CcSetup {
        realm,
        client,
        http,
        metadata,
    }
}
