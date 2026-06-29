//! Test-support kit for huskarl integration tests.

pub mod dex;
pub mod keycloak;
pub mod node_oidc;
pub mod okta;
pub mod plain_secret;
pub mod provider;
pub mod spec;

pub use dex::DexProvider;
pub use keycloak::{KeycloakAdmin, KeycloakProvider, TestRealm};
pub use node_oidc::NodeOidcProvider;
pub use okta::OktaProvider;
pub use plain_secret::PlainSecret;
pub use provider::{Error, TestProvider};
pub use spec::{ClientSpec, Features, MtlsMaterial, ProvisionedClient, Transport};
