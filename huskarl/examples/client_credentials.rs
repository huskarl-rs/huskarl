//! Obtain one token using `OpenID` Connect discovery.
//!
//! See examples/README.md for configuration and expected output.

use huskarl::{
    core::{
        client_auth::ClientSecret, secrets::EnvVarSecret,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    prelude::*,
};
use huskarl_reqwest::ReqwestClient;
use snafu::prelude::*;

#[snafu::report]
#[tokio::main]
pub async fn main() -> Result<(), snafu::Whatever> {
    let issuer = std::env::var("ISSUER").whatever_context("Failed to get ISSUER")?;
    let client_id = std::env::var("CLIENT_ID").whatever_context("Failed to get CLIENT_ID")?;
    let client_secret =
        EnvVarSecret::string("CLIENT_SECRET").whatever_context("Failed to get CLIENT_SECRET")?;

    let http_client = ReqwestClient::builder()
        .build()
        .await
        .whatever_context("Failed to build client")?;

    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http_client)
        .issuer(issuer)
        .call()
        .await
        .whatever_context("Failed to get authorization server metadata")?;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(client_id)
        .http_client(http_client)
        .client_auth(ClientSecret::new(client_secret))
        .build();

    let scope = std::env::var("SCOPE").unwrap_or_default();
    let token_response = grant
        .exchange(
            ClientCredentialsGrantParameters::builder()
                .scope(scope.split_whitespace().map(str::to_owned).collect())
                .build(),
        )
        .await
        .whatever_context("Failed to get token")?;

    println!(
        "Access token: {}",
        token_response.access_token().token().expose_secret()
    );

    Ok(())
}
