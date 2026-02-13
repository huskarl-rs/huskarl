use huskarl::{
    client_auth::ClientSecret,
    dpop::NoDPoP,
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    prelude::*,
    secrets::{EnvVarSecret, encodings::StringEncoding},
    server_metadata::AuthorizationServerMetadata,
};
use snafu::prelude::*;

#[snafu::report]
#[tokio::main]
pub async fn main() -> Result<(), snafu::Whatever> {
    let issuer = std::env::var("ISSUER").whatever_context("Failed to get ISSUER")?;
    let client_id = std::env::var("CLIENT_ID").whatever_context("Failed to get CLIENT_ID")?;
    let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)
        .whatever_context("Failed to get CLIENT_SECRET")?;

    let http_client = reqwest::Client::new();

    let metadata = AuthorizationServerMetadata::from_issuer(issuer)
        .call(&http_client)
        .await
        .whatever_context("Failed to get authorization server metadata")?;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(client_id)
        .client_auth(ClientSecret::new(client_secret))
        .dpop(NoDPoP)
        .build();

    let token_response = grant
        .exchange(
            &http_client,
            ClientCredentialsGrantParameters::builder()
                .scopes(vec!["test"])
                .build(),
        )
        .await
        .whatever_context("Failed to get token")?;

    println!(
        "Access token: {}",
        token_response.access_token.expose_token()
    );

    Ok(())
}
