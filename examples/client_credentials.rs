use huskarl::{
    client_auth::ClientSecret,
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    prelude::*,
    secrets::{EnvVarSecret, encodings::StringEncoding},
};
use secrecy::ExposeSecret as _;
use snafu::prelude::*;

#[snafu::report]
#[tokio::main]
pub async fn main() -> Result<(), snafu::Whatever> {
    let http_client = reqwest::Client::new();

    let client_auth = ClientSecret::new(
        EnvVarSecret::new("CLIENT_SECRET", StringEncoding)
            .whatever_context("Failed to get CLIENT_SECRET")?,
    );

    let grant = ClientCredentialsGrant::builder()
        .client_id(std::env::var("CLIENT_ID").whatever_context("Failed to get CLIENT_ID")?)
        .client_auth(client_auth)
        .token_endpoint(
            std::env::var("TOKEN_ENDPOINT").whatever_context("Failed to get TOKEN_ENDPOINT")?,
        )
        .whatever_context("Invalid token endpoint URL")?
        .build();

    let token_response = grant
        .exchange(
            &http_client,
            ClientCredentialsGrantParameters::builder()
                .scopes(["test"])
                .build(),
        )
        .await
        .whatever_context("Failed to get token")?;

    println!(
        "Access token: {}",
        token_response.access_token.expose_secret()
    );

    Ok(())
}
