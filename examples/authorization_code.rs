use huskarl::{
    client_auth::ClientSecret,
    dpop::NoDPoP,
    grant::authorization_code::{
        AuthorizationCodeGrant, NoJar, StartInput, StartOutput, bind_loopback,
    },
    secrets::{EnvVarSecret, encodings::StringEncoding},
    server_metadata::AuthorizationServerMetadata,
};
use secrecy::ExposeSecret as _;
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

    let listener = bind_loopback(8080)
        .await
        .whatever_context("Failed to bind to localhost")?;

    let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .whatever_context("Authorization server metadata didn't include authorization URL")?
        .client_id(client_id)
        .client_auth(ClientSecret::new(client_secret))
        .redirect_uri("http://localhost:8080/login/callback")
        .dpop(NoDPoP)
        .jar(NoJar)
        .build();

    let StartOutput {
        authorization_url,
        expires_in: _,
        pending_state,
    } = grant
        .start(&http_client, StartInput::builder().scopes(["test"]).build())
        .await
        .whatever_context("Getting authorization URL failed")?;

    println!("Authorization URL: {}", authorization_url.to_string());

    let token_response = grant
        .complete_on_loopback(&http_client, &listener, &pending_state)
        .await
        .whatever_context("Getting token failed")?;

    println!(
        "Access token: {}",
        token_response.access_token.expose_secret()
    );

    Ok(())
}
