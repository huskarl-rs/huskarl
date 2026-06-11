use huskarl::{
    core::{
        client_auth::ClientSecret,
        dpop::NoDPoP,
        secrets::{EnvVarSecret, encodings::StringEncoding},
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
    let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)
        .whatever_context("Failed to get CLIENT_SECRET")?;

    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .whatever_context("Failed to build client")?;

    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer(issuer)
        .call()
        .await
        .whatever_context("Failed to get authorization server metadata")?;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(client_id)
        .http_client(http_client)
        .client_auth(ClientSecret::new(client_secret))
        .dpop(NoDPoP)
        .build();

    let token_response = grant
        .exchange(
            ClientCredentialsGrantParameters::builder()
                .scopes(vec!["test"])
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
