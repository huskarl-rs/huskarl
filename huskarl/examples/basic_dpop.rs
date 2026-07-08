use http::Method;
use huskarl::{
    core::{
        client_auth::ClientSecret,
        dpop::{DPoP, ResourceServerDPoP},
        secrets::{EnvVarSecret, encodings::StringEncoding},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    prelude::*,
    token::AccessToken,
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
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
        .build()
        .await
        .whatever_context("Failed to build client")?;

    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer(issuer)
        .call()
        .await
        .whatever_context("Failed to get authorization server metadata")?;

    // The tokens obtained through this grant are bound to this key.
    let dpop_key = PrivateKey::generate(GenerateAlgorithm::Ed25519, None)
        .whatever_context("Failed to generate DPoP key")?;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(client_id)
        .http_client(http_client.clone())
        .client_auth(ClientSecret::new(client_secret))
        .dpop(DPoP::builder().signer(dpop_key).build())
        .build();

    let token_response = grant
        .exchange(
            ClientCredentialsGrantParameters::builder()
                .scope(bon::vec!["test"])
                .build(),
        )
        .await
        .whatever_context("Failed to get token")?;

    let access_token = token_response.access_token();

    println!("Access token: {}", access_token.token().expose_secret());

    let resource_server_dpop = grant.dpop().to_resource_server_dpop();

    let AccessToken::DPoP(dpop_token) = access_token else {
        println!("Expected response to be a DPoP token");
        return Ok(());
    };

    let resource_uri: http::Uri = "https://api.example.com/resource"
        .parse()
        .whatever_context("Invalid resource URI")?;
    let dpop_proof = resource_server_dpop
        .proof(
            &Method::GET,
            &resource_uri,
            dpop_token.token(),
            dpop_token.jkt(),
        )
        .await
        .whatever_context("Failed to create DPoP proof")?;

    if let Some(dpop_proof) = dpop_proof {
        println!("DPoP header: {}", dpop_proof.expose_secret());
    }

    Ok(())
}
