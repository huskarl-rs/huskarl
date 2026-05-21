use http::Method;
use huskarl::{
    core::{
        client_auth::ClientSecret,
        dpop::{AuthorizationServerDPoP, DPoP, ResourceServerDPoP},
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
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .whatever_context("Failed to build client")?;

    let metadata = AuthorizationServerMetadata::builder()
        .issuer(issuer)
        .http_client(&http_client)
        .build()
        .await
        .whatever_context("Failed to get authorization server metadata")?;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(client_id)
        .client_auth(ClientSecret::new(client_secret))
        .dpop(
            DPoP::builder()
                .signer(PrivateKey::generate(GenerateAlgorithm::Ed25519))
                .build(),
        )
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

    let access_token = token_response.access_token();

    println!("Access token: {}", access_token.token().expose_secret());

    let resource_server_dpop = grant.dpop().to_resource_server_dpop();

    let AccessToken::Dpop(dpop_token) = access_token else {
        println!("Expected response to be a DPoP token");
        return Ok(());
    };

    let dpop_proof = resource_server_dpop
        .proof(
            &Method::GET,
            &"https://blah/".parse().unwrap(),
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
