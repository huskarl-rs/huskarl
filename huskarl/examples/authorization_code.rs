use std::sync::Arc;

use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::{
        client_auth::NoAuth, dpop::DPoP, jwk::JwksSource,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::{
        AuthorizationCodeGrant, NoJar, StartInput, StartOutput, bind_loopback,
    },
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::validator::{dpop_nonce::NoNonceCheck, rfc9068::Rfc9068Validator};
use snafu::prelude::*;

#[snafu::report]
#[tokio::main]
pub async fn main() -> Result<(), snafu::Whatever> {
    let issuer = std::env::var("ISSUER").whatever_context("Failed to get ISSUER")?;
    let client_id = std::env::var("CLIENT_ID").whatever_context("Failed to get CLIENT_ID")?;

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

    let listener = bind_loopback(8080)
        .await
        .whatever_context("Failed to bind to localhost")?;

    let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .whatever_context("Authorization server metadata didn't include authorization URL")?
        .client_id(client_id)
        .client_auth(NoAuth)
        .redirect_uri("http://localhost:8080/login/callback")
        .dpop(
            DPoP::builder()
                .signer(PrivateKey::generate(GenerateAlgorithm::Es256))
                .build(),
        )
        .jar(NoJar)
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(http_client.clone())
                .build(),
        ))
        .build()
        .await
        .whatever_context("Failed to build grant")?;

    let StartOutput {
        authorization_url,
        expires_in: _,
        pending_state,
    } = grant
        .start(&http_client, StartInput::scopes(["test"]))
        .await
        .whatever_context("Getting authorization URL failed")?;

    println!("Open this URL in your browser:\n{}", authorization_url);

    let (token_response, id_token) = grant
        .complete_on_loopback_oidc(&http_client, &listener, &pending_state, None)
        .await
        .whatever_context("Getting token failed")?;

    println!("ID token: {:?}", id_token);

    // Prime the authorizer with the token response from the authorization code exchange.
    // The authorizer handles DPoP proof generation and token refresh automatically.
    let authorizer = HttpAuthorizer::builder()
        .cache(
            InMemoryTokenCache::builder()
                .grant(grant)
                .refresh_store(InMemoryRefreshTokenStore::default())
                .build(),
        )
        .build();

    authorizer.prime(Arc::new(token_response)).await;

    let resource_server_validator = Rfc9068Validator::builder_from_metadata(&metadata)
        .audience("api://default")
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(http_client.clone())
                .build(),
        ))
        .dpop_nonce_checker(NoNonceCheck)
        .build()
        .await
        .whatever_context("Failed to build resource server validator")?;

    // Replace with your actual resource server endpoint.
    let resource_server_url = "https://api.example.com"
        .parse::<http::Uri>()
        .whatever_context("Invalid resource server URL")?;

    let headers = authorizer
        .get_headers(&http_client, &Method::GET, &resource_server_url)
        .await
        .whatever_context("Failed to get authorization headers")?;

    let validation_response = resource_server_validator
        .validate_request(&headers, &Method::GET, &resource_server_url, None)
        .await
        .outcome
        .whatever_context("Token failed to validate")?;

    println!("Validated token (if any): {:?}", validation_response);

    Ok(())
}
