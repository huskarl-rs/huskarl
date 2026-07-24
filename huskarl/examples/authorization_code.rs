use std::sync::Arc;

use http::Method;
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource},
    core::{
        client_auth::NoAuth, dpop::DPoP, jwk::JwksSource,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::authorization_code::{AuthorizationCodeGrant, StartInput, StartOutput, bind_loopback},
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;
use snafu::prelude::*;

#[snafu::report]
#[tokio::main]
pub async fn main() -> Result<(), snafu::Whatever> {
    let issuer = std::env::var("ISSUER").whatever_context("Failed to get ISSUER")?;
    let client_id = std::env::var("CLIENT_ID").whatever_context("Failed to get CLIENT_ID")?;

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

    let listener = bind_loopback(8080)
        .await
        .whatever_context("Failed to bind the loopback callback listener")?;

    // The tokens obtained through this grant are bound to this key.
    let dpop_key = PrivateKey::generate(GenerateAlgorithm::Es256, None)
        .whatever_context("Failed to generate DPoP key")?;

    let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .whatever_context("Authorization server metadata didn't include authorization URL")?
        .client_id(client_id)
        .http_client(http_client.clone())
        .client_auth(NoAuth)
        // A literal loopback address, not `localhost` (RFC 8252 §7.3):
        // `bind_loopback` binds one address family, and `localhost` may resolve
        // to the other one — the callback would then never arrive. Register
        // this exact URI with the authorization server.
        .redirect_uri("http://127.0.0.1:8080/login/callback")
        .dpop(DPoP::builder().signer(dpop_key).build())
        // ID-token verification is zero-config: the metadata's `jwks_uri` is
        // used to build a default `JwksSource` over `http_client`. Set
        // `jws_verifier_factory` only to customize (e.g. a KMS-backed verifier).
        .build()
        .await
        .whatever_context("Failed to build grant")?;

    let StartOutput {
        authorization_url,
        expires_at: _,
        pending_state,
        ..
    } = grant
        .start(StartInput::scope(bon::vec!["test"]))
        .await
        .whatever_context("Getting authorization URL failed")?;

    println!("Open this URL in your browser:\n{}", authorization_url);

    let completed = grant
        .complete_on_loopback(&listener, &pending_state, None)
        .await
        .whatever_context("Getting token failed")?;

    println!("ID token: {:?}", completed.id_token);

    // Hand the token response from the authorization code exchange to the
    // source; it serves the token and refreshes it automatically. DPoP proof
    // generation is handled by the authorizer.
    let source = GrantTokenSource::builder()
        .grant(grant)
        .grant_parameters(NoSource)
        .refresh_store(InMemoryRefreshTokenStore::default())
        .build();
    source
        .prime(completed.token_response)
        .await
        .whatever_context("Failed to prime the token source")?;

    let authorizer = HttpAuthorizer::builder()
        .cache(InMemoryTokenCache::builder().source(source).build())
        .build();

    let resource_server_validator = Rfc9068Validator::builder_from_metadata(&metadata)
        .audience("api://default")
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(http_client.clone())
                .build(),
        ))
        .build()
        .await
        .whatever_context("Failed to build resource server validator")?;

    // Replace with your actual resource server endpoint.
    let resource_server_url = "https://api.example.com"
        .parse::<http::Uri>()
        .whatever_context("Invalid resource server URL")?;

    let headers = authorizer
        .get_headers(&Method::GET, &resource_server_url)
        .await
        .whatever_context("Failed to get authorization headers")?;

    let validation_result = resource_server_validator
        .validate_request(&headers, &Method::GET, &resource_server_url, None)
        .await;

    // A resource server must echo this nonce in the response's `DPoP-Nonce`
    // header — on success (nonce rotation) as well as on rejections. On the
    // rejection path, `ValidationResult::rejection` carries it automatically.
    if let Some(nonce) = &validation_result.dpop_nonce {
        println!("DPoP-Nonce to echo in the response: {nonce}");
    }

    let validation_response = validation_result
        .outcome
        .whatever_context("Token failed to validate")?;

    println!("Validated token (if any): {:?}", validation_response);

    Ok(())
}
