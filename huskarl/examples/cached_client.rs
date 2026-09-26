//! Make two authenticated GET requests using one in-memory token cache.
//!
//! See examples/README.md for configuration and expected output.

use std::time::Duration;

use http::{HeaderMap, Method, StatusCode, Uri};
use huskarl::{
    authorizer::{HttpAuthorizer, dpop_resend_advised, parse_challenges},
    cache::{
        GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, Recovery, TokenError,
    },
    core::{
        OAuthErrorCode, client_auth::ClientSecret, secrets::EnvVarSecret,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
};
use huskarl_reqwest::ReqwestClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = std::env::var("ISSUER")?;
    let client_id = std::env::var("CLIENT_ID")?;
    let resource_url = std::env::var("RESOURCE_URL")?;
    let uri: Uri = resource_url.parse()?;
    let scope = std::env::var("SCOPE").unwrap_or_default();

    // Avoid forwarding authorization headers or DPoP proofs through redirects.
    let requests = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let http_client = ReqwestClient::from(requests.clone());
    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .issuer(issuer)
        .http_client(&http_client)
        .call()
        .await?;
    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id(client_id)
        .client_auth(ClientSecret::new(EnvVarSecret::string("CLIENT_SECRET")?))
        .http_client(http_client)
        .build();
    let source = GrantTokenSource::builder()
        .grant(grant)
        .grant_parameters(
            ClientCredentialsGrantParameters::builder()
                .scope(scope.split_whitespace().map(str::to_owned).collect())
                .build(),
        )
        .refresh_store(InMemoryRefreshTokenStore::default())
        .build();
    let cache = InMemoryTokenCache::builder().source(source).build();
    let authorizer = HttpAuthorizer::builder().cache(cache).build();

    // Reuse the authorizer: InMemoryTokenCache serves valid cached tokens and
    // drives acquisition/refresh on demand. Other caches can schedule differently.
    for request_number in 1..=2 {
        let mut response = requests
            .get(&resource_url)
            .headers(acquire_headers(&authorizer, &uri).await?)
            .send()
            .await?;
        authorizer.process_response(&uri, response.headers());

        let invalid_token = response.status() == StatusCode::UNAUTHORIZED
            && parse_challenges(response.headers())
                .iter()
                .any(|challenge| challenge.error() == Some(OAuthErrorCode::InvalidToken));
        if invalid_token || dpop_resend_advised(response.status(), response.headers()) {
            // This GET is safe to repeat. Retry a recoverable challenge once;
            // process_response has already invalidated the token or saved the nonce.
            response = requests
                .get(&resource_url)
                .headers(acquire_headers(&authorizer, &uri).await?)
                .send()
                .await?;
            authorizer.process_response(&uri, response.headers());
        }
        println!("Request {request_number}: {}", response.status());
        response.error_for_status_ref()?;
        if response.status().is_redirection() {
            return Err("configure RESOURCE_URL with the final resource URL".into());
        }
    }
    Ok(())
}

// A small application policy: retry acquisition once when advised, respecting
// the minimum delay. Other recovery actions need configuration/operator input
// for this non-interactive service client, so return the original error.
async fn acquire_headers(authorizer: &HttpAuthorizer, uri: &Uri) -> Result<HeaderMap, TokenError> {
    match authorizer.get_headers(&Method::GET, uri).await {
        Ok(headers) => Ok(headers),
        Err(error) => match error.recovery() {
            Recovery::Retry { after } => {
                tokio::time::sleep(after.unwrap_or(Duration::from_secs(1))).await;
                authorizer.get_headers(&Method::GET, uri).await
            }
            recovery => {
                eprintln!("Token acquisition needs application action: {recovery:?}");
                Err(error)
            }
        },
    }
}
