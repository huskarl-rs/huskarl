//! Validate one RFC 9068 bearer token using an `OpenID` Connect issuer's JWKS.
//!
//! See examples/README.md for configuration and expected output.

#[cfg(target_family = "wasm")]
fn main() {}

#[cfg(not(target_family = "wasm"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use http::{HeaderValue, Method, Uri, header::AUTHORIZATION};
    use huskarl_reqwest::ReqwestClient;
    use huskarl_resource_server::{
        core::server_metadata::AuthorizationServerMetadata, validator::rfc9068::Rfc9068Validator,
    };

    let issuer = std::env::var("ISSUER")?;
    let audience = std::env::var("AUDIENCE")?;
    let resource_uri: Uri = std::env::var("RESOURCE_URL")?.parse()?;
    if resource_uri.scheme().is_none() || resource_uri.authority().is_none() {
        return Err("RESOURCE_URL must be the absolute external request URL".into());
    }
    let access_token = std::env::var("ACCESS_TOKEN")?;
    let http_client = ReqwestClient::builder().build().await?;
    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http_client)
        .issuer(issuer)
        .call()
        .await?;
    let validator = Rfc9068Validator::builder_from_metadata(&metadata)
        .jwks_source(http_client)
        .audience(audience)
        .build()
        .await?;

    let mut headers = http::HeaderMap::new();
    let mut authorization = HeaderValue::from_str(&format!("Bearer {access_token}"))?;
    authorization.set_sensitive(true);
    headers.insert(AUTHORIZATION, authorization);
    let result = validator
        .validate_request(&headers, &Method::GET, &resource_uri, None)
        .await;

    let validator_metadata = validator.validator_metadata(None);
    if let Some(rejection) = result.rejection(&validator_metadata, None) {
        let response = rejection.apply(http::Response::builder()).body(())?;
        println!("Rejected: {}", response.status());
        for (name, value) in response.headers() {
            println!("{name}: {}", value.to_str()?);
        }
        return Err("request authentication failed".into());
    }

    // Applications must also check the claims against their authorization policy.
    // A framework adapter can deliver nonce headers on successful responses too.
    if let Some(nonce) = &result.dpop_nonce {
        println!("DPoP-Nonce: {nonce}");
    }
    println!("Authenticated; application authorization is still required.");
    Ok(())
}
