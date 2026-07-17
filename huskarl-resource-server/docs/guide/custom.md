# Validating non-RFC-9068 access tokens

[`CustomValidator`](crate::validator::custom::CustomValidator) validates JWT
access tokens whose claim set does not conform to RFC 9068. Validation rules are
configured via
[`AccessTokenValidationRules`](crate::validator::custom::AccessTokenValidationRules)
or through individual builder methods such as `.aud()`, `.iss()`, and
`.sub()`. For RFC 9068-compliant authorization servers, use the [RFC 9068
guide](crate::_docs::guide::rfc9068) instead — see [choosing a
validator](crate::_docs::explanation::choosing_a_validator).

## 1. Set up your HTTP client

A HTTP client needs to be configured. Using the `huskarl_reqwest` crate:

```rust
use huskarl_reqwest::ReqwestClient;

# async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
let client: ReqwestClient = ReqwestClient::builder().build().await?;
# Ok(())
# }
```

## 2a. Build the validator from authorization server metadata

```rust
use std::sync::Arc;

use huskarl_resource_server::{
    core::{
        jwk::JwksSource,
        server_metadata::AuthorizationServerMetadata,
    },
    validator::custom::CustomValidator,
};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;

let metadata = AuthorizationServerMetadata::fetch()
    .http_client(&http_client)
    .issuer("https://my-issuer")
    .call()
    .await?;

let validator = CustomValidator::builder_from_metadata(&metadata)
    .aud("api://my-resource")
    .jws_verifier_factory(Arc::new(
        JwksSource::builder()
            .http_client(http_client.clone())
            .build(),
    ))
    .build()
    .await?;
# Ok(())
# }
```

## 2b. Alternative: Build without authorization server metadata

```rust
use std::sync::Arc;

use huskarl_resource_server::{
    core::jwk::JwksSource,
    validator::custom::CustomValidator,
};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;

let validator = CustomValidator::builder()
    .authorization_server("https://my-issuer")
    .aud("api://my-resource")
    .jwks_uri("https://my-issuer/.well-known/jwks.json".parse()?)
    .jws_verifier_factory(Arc::new(
        JwksSource::builder()
            .http_client(http_client.clone())
            .build(),
    ))
    .build()
    .await?;
# Ok(())
# }
```

## 3. Validate a request

Call
[`CustomValidator::validate_request`](crate::validator::custom::CustomValidator::validate_request)
with the HTTP request headers, method, and URI. The
[`outcome`](crate::validator::ValidationResult::outcome) field of the result is:

- `Ok(None)` — no authentication header was present
- `Ok(Some(_))` — a valid token was found; the request is authenticated
- `Err(_)` — a token was present but invalid

The URI must be the **absolute external target URI** the client addressed
(scheme + authority + path): it is compared against the `htu` claim of any
DPoP proof (RFC 9449 §4.3). Framework request objects usually carry only the
origin-form path (`/resource`), and behind TLS-terminating or rewriting
proxies only your deployment knows the external URI — reconstruct it from a
configured public base URL or from forwarded headers you trust. A
non-absolute URI fails every DPoP validation with an integration error.

```rust
# use std::sync::Arc;
# use huskarl_resource_server::core::{
#     jwk::JwksSource,
#     server_metadata::AuthorizationServerMetadata,
# };
# use huskarl_resource_server::validator::custom::CustomValidator;
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
# let metadata = AuthorizationServerMetadata::fetch().http_client(&http_client).issuer("https://my-issuer").call().await?;
# let validator = CustomValidator::builder_from_metadata(&metadata).aud("api://my-resource").jws_verifier_factory(Arc::new(JwksSource::builder().http_client(http_client.clone()).build())).build().await?;
use http::{HeaderValue, Method, Uri, header::AUTHORIZATION};

let mut headers = http::HeaderMap::new();
headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer mF_9.B5f-4.1JqM"));
let method = Method::GET;
let uri = Uri::from_static("https://api.example.com/resource");

let result = validator.validate_request(&headers, &method, &uri, None).await;

match result.outcome {
    Ok(Some(validated)) => println!("Authenticated: subject={:?}", validated.sub),
    Ok(None) => println!("No authentication provided"),
    Err(e) => println!("Validation failed: {e}"),
}
# Ok(())
# }
```

To turn a failed or unauthenticated result into the HTTP response — status
code, `WWW-Authenticate` challenges, and `DPoP-Nonce` header — see [rejecting
a request](crate::_docs::guide::rfc9068#4-reject-a-request) and the
[`rejection`](crate::rejection) module.
