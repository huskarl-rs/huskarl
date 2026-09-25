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

Use an HTTP client to fetch discovery metadata and signing keys:

```rust
use huskarl_reqwest::ReqwestClient;

# async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
let client: ReqwestClient = ReqwestClient::builder().build().await?;
# Ok(())
# }
```

## 2a. Build the validator from authorization server metadata

```rust
use huskarl_resource_server::{
    core::server_metadata::AuthorizationServerMetadata,
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
    .iss(metadata.issuer.clone())
    .aud("api://my-resource")
    .jwks_source(http_client.clone())
    .build()
    .await?;
# Ok(())
# }
```

## 2b. Alternative: Build without authorization server metadata

```rust
use huskarl_resource_server::validator::custom::CustomValidator;
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;

let validator = CustomValidator::builder()
    .authorization_server("https://my-issuer")
    .iss("https://my-issuer")
    .aud("api://my-resource")
    .jwks_uri("https://my-issuer/.well-known/jwks.json".parse()?)
    .jwks_source(http_client.clone())
    .build()
    .await?;
# Ok(())
# }
```

## 2c. Choose claim checks

`builder_from_metadata` copies `jwks_uri` and `authorization_server` into the
builder. `authorization_server` identifies the server in this resource's
metadata; it does not set the token's issuer check. Set `.iss(...)` and
`.aud(...)` to the values your API expects, as in the examples above.

The default rules require `iss`, `sub`, `exp`, `iat`, and `jti` to be present.
They do not require a particular issuer, audience, or token type. A string
passed to `.iss(...)`, `.aud(...)`, `.sub(...)`, or `.typ(...)` requires the
claim to be present and equal to that string. Use
[`ClaimCheck`](crate::core::jwt::validator::ClaimCheck) for other policies,
such as accepting several audiences or explicitly disabling a check.

Set individual rules on the builder, or supply a complete
[`AccessTokenValidationRules`](crate::validator::custom::AccessTokenValidationRules)
with `.rules(...)`. Order matters: `.rules(...)` replaces all previously set
claim rules; individual rule setters after it adjust that supplied policy.
Requiring a `jti` claim does not enable replay rejection. That requires a
checker; see [choosing replay checks](crate::_docs::guide::rfc9068#2e-choose-replay-checks).

## 2d. Construction and key sources

Creating the builder does no HTTP work. With `.jwks_source(http_client)`,
`.build().await` fetches the initial JWKS and fails if the URI is missing or
the fetch fails. Build once and reuse the validator across requests; key
refresh can perform HTTP requests during validation.

Use `.jws_verifier_factory(...)` instead of `.jwks_source(...)` for a configured
`JwksSource` or a custom key source. A custom factory may supply its own keys
without a URI. See [customizing the key source](crate::_docs::guide::rfc9068#2d-customize-the-key-source)
for TTL and startup settings. Factory and checker setters accept concrete
implementations or shared implementations in `Arc`. With
`default-jws-verifier-platform` disabled, supply `.jws_verifier_platform(...)`.

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
# use huskarl_resource_server::core::server_metadata::AuthorizationServerMetadata;
# use huskarl_resource_server::validator::custom::CustomValidator;
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
# let metadata = AuthorizationServerMetadata::fetch()
#     .http_client(&http_client)
#     .issuer("https://my-issuer")
#     .call()
#     .await?;
# let validator = CustomValidator::builder_from_metadata(&metadata)
#     .iss(metadata.issuer.clone())
#     .aud("api://my-resource")
#     .jwks_source(http_client.clone())
#     .build()
#     .await?;
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
