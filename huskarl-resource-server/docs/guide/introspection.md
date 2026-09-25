# Validating tokens by introspection

[`IntrospectionValidator`](crate::validator::introspection::IntrospectionValidator)
validates access tokens by calling an authorization server's RFC 7662 token
introspection endpoint, rather than verifying JWT signatures locally. This
enables validation of opaque tokens and authoritative revocation-status checks.
It optionally supports RFC 9701 (JWT Response for Introspection) when a
`jwks_uri` is configured or a custom `jws_verifier_factory` is supplied.
A URI enables the default JWKS source; custom factories may supply their own
keys without a URI. The low-level `TokenIntrospection` builder offers
`.jwks_source(http_client)` to select a default JWKS source explicitly.
See [choosing a
validator](crate::_docs::explanation::choosing_a_validator) for the trade-offs.

## 1. Set up your HTTP client

Use an HTTP client for discovery and introspection requests:

```rust
use huskarl_reqwest::ReqwestClient;

# async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
let client: ReqwestClient = ReqwestClient::builder().build().await?;
# Ok(())
# }
```

## 2. Set up client authentication

The introspection endpoint requires the resource server to authenticate to the
authorization server. This example uses a client secret, but any
`ClientAuthentication` implementation can be used.

```rust
use huskarl_resource_server::core::{
    client_auth::ClientSecret,
    secrets::{EnvVarSecret, encodings::StringEncoding},
};

# async fn setup_client_auth() -> Result<(), Box<dyn std::error::Error>> {
let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
let client_auth: ClientSecret = ClientSecret::new(client_secret);
# Ok(())
# }
```

## 3a. Build the validator from authorization server metadata

Note: `builder_from_metadata` errors if the server advertises no introspection
endpoint. Since introspection is optional, add `.ok()` to treat an absent
endpoint as "unsupported" rather than a failure.

```rust
use huskarl_resource_server::{
    core::{
        client_auth::ClientSecret,
        secrets::{EnvVarSecret, encodings::StringEncoding},
        server_metadata::AuthorizationServerMetadata,
    },
    validator::introspection::IntrospectionValidator,
};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
# let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;

let metadata = AuthorizationServerMetadata::fetch()
    .http_client(&http_client)
    .issuer("https://my-issuer")
    .call()
    .await?;

let validator = IntrospectionValidator::builder_from_metadata(&metadata)?
    .client_id("my-resource-server")
    .aud("api://my-resource")
    .client_auth(ClientSecret::new(client_secret))
    .http_client(http_client.clone())
    .build()
    .await?;
# Ok(())
# }
```

## 3b. Alternative: Build without authorization server metadata

```rust
use huskarl_resource_server::{
    core::{
        client_auth::ClientSecret,
        secrets::{EnvVarSecret, encodings::StringEncoding},
    },
    validator::introspection::IntrospectionValidator,
};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
# let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;

let validator = IntrospectionValidator::builder()
    .client_id("my-resource-server")
    .issuer("https://my-issuer")
    .introspection_endpoint("https://my-issuer/oauth/introspect".parse()?)
    .aud("api://my-resource")
    .client_auth(ClientSecret::new(client_secret))
    .http_client(http_client.clone())
    .build()
    .await?;
# Ok(())
# }
```

## 3c. Construction and defaults

`builder_from_metadata` copies the issuer, endpoint URLs, and JWKS URI from
the supplied metadata without making HTTP requests. The client ID and
credentials authenticate this resource server to the introspection endpoint;
`.aud(...)` identifies the API the access token must authorize. These values
need not be the same. Pass `ClaimCheck::NoCheck` explicitly if your deployment
does not check token audiences.

`.build().await` does not call the introspection endpoint. If a JWKS URI is
configured, it builds a default `JwksSource` using `http_client` and fetches
keys for signed introspection responses. A failed initial fetch fails
construction. Without a URI or custom factory, there is no key fetch and
only JSON introspection responses can be processed.

`.request_jwt_response(true)` asks for a signed response. Its default is
`false`, and enabling it does not require the server to return a JWT.
Use `.jws_verifier_factory(...)` to configure key refresh or startup policy,
or to supply keys without a URI. With `default-jws-verifier-platform`
disabled, supply `.jws_verifier_platform(...)` explicitly.

Reuse the constructed validator. Each authenticated validation attempt calls
the introspection endpoint; signed responses can also trigger key refresh.
Bearer tokens are accepted unless `.require_dpop(true)` is set. A
`.dpop_jti_checker(...)` can reject reused proofs independently of the
access token's reuse.

## 4. Validate a request

Call
[`IntrospectionValidator::validate_request`](crate::validator::introspection::IntrospectionValidator::validate_request)
with the HTTP request headers, method, and URI. The
[`outcome`](crate::validator::ValidationResult::outcome) field of the result is:

- `Ok(None)` — no authentication header was present
- `Ok(Some(_))` — the token was active; the request is authenticated
- `Err(_)` — a token was present but inactive or the introspection call failed

The URI must be the **absolute external target URI** the client addressed
(scheme + authority + path): it is compared against the `htu` claim of any
DPoP proof (RFC 9449 §4.3). Framework request objects usually carry only the
origin-form path (`/resource`), and behind TLS-terminating or rewriting
proxies only your deployment knows the external URI — reconstruct it from a
configured public base URL or from forwarded headers you trust. A
non-absolute URI fails every DPoP validation with an integration error.

```rust
# use huskarl_resource_server::core::{
#     client_auth::ClientSecret,
#     secrets::{EnvVarSecret, encodings::StringEncoding},
#     server_metadata::AuthorizationServerMetadata,
# };
# use huskarl_resource_server::validator::introspection::IntrospectionValidator;
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
# let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
# let metadata = AuthorizationServerMetadata::fetch().http_client(&http_client).issuer("https://my-issuer").call().await?;
# let validator = IntrospectionValidator::builder_from_metadata(&metadata)?.client_id("my-resource-server").aud("api://my-resource").client_auth(ClientSecret::new(client_secret)).http_client(http_client.clone()).build().await?;
use http::{HeaderValue, Method, Uri, header::AUTHORIZATION};

let mut headers = http::HeaderMap::new();
headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer mF_9.B5f-4.1JqM"));
let method = Method::GET;
let uri = Uri::from_static("https://api.example.com/resource");

let result = validator.validate_request(&headers, &method, &uri, None).await;

match result.outcome {
    Ok(Some(validated)) => println!("Authenticated: subject={:?}", validated.sub),
    Ok(None) => println!("No authentication provided"),
    Err(e) => println!("Introspection failed: {e}"),
}
# Ok(())
# }
```

To turn a failed or unauthenticated result into the HTTP response — status
code, `WWW-Authenticate` challenges, and `DPoP-Nonce` header — see [rejecting
a request](crate::_docs::guide::rfc9068#4-reject-a-request) and the
[`rejection`](crate::rejection) module.
