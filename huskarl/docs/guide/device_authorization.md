# Device authorization grant

[`DeviceAuthorizationGrant`](crate::grant::device_authorization::DeviceAuthorizationGrant)
(RFC 8628) is used for devices with limited input capabilities, such as smart
TVs or CLI tools. The device displays a short code and URL for the user to
visit on a separate device, then polls the token endpoint until authorization
completes or the code expires.

## 1. Set up your HTTP client and client authentication

See [Setting up an HTTP client and client
authentication](crate::_docs::guide::setup) for the shared setup the rest of
this page assumes. Device authorization is commonly used by public clients (CLI
tools, smart TVs) that use `NoAuth`; confidential clients pass their
credentials instead.

## 2a. Set up the grant with authorization server metadata

Note: `builder_from_metadata` errors if the server advertises no device
authorization endpoint. Since the device flow is optional, add `.ok()` to treat
an absent endpoint as "unsupported" rather than a failure.

```rust
use huskarl::{
    core::{client_auth::NoAuth, server_metadata::AuthorizationServerMetadata},
    grant::device_authorization::DeviceAuthorizationGrant,
};
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder()
#     .build()
#     .await?;

let metadata = AuthorizationServerMetadata::fetch()
    .http_client(&client)
    .issuer("https://my-issuer")
    .call()
    .await?;

let grant: DeviceAuthorizationGrant =
    DeviceAuthorizationGrant::builder_from_metadata(&metadata)?
        .client_id("client_id")
        .http_client(client)
        .client_auth(NoAuth)
        .build();
# Ok(())
# }
```

## 2b. Alternative: Set up the grant without metadata

```rust
use huskarl::{
    core::client_auth::NoAuth, grant::device_authorization::DeviceAuthorizationGrant,
};
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder()
#     .build()
#     .await?;

let grant: DeviceAuthorizationGrant = DeviceAuthorizationGrant::builder()
    .device_authorization_endpoint("https://my-server/device_authorization".parse()?)
    .token_endpoint("https://my-server/token".parse()?)
    .client_id("client_id")
    .http_client(client)
    .client_auth(NoAuth)
    .build();
# Ok(())
# }
```

## 3. Start the device authorization flow

```rust
use huskarl::{
    core::client_auth::NoAuth,
    grant::device_authorization::{DeviceAuthorizationGrant, StartInput},
};
# async fn start_flow(
#     grant: &DeviceAuthorizationGrant,
# ) -> Result<(), Box<dyn std::error::Error>> {

let start_output = grant.start(StartInput::scope(bon::vec!["read", "write"])).await?;

// Display to the user — they visit the URL and enter the code on another device.
println!("Visit: {}", start_output.verification_uri);
println!("Code: {}", start_output.user_code);
# Ok(())
# }
```

## 4. Poll for completion

```rust
use huskarl::{
    core::client_auth::NoAuth,
    grant::device_authorization::{DeviceAuthorizationGrant, StartOutput},
    token::AccessToken,
};
# async fn poll_flow(
#     grant: &DeviceAuthorizationGrant,
#     start_output: StartOutput,
# ) -> Result<(), Box<dyn std::error::Error>> {

let mut pending_state = start_output.pending_state;
let response = grant.poll_to_completion(&mut pending_state, None).await?;
let token: &AccessToken = response.access_token();
# Ok(())
# }
```

## 5. Validate an ID token if the provider returns one

Neither [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#Authentication)
nor [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) defines ID-token
issuance for the device grant. Some providers nevertheless return ID tokens
when `openid` is requested. [OpenID Connect Key Binding draft 03](https://openid.net/specs/openid-connect-key-binding-1_0-03.html#section-3)
explicitly covers the device flow for key-bound ID tokens; it is not a final standard.

Check your provider's support before requesting `openid` in `start()`.
Polling returns any ID token without validating it. Before using its identity
claims, validate it with the OP's verification keys, issuer, and your client ID:

```rust
use huskarl::{
    core::crypto::verifier::JwsVerifier,
    grant::core::TokenResponse,
    token::id_token::IdTokenValidator,
};
# async fn validate(
#     verifier: impl JwsVerifier + 'static,
#     response: &TokenResponse,
# ) -> Result<(), Box<dyn std::error::Error>> {
let validator = IdTokenValidator::builder()
    .verifier(verifier)
    .issuer("https://my-issuer")
    .audience("client_id")
    .build();

if let Some(id_token) = response.id_token() {
    let claims = validator.validate(id_token, None).await?;
    // Use the validated identity claims within your application.
}
# Ok(())
# }
```

## Request a key-bound ID token

Enable `experimental-oidc-key-binding`, configure a [DPoP signer](crate::_docs::guide::dpop),
and request `openid` and `bound_key`. On the validator builder above, add
`.openid_bound_key_requested(pending_state.openid_bound_key_requested)` to
accept `dpop+id_token` as well as ordinary ID tokens if the OP ignores `bound_key`.

Retain the original signing key for subsequent refreshes, including for
confidential clients. See the [refresh guide](crate::_docs::guide::refresh)
and [key-binding behavior](crate::_docs::explanation::dpop_bindings#id-token-key-binding)
for validation limits and draft compatibility.
