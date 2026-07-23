# Authorization code grant

[`AuthorizationCodeGrant`](crate::grant::authorization_code::AuthorizationCodeGrant)
(RFC 6749 §4.1) is used when a user needs to authorize the application. The
user is redirected to the authorization server to authenticate and grant
consent, then redirected back with a short-lived code that is exchanged for
tokens. PKCE (RFC 7636) is applied automatically.

## 1. Set up your HTTP client and client authentication

See [Setting up an HTTP client and client
authentication](crate::_docs::guide::setup) for the shared setup the rest of
this page assumes. Public clients (single-page apps, CLI tools) typically use
`NoAuth`; confidential clients pass their credentials instead.

## 2a. Set up the grant with authorization server metadata

Note: `builder_from_metadata` returns `None` if the server does not advertise
an authorization endpoint.

```rust
use huskarl::{
    core::{client_auth::NoAuth, server_metadata::AuthorizationServerMetadata},
    grant::authorization_code::AuthorizationCodeGrant,
};
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder().build().await?;

let metadata = AuthorizationServerMetadata::fetch()
    .http_client(&client)
    .issuer("https://my-issuer")
    .call()
    .await?;

let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
    .expect("server does not support authorization code grant")
    .client_id("client_id")
    .http_client(client)
    .client_auth(NoAuth)
    .redirect_uri("https://my-app/callback")
    .build()
    .await?;
# Ok(())
# }
```

## 2b. Alternative: Set up the grant without metadata

```rust
use huskarl::{core::client_auth::NoAuth, grant::authorization_code::AuthorizationCodeGrant};
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder().build().await?;

let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder()
    .authorization_endpoint("https://my-server/authorize".parse()?)
    .token_endpoint("https://my-server/token".parse()?)
    .client_id("client_id")
    .http_client(client)
    .client_auth(NoAuth)
    .redirect_uri("https://my-app/callback")
    .build()
    .await?;
# Ok(())
# }
```

## 3. Start the authorization flow

Call `start()` to get the URL to redirect the user to and the pending state
that must be persisted until the callback arrives. `PendingState` implements
`Serialize`/`Deserialize` and can be stored in a session or database.

```rust
use huskarl::grant::authorization_code::{AuthorizationCodeGrant, StartInput};
# async fn start_flow(
#     grant: &AuthorizationCodeGrant,
# ) -> Result<(), Box<dyn std::error::Error>> {

let start_output = grant.start(StartInput::scope(bon::vec!["read", "write"])).await?;

// Redirect the user to this URL to authorize.
let authorization_url = start_output.authorization_url;

// Persist this — it is needed to complete the flow when the callback arrives.
let pending_state = start_output.pending_state;
# Ok(())
# }
```

## 4a. Complete the authorization flow

When the authorization server redirects back to your application, parse the
callback URL (or just its query string) into a `CompleteInput` and pass it to
`complete()`. Parsing captures `code`, `state`, and the RFC 9207 `iss`
parameter. An OAuth error response (e.g. the user denied access) also parses;
`complete()` state-checks it like any other callback, then surfaces it with the
server's `oauth_error_code()` and `oauth_error_description()`. An unsolicited
error response is rejected as a state mismatch, not reported as a denied login.

```rust
use huskarl::{
    grant::authorization_code::{AuthorizationCodeGrant, CompleteInput, PendingState},
    token::AccessToken,
};
# async fn complete_flow(
#     grant: &AuthorizationCodeGrant,
#     pending_state: &PendingState,
#     callback_url: &str,
# ) -> Result<(), Box<dyn std::error::Error>> {

// The redirect callback URL, or just its query string
// ("code=..&state=..&iss=..").
let complete_input: CompleteInput = callback_url.parse()?;

let completed = grant.complete(pending_state, complete_input).await?;
let token: &AccessToken = completed.token_response.access_token();
# Ok(())
# }
```

To also set fields the callback does not carry — RFC 8707 `resource`
indicators for the token exchange — use
`CompleteInput::builder_from_callback(url)?`, which returns the parsed but
unbuilt builder, set them, then `build()`.

When building `CompleteInput` via its builder instead (e.g. from
framework-typed query parameters), include `iss`: a server that advertises
RFC 9207 support in its metadata — as conforming servers do — makes the
parameter mandatory, and completion fails with `MissingIssuer` if it is
dropped.

## OpenID Connect flows

Requesting the `openid` scope makes the flow an OIDC authentication: the
grant sends a `nonce`, requires ID-token validation to be configured (a
`jws_verifier_factory` and an issuer) before `start()` will proceed, and
rejects a token response without an ID token (OIDC Core 1.0 §3.1.3.3) —
unless the server narrowed `openid` out of the granted scope. `complete()`
returns the validated ID token on `CompleteOutput::id_token` alongside the
token response whenever the flow is OIDC.

The `oidc` builder setting overrides this inference for non-standard
servers. `oidc(false)` treats `openid` as an ordinary OAuth scope — for
pure-OAuth servers whose scope merely happens to use that name. An ID
token the server returns anyway is still validated. `oidc(true)` applies
OIDC semantics regardless of scope — for servers that issue ID tokens on
their own rules — and a missing ID token is then an error even if the
granted scope omits `openid`. Since `oidc(true)` declares every flow OIDC,
the validation-capability check moves from `start()` to grant build time.

## Signed authorization responses (JARM)

Set `response_mode` to ask the server to return the authorization response as
a signed JWT ([JARM](https://openid.net/specs/oauth-v2-jarm.html)), so the
callback parameters cannot be tampered with in transit:

```rust
use std::sync::Arc;

use huskarl::{
    core::{client_auth::NoAuth, jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
    grant::authorization_code::{AuthorizationCodeGrant, ResponseMode},
};
# async fn setup_jarm_grant(
#     metadata: &AuthorizationServerMetadata,
# ) -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder().build().await?;

let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder_from_metadata(metadata)
    .expect("server does not support authorization code grant")
    .client_id("client_id")
    .http_client(client.clone())
    .client_auth(NoAuth)
    .redirect_uri("https://my-app/callback")
    .response_mode(ResponseMode::QueryJwt)
    .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(client).build()))
    .build()
    .await?;
# Ok(())
# }
```

The rest of the flow is unchanged: parse the callback and call `complete()` as
above. Completion verifies the JWT's signature, issuer, audience, and expiry
before any other check, then runs the usual `state` and `iss` checks on the
verified parameters. A JARM error response is likewise verified before it
surfaces.

Because the client now requires every callback to be a JWT, a JWT-secured
`response_mode` requires ID-token-style validation to be configured — a
`jws_verifier_factory` and an issuer — and the grant fails to build without
them.

Completion enforces the mode in both directions. A plain callback for a flow
that requested JARM is rejected (`MissingJarmResponse`), since honoring it
would let an attacker strip the signature; a `response` JWT
arriving on a flow that did not request JARM is rejected as
`UnexpectedJarmResponse`. This is why the requested mode is recorded in
`PendingState` — persist it along with the rest.

`builder_from_metadata` seeds `allowed_authorization_signed_response_algs`
from the server's `authorization_signing_alg_values_supported`, pinning the
accepted signature algorithms. Encrypted JARM responses are not yet supported.

## 4b. Alternative for CLI tools: complete using the loopback server

For command-line tools, `complete_on_loopback` handles the callback automatically
by binding a local HTTP server to receive it — no need to extract parameters manually.
Use `bind_loopback` to create the listener, include its port in the `redirect_uri`,
and pass it to `complete_on_loopback` after calling `start`.

Requires the `authorization-flow-loopback` feature.
