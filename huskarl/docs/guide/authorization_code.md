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

Note: `builder_from_metadata` errors if the server advertises no authorization
endpoint.

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

let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder_from_metadata(&metadata)?
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

## 2c. What the builder configures

With discovery metadata, the application supplies its client ID,
authentication, HTTP client, and redirect URI. Metadata supplies server
endpoints and capabilities. `builder_from_metadata` reads the supplied value;
the preceding metadata `.fetch().call().await` performs discovery.

| Setting | Default behavior | When to configure it |
| --- | --- | --- |
| PKCE | Enabled; prefers `S256` | A provider requires different behavior |
| OIDC | Inferred from `openid` in the scope passed to `start()` | Use `.oidc(true)` or `.oidc(false)` to declare the flow explicitly |
| PAR | Used when an endpoint is available; required when the server requires it | Set `.prefer_pushed_authorization_requests(false)` to opt out of optional PAR |
| JAR and JARM | No request object or JWT response mode selected | Supply `.jar(...)` or a JWT-secured `.response_mode(...)` |
| DPoP | Disabled | Supply `.dpop(...)` to use sender-constrained tokens |
| Signature verification | Uses `jwks_uri` and the grant's HTTP client when needed | Supply `.jws_verifier_factory(...)` for custom keys, refresh, or startup policy |

Metadata-populated fields are already set on the returned builder. Use
`builder()` when configuring those fields yourself. Choose additional policy
settings before `.build().await`; per-login scopes and other request inputs
belong to `start()`.

## 2d. What happens during construction

`.build().await` checks the configuration and builds the verifier. When using
the default JWKS source, it attempts an initial key fetch:

- With `.oidc(true)` or a JWT-secured response mode, a failed fetch fails construction.
- With OIDC inferred from scope, a failed fetch is tolerated. Validation retries
  fetching keys when needed; a token cannot pass verification without usable keys.
- With `.oidc(false)` and no JARM, or without a JWKS URI, no default key fetch occurs.

A supplied factory controls its own startup behavior and is called even without
a JWKS URI. With `default-jws-verifier-platform` disabled, provide
`.jws_verifier_platform(...)` whenever a verifier is needed.

Build a grant once and reuse it for multiple authorization flows. Construction
does not start a login or exchange a code. `start()` may send a PAR request;
`complete()` exchanges the code at the token endpoint. Key refresh can also
perform HTTP requests when signatures are verified.

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
`jwks_uri` — or a custom `jws_verifier_factory` — and an issuer) before
`start()` will proceed, and
rejects a token response without an ID token (OIDC Core 1.0 §3.1.3.3) —
unless the server narrowed `openid` out of the granted scope. `complete()`
returns the validated ID token on `CompleteOutput::id_token` alongside the
token response whenever the flow is OIDC.

When metadata provides `jwks_uri`, the grant configures signature verification
using its HTTP client. See [construction behavior](#2d-what-happens-during-construction)
for initial fetch failures and custom factories. Without a URI or custom
factory, an OIDC flow fails at build or start when verification is required.

The `oidc` builder setting overrides this inference for non-standard
servers. `oidc(false)` treats `openid` as an ordinary OAuth scope — for
pure-OAuth servers whose scope merely happens to use that name. Without JARM,
it builds no default verifier and fetches no JWKS; supply `jws_verifier_factory` to still
validate an ID token the server returns anyway. `oidc(true)` applies
OIDC semantics regardless of scope — for servers that issue ID tokens on
their own rules — and a missing ID token is then an error even if the
granted scope omits `openid`. Since `oidc(true)` declares every flow OIDC,
the validation-capability check moves from `start()` to grant build time.

## Signed authorization responses (JARM)

Set `response_mode` to ask the server to return the authorization response as
a signed JWT ([JARM](https://openid.net/specs/oauth-v2-jarm.html)), so the
callback parameters cannot be tampered with in transit:

```rust
use huskarl::{
    core::{client_auth::NoAuth, server_metadata::AuthorizationServerMetadata},
    grant::authorization_code::{AuthorizationCodeGrant, ResponseMode},
};
# async fn setup_jarm_grant(
#     metadata: &AuthorizationServerMetadata,
# ) -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder().build().await?;

let grant: AuthorizationCodeGrant = AuthorizationCodeGrant::builder_from_metadata(metadata)?
    .client_id("client_id")
    .http_client(client)
    .client_auth(NoAuth)
    .redirect_uri("https://my-app/callback")
    // JARM requires signature verification; `builder_from_metadata` supplies the
    // `jwks_uri`, so the default `JwksSource` verifier is used automatically.
    .response_mode(ResponseMode::QueryJwt)
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
`jwks_uri` (or a custom `jws_verifier_factory`) and an issuer — and the grant
fails to build without them.

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

Write the `redirect_uri` with a literal loopback address — `http://127.0.0.1:<port>/…`
or `http://[::1]:<port>/…` — rather than `localhost`, and register that exact URI
with the authorization server (RFC 8252 §7.3). `bind_loopback` binds a single
address family, so a `localhost` redirect may resolve to the family it did not
bind and the callback never arrives.

Requires the `authorization-flow-loopback` feature.
