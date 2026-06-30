<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme --manifest-path huskarl/Cargo.toml

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Huskarl provides tools for implementing secure `OAuth2` clients in rust.

This library provides several grant implementations, each driven by grant-specific
parameters that define how the grant/workflow should progress.

The library also provides a caching layer for token responses; and a HTTP authorizer
that can be used to make authenticated requests to resource servers.

## The huskarl ecosystem

This crate is one of three that fit together. Each carries its own how-to guides
and explanation in a `_docs` module:

- **`huskarl`** (this crate) — `OAuth2` **clients**: grants, token caching, and
  the request authorizer.
- [`huskarl-resource-server`](https://docs.rs/huskarl-resource-server) —
  **resource servers**: access-token validation and request authorization.
- [`huskarl-core`](https://docs.rs/huskarl-core) — the shared **foundation** the
  other two build on.

## Conformance and interoperability

Huskarl’s client is verified against the official [`OpenID` conformance
suite](https://openid.net/certification/). It passes the `OpenID Connect` Core
*Basic client* certification plan, plus the **FAPI 2.0 Security Profile** and
**Message Signing** client plans — these adding `private_key_jwt` client
authentication, `DPoP` sender-constrained tokens, and signed authorization
requests (JAR). The grants are additionally run end-to-end against real
authorization servers — Keycloak, Dex, `node-oidc-provider`, and Okta — in CI.
See the [repository](https://github.com/huskarl-rs/huskarl) for the full provider
matrix and conformance plans.

## Setup

1. Create a HTTP client instance (e.g. with `huskarl-reqwest`).
2. Get authorization server metadata (or OIDC discovery data) when appropriate (but not necessary).
3. Set up your client’s authentication.
4. Create the grant, filling in its fields, and supplying the client authentication.

Once you have a grant, how exactly to use it depends on the grant. The simplest grants only
require the `exchange` call, which exchanges grant-specific parameters for a token at the token
endpoint.

Other grants act like workflows, with a set of steps required, which will also involve one
or more calls to the token endpoint.

## Grants provided in this crate:

- [`ClientCredentials`](https://docs.rs/huskarl/latest/huskarl/grant/client_credentials/struct.ClientCredentialsGrant.html)
  Allows a client to exchange its own credentials in return for an access token.
- [`Refresh`](https://docs.rs/huskarl/latest/huskarl/grant/refresh/struct.RefreshGrant.html)
  Allows a client which previously received a refresh token alongside an access token, to exchange
  it in return for an access token.
- [`AuthorizationCode`](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/grant/struct.AuthorizationCodeGrant.html)
  Provides the ability for a client to send the interactive user a URL at which to authenticate;
  a code from a successful authentication is returned to the client, which can exchange it in
  return for an access token.
- [`DeviceAuthorization`](https://docs.rs/huskarl/latest/huskarl/grant/device_authorization/grant/struct.DeviceAuthorizationGrant.html)
  Enables a client to provide a code and/or URL to an interactive user, which they can use to
  log in from another machine. They complete the requirements of login, and the authorization
  server is notified that it can provide the corresponding access token to the client.
- [`TokenExchange`](https://docs.rs/huskarl/latest/huskarl/grant/token_exchange/struct.TokenExchangeGrant.html)
  Allows the client to exchange an existing token for a new security token, supporting
  impersonation and delegation use cases.

Further grants — CIBA, JWT authorization, provider-specific flows — can be implemented in this
crate or by external crates.

Beyond grants, the [`registration`](https://docs.rs/huskarl/latest/huskarl/registration/) module implements OAuth 2.0 Dynamic Client Registration
(RFC 7591), letting a client register itself with an authorization server and obtain the
`client_id`/`client_secret` that drive the grants above.

## Examples

### Client Credentials Grant

```rust
let metadata = AuthorizationServerMetadata::fetch()
    .http_client(&http_client)
    .issuer(issuer)
    .call()
    .await
    .unwrap();

let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
    .client_id(client_id)
    .http_client(http_client)
    .client_auth(ClientSecret::new(client_secret))
    .build();

let token_response = grant
    .exchange(
        ClientCredentialsGrantParameters::builder()
            .scopes(vec!["test"])
            .build(),
    )
    .await
    .unwrap();

println!(
    "Access token: {}",
    token_response.access_token().token().expose_secret()
);
```

## Guides and explanation

The API items in this crate are the **reference** documentation. For
task-oriented how-to guides — setting up each grant, caching tokens, and
making authenticated requests — and design explanation (error handling,
sharing a refresh token store, refresh timing), see the [`_docs`](https://docs.rs/huskarl/latest/huskarl/_docs/) module.

Most applications wrap a grant in an
[`InMemoryTokenCache`](https://docs.rs/huskarl/latest/huskarl/cache/in_memory/struct.InMemoryTokenCache.html) and an
[`HttpAuthorizer`](https://docs.rs/huskarl/latest/huskarl/authorizer/struct.HttpAuthorizer.html) for the request path; every
operation returns the one concrete [`Error`](https://docs.rs/huskarl_core/latest/huskarl_core/error/struct.Error.html) type, which embeds
in your own error enum. See [caching tokens and wiring an
authorizer](https://docs.rs/huskarl/latest/huskarl/_docs/guide/caching/) and [error
handling](https://docs.rs/huskarl/latest/huskarl/_docs/explanation/error_handling/).

<!-- cargo-reedme: end -->
