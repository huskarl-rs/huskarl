<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

An OAuth 2.0 client toolkit for obtaining, caching, and using access tokens.

Use a grant to obtain a token, wrap it in the cache to manage its lifecycle,
then use the HTTP authorizer to attach it to outgoing resource requests. Each
grant exposes only the parameters and interactive steps required by that flow.

## Documentation

- **Learn:** [get your first access token](https://docs.rs/huskarl/latest/huskarl/_docs/tutorial/first_token/) against
  a local authorization server.
- **Solve a task:** use the [how-to guides](https://docs.rs/huskarl/latest/huskarl/_docs/guide/) to configure a grant,
  choose [client authentication](https://docs.rs/huskarl/latest/huskarl/_docs/guide/client_authentication/), add
  [`DPoP`](https://docs.rs/huskarl/latest/huskarl/_docs/guide/dpop/), cache tokens, or authorize requests.
- **Understand the design:** read the [explanation](https://docs.rs/huskarl/latest/huskarl/_docs/explanation/) of the
  error model, refresh timing, token-source resolution, and shared stores.
- **Look up the API:** use the crate modules and item pages in this reference.

Most applications wrap a grant in an
[`InMemoryTokenCache`](https://docs.rs/huskarl/latest/huskarl/cache/in_memory/struct.InMemoryTokenCache.html) and an
[`HttpAuthorizer`](https://docs.rs/huskarl/latest/huskarl/authorizer/struct.HttpAuthorizer.html) for the request path. Most
operations return [`Error`](https://docs.rs/huskarl_core/latest/huskarl_core/error/struct.Error.html); token acquisition returns
[`TokenError`](https://docs.rs/huskarl/latest/huskarl/cache/struct.TokenError.html), whose [`Recovery`](https://docs.rs/huskarl/latest/huskarl/cache/enum.Recovery.html) guides
application control flow. See [caching tokens and wiring an
authorizer](https://docs.rs/huskarl/latest/huskarl/_docs/guide/caching/) and the [error-handling
guide](https://docs.rs/huskarl/latest/huskarl/_docs/guide/handling_errors/).

## The huskarl ecosystem

This crate is one of three that fit together. Each carries its own how-to guides
and explanation in a `_docs` module:

- **`huskarl`** (this crate) — OAuth 2.0 **clients**: grants, token caching, and
  the request authorizer.
- [`huskarl-resource-server`](https://docs.rs/huskarl-resource-server) —
  **resource servers**: access-token validation and request authorization.
- [`huskarl-core`](https://docs.rs/huskarl-core) — the shared **foundation** the
  other two build on.

## Conformance and interoperability

Huskarl’s client is verified against the official [OpenID conformance
suite](https://openid.net/certification/). It passes the OpenID Connect Core
*Basic client* certification plan, plus the **FAPI 2.0 Security Profile** and
**Message Signing** client plans — these adding `private_key_jwt` client
authentication, `DPoP` sender-constrained tokens, and signed authorization
requests and responses (JAR and JARM). The grants are additionally run
end-to-end against real
authorization servers — Keycloak, Dex, `node-oidc-provider`, and Okta — in CI.
See the [repository](https://github.com/huskarl-rs/huskarl) for the full provider
matrix and conformance plans.

## Grants

Each grant is driven by grant-specific parameters and exchanges them for a token
at the token endpoint. The simplest need only an `exchange` call; the workflow
grants add interactive steps first. Each has a [how-to guide](https://docs.rs/huskarl/latest/huskarl/_docs/guide/) with
setup and a worked example.

- [`ClientCredentialsGrant`](https://docs.rs/huskarl/latest/huskarl/grant/client_credentials/struct.ClientCredentialsGrant.html) — RFC 6749 §4.4
- [`RefreshGrant`](https://docs.rs/huskarl/latest/huskarl/grant/refresh/struct.RefreshGrant.html) — RFC 6749 §6
- [`AuthorizationCodeGrant`](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/grant/struct.AuthorizationCodeGrant.html) — RFC 6749 §4.1
- [`DeviceAuthorizationGrant`](https://docs.rs/huskarl/latest/huskarl/grant/device_authorization/grant/struct.DeviceAuthorizationGrant.html) — RFC 8628
- [`TokenExchangeGrant`](https://docs.rs/huskarl/latest/huskarl/grant/token_exchange/struct.TokenExchangeGrant.html) — RFC 8693
- [`JwtBearerGrant`](https://docs.rs/huskarl/latest/huskarl/grant/jwt_bearer/struct.JwtBearerGrant.html) — RFC 7523

Further grants — CIBA, provider-specific flows — can be implemented in this
crate or by external crates. The [`registration`](https://docs.rs/huskarl/latest/huskarl/registration/) module implements OAuth 2.0
Dynamic Client Registration (RFC 7591).

<!-- cargo-reedme: end -->
