<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

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

## Guides and explanation

The API items in this crate are the **reference** documentation. For
task-oriented how-to guides — setting up each grant, choosing [client
authentication](https://docs.rs/huskarl/latest/huskarl/_docs/guide/client_authentication/), sender-constraining
tokens with [`DPoP`](https://docs.rs/huskarl/latest/huskarl/_docs/guide/dpop/), caching tokens, and making
authenticated requests — and design explanation (error handling, sharing a
refresh token store, refresh timing), see the [`_docs`](https://docs.rs/huskarl/latest/huskarl/_docs/) module.

Most applications wrap a grant in an
[`InMemoryTokenCache`](https://docs.rs/huskarl/latest/huskarl/cache/in_memory/struct.InMemoryTokenCache.html) and an
[`HttpAuthorizer`](https://docs.rs/huskarl/latest/huskarl/authorizer/struct.HttpAuthorizer.html) for the request path. Most
operations return [`Error`](https://docs.rs/huskarl_core/latest/huskarl_core/error/struct.Error.html); token acquisition returns
[`TokenError`](https://docs.rs/huskarl/latest/huskarl/cache/struct.TokenError.html), whose [`Recovery`](https://docs.rs/huskarl/latest/huskarl/cache/enum.Recovery.html) guides
application control flow. See [caching tokens and wiring an
authorizer](https://docs.rs/huskarl/latest/huskarl/_docs/guide/caching/) and the [error-handling
guide](https://docs.rs/huskarl/latest/huskarl/_docs/guide/handling_errors/).

<!-- cargo-reedme: end -->
