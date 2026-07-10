# Huskarl — OAuth 2 clients and resource servers for Rust

[![CI](https://github.com/huskarl-rs/huskarl/actions/workflows/ci.yml/badge.svg)](https://github.com/huskarl-rs/huskarl/actions/workflows/ci.yml)
[![Conformance](https://github.com/huskarl-rs/huskarl/actions/workflows/conformance.yml/badge.svg)](https://github.com/huskarl-rs/huskarl/actions/workflows/conformance.yml)

[![huskarl](https://img.shields.io/crates/v/huskarl.svg?label=huskarl)](https://crates.io/crates/huskarl) [![docs.rs](https://img.shields.io/docsrs/huskarl)](https://docs.rs/huskarl)\
[![huskarl-resource-server](https://img.shields.io/crates/v/huskarl-resource-server.svg?label=huskarl-resource-server)](https://crates.io/crates/huskarl-resource-server) [![docs.rs](https://img.shields.io/docsrs/huskarl-resource-server)](https://docs.rs/huskarl-resource-server)\
[![huskarl-core](https://img.shields.io/crates/v/huskarl-core.svg?label=huskarl-core)](https://crates.io/crates/huskarl-core) [![docs.rs](https://img.shields.io/docsrs/huskarl-core)](https://docs.rs/huskarl-core)\
[![huskarl-crypto-native](https://img.shields.io/crates/v/huskarl-crypto-native.svg?label=huskarl-crypto-native)](https://crates.io/crates/huskarl-crypto-native) [![docs.rs](https://img.shields.io/docsrs/huskarl-crypto-native)](https://docs.rs/huskarl-crypto-native)\
[![huskarl-crypto-webcrypto](https://img.shields.io/crates/v/huskarl-crypto-webcrypto.svg?label=huskarl-crypto-webcrypto)](https://crates.io/crates/huskarl-crypto-webcrypto) [![docs.rs](https://img.shields.io/docsrs/huskarl-crypto-webcrypto)](https://docs.rs/huskarl-crypto-webcrypto)\
[![huskarl-reqwest](https://img.shields.io/crates/v/huskarl-reqwest.svg?label=huskarl-reqwest)](https://crates.io/crates/huskarl-reqwest) [![docs.rs](https://img.shields.io/docsrs/huskarl-reqwest)](https://docs.rs/huskarl-reqwest)\
[![huskarl-redis](https://img.shields.io/crates/v/huskarl-redis.svg?label=huskarl-redis)](https://crates.io/crates/huskarl-redis) [![docs.rs](https://img.shields.io/docsrs/huskarl-redis)](https://docs.rs/huskarl-redis)

A húskarl was a well-paid, well-trained household bodyguard in medieval
northern Europe. Likewise, huskarl guards access to your services: a suite of
Rust crates for **requesting** and **validating** `OAuth2` access tokens — the
two jobs that client authors and service deployers face every day.

Its premise is that the modern `OAuth2` security extensions — often marketed
"for high-security and regulated environments" — should not be treated as
optional extras. Security is not a checkbox for passing regulation; if
sender-constrained tokens and signed authorization requests are easy to add,
why not have them? Huskarl makes them accessible with minimal ceremony.

## Why huskarl

- **Tested against the OpenID conformance suite.** The client passes the test
  plans used for `OpenID Connect` Core (Basic client) certification, plus the
  **FAPI 2.0 Security Profile** and **FAPI 2.0 Message Signing** client plans
  (huskarl has not been formally certified — the same suites run locally and
  in CI). The grants also run end-to-end against real authorization servers:
  Keycloak, Dex, `node-oidc-provider`, and Okta.
- **Modern extensions with minimal ceremony.** `DPoP` sender-constrained
  tokens, pushed (PAR) and signed (JAR) authorization requests, PKCE,
  `private_key_jwt`, and mTLS client authentication are builder options, not
  projects.
- **Keys and secrets can stay out of process memory.** Signing, verification,
  and secret access are async traits, so signing keys can live in a cloud KMS
  or HSM, and client secrets can come from a secret manager — with built-in
  wrappers that keep them redacted in logs and `Debug` output, decoded, and
  cached.
- **Token lifecycle in the box.** A token cache with single-flight refresh,
  and an HTTP authorizer that attaches (and `DPoP`-binds) tokens to outgoing
  requests, so grants compose into "make an authenticated request" rather
  than "exchange once, then good luck".
- **Both roles.** The client side (grants, cache, authorizer) and the
  resource-server side (RFC 9068 access-token validation, introspection,
  server-side `DPoP`, `WWW-Authenticate` challenges).
- **Comfortable to hold.** Strategy traits are dyn-capable, so clients and
  authorizers are plain storable values — no tower of generic parameters —
  and every operation returns one concrete `Error`/`ErrorKind` that embeds
  cleanly in your own error type. Type-safe builders make missing
  configuration a compile error.
- **Hardened defaults.** `forbid(unsafe_code)`; no `unwrap`/`expect`/`panic`
  in library code; HTTP response bodies and fetched JWKS sizes are bounded by
  default; fuzzing and `cargo-deny` in CI.
- **Runs on most `std` platforms, including WASM** (via a `WebCrypto` backend).

## Quick start

A client obtaining a token with the client-credentials grant
(`cargo add huskarl huskarl-reqwest`):

```rust
use huskarl::prelude::*;
use huskarl::core::client_auth::ClientSecret;
use huskarl::core::secrets::EnvVarSecret;
use huskarl::core::server_metadata::AuthorizationServerMetadata;
use huskarl::grant::client_credentials::{
    ClientCredentialsGrant, ClientCredentialsGrantParameters,
};
use huskarl_reqwest::ReqwestClient;

async fn fetch_token() -> Result<(), huskarl::core::Error> {
    let http_client = ReqwestClient::builder().build().await?;

    // RFC 8414 / OIDC discovery.
    let metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer("https://as.example.com")
        .call()
        .await?;

    let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
        .client_id("my-client")
        .http_client(http_client)
        .client_auth(ClientSecret::new(EnvVarSecret::string("CLIENT_SECRET")?))
        .build();

    let token_response = grant
        .exchange(
            ClientCredentialsGrantParameters::builder()
                .scope(bon::vec!["read"])
                .build(),
        )
        .await?;

    println!(
        "access token: {}",
        token_response.access_token().token().expose_secret()
    );
    Ok(())
}
```

And a resource server validating RFC 9068 JWT access tokens against the
issuer's JWKS (`cargo add huskarl-resource-server huskarl-reqwest`):

```rust
use std::sync::Arc;

use huskarl_resource_server::{
    core::{Error, jwk::JwksSource},
    validator::rfc9068::Rfc9068Validator,
};

async fn build_validator(
    http_client: huskarl_reqwest::ReqwestClient,
) -> Result<Rfc9068Validator, Error> {
    Rfc9068Validator::builder()
        .issuer("https://as.example.com")
        .audience("https://api.example.com")
        .jws_verifier_factory(Arc::new(
            JwksSource::builder().http_client(http_client).build(),
        ))
        .build()
        .await
}
```

The grants cover authorization code (with PKCE, PAR, and JAR), client
credentials, refresh, device authorization, token exchange (RFC 8693), and
JWT bearer (RFC 7523); the [`registration`] module adds dynamic client
registration (RFC 7591). Each crate's how-to guides and design explanations
live in its `_docs` module — see
[huskarl](https://docs.rs/huskarl/latest/huskarl/_docs/),
[huskarl-resource-server](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/),
and [huskarl-core](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/).

[`registration`]: https://docs.rs/huskarl/latest/huskarl/registration/

## Conformance and interoperability testing

Huskarl is verified two ways, both mirrored in CI:

- **Provider matrix** — the grants run end-to-end against real authorization
  servers. Keycloak exercises the full flow set (client credentials including
  `DPoP` and private-key-JWT, refresh, introspection, mTLS, and authorization
  code with PAR/JAR); the authorization-code flow also runs against Dex,
  node-oidc-provider, and Okta (the latter two with PAR and JAR too).
  `mise run matrix` prints the coverage report and `mise run providers:test`
  runs the suite.
- **OpenID conformance suite** — the huskarl client passes the test plans
  used for certification: **OpenID Connect Core** (Basic client), and the
  **FAPI 2.0 Security Profile** and **FAPI 2.0 Message Signing** client plans
  (the FAPI plans add private-key-JWT authentication, `DPoP`
  sender-constrained tokens, and signed/JAR authorization requests). Huskarl
  has not been submitted for formal certification; the suites run against the
  [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite) via
  `mise run conformance:test:oidc` and `mise run conformance:test:fapi2`.

See [`integration/README.md`](integration/README.md) for the full provider
matrix, and
[`integration/huskarl-conformance/README.md`](integration/huskarl-conformance/README.md)
for the conformance setup.

## Crates

| Crate | Role |
|---|---|
| [`huskarl`](https://docs.rs/huskarl) | `OAuth2` **clients** (OIDC relying parties): grants, token cache, HTTP authorizer, dynamic registration |
| [`huskarl-resource-server`](https://docs.rs/huskarl-resource-server) | `OAuth2` **resource servers**: access-token validation (RFC 9068 and introspection), server-side `DPoP`, `WWW-Authenticate` |
| [`huskarl-core`](https://docs.rs/huskarl-core) | The shared **foundation**: JWT/JWK handling, crypto and secret traits, client authentication, `DPoP` primitives, server metadata, wire encoding, the `Error` type |
| [`huskarl-crypto-native`](https://docs.rs/huskarl-crypto-native) | Crypto backend built on the RustCrypto crates |
| [`huskarl-crypto-webcrypto`](https://docs.rs/huskarl-crypto-webcrypto) | Crypto backend built on `WebCrypto`, for WASM environments |
| [`huskarl-reqwest`](https://docs.rs/huskarl-reqwest) | [`reqwest`](https://docs.rs/reqwest)-backed HTTP client for the crates above |
| [`huskarl-redis`](https://docs.rs/huskarl-redis) | Redis-backed replay prevention: shares the JWT/`DPoP` `jti` seen-set across server replicas |

A rule of thumb for the split: if both a resource server and a client might
need it, it lives in `huskarl-core`.

## Design notes

**Async first.** Secret access and cryptographic operations are async traits.
This is what lets a signing key live in `WebCrypto`, a cloud KMS, or an HSM
rather than in process memory — a network round trip fits the same interface
as an in-memory key.

**Traits for extensibility.** Crypto platforms, secret providers, grants,
client authentication methods, JWKS sources, refresh-token stores, and HTTP
clients are all defined as traits you can implement yourself when the
provided implementations don't fit. The strategy traits are dyn-capable, so
your own implementations plug in as `Arc<dyn …>` values.

**A struct per grant, built with [`bon`](https://docs.rs/bon).** Each grant
is its own type that knows exactly what it needs: required options are
enforced at compile time, irrelevant ones aren't mentioned, and the builder
machinery disappears after construction.

**One error type.** Every operation returns the same concrete
`Error`/`ErrorKind` pair, designed to embed in your application's error type
without generics.

The design rationale — the error model, untrusted-key handling, crypto
strategy composition, validator choice — is written up in the `_docs` modules
linked above.

## Supported specifications

### Core framework

- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 6750 - Bearer Token Usage

### Token management

- RFC 7009 - Token Revocation
- RFC 7662 - Token Introspection
- RFC 9701 - JWT Response for Token Introspection

### JWT / cryptography

- RFC 7515 - JSON Web Signature (JWS)
- RFC 7517 - JSON Web Key (JWK)
- RFC 7518 - JSON Web Algorithms (JWA)
- RFC 7519 - JSON Web Token (JWT)
- RFC 7521 - Assertion Framework for OAuth 2.0
- RFC 7523 - JWT Profile for Client Authentication and Authorization Grants
- RFC 7800 - Proof-of-Possession Key Semantics for JWTs

### Security extensions

- RFC 7636 - PKCE
- RFC 8705 - mTLS Client Auth & Certificate-Bound Tokens
- RFC 8707 - Resource Indicators
- RFC 9101 - JWT-Secured Authorization Request (JAR)
- RFC 9126 - Pushed Authorization Requests (PAR)
- RFC 9449 - DPoP

### Authorization flows

- RFC 8252 - OAuth 2.0 for Native Apps
- RFC 8628 - Device Authorization Grant
- RFC 8693 - Token Exchange

### Discovery & metadata

- RFC 8414 - Authorization Server Metadata
- RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens
- RFC 9207 - Authorization Server Issuer Identification

### Client lifecycle

- RFC 7591 - Dynamic Client Registration

### OpenID Connect

- OpenID Connect Core 1.0

## Status

Huskarl is pre-1.0: the API is still evolving, and the crates version
independently (a breaking change in one does not force a major bump in the
others). It is used in production, and changes are gated by the conformance
and provider-matrix suites above.

Minimum supported Rust version: **1.92** (edition 2024).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
