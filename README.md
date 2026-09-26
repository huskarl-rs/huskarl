# Huskarl — OAuth 2 clients and resource servers for Rust

[![CI](https://github.com/huskarl-rs/huskarl/actions/workflows/ci.yml/badge.svg)](https://github.com/huskarl-rs/huskarl/actions/workflows/ci.yml)
[![Conformance](https://github.com/huskarl-rs/huskarl/actions/workflows/conformance.yml/badge.svg)](https://github.com/huskarl-rs/huskarl/actions/workflows/conformance.yml)

[![huskarl](https://img.shields.io/crates/v/huskarl.svg?label=huskarl)](https://crates.io/crates/huskarl) [![docs.rs](https://img.shields.io/docsrs/huskarl)](https://docs.rs/huskarl)\
[![huskarl-resource-server](https://img.shields.io/crates/v/huskarl-resource-server.svg?label=huskarl-resource-server)](https://crates.io/crates/huskarl-resource-server) [![docs.rs](https://img.shields.io/docsrs/huskarl-resource-server)](https://docs.rs/huskarl-resource-server)\
[![huskarl-core](https://img.shields.io/crates/v/huskarl-core.svg?label=huskarl-core)](https://crates.io/crates/huskarl-core) [![docs.rs](https://img.shields.io/docsrs/huskarl-core)](https://docs.rs/huskarl-core)\
[![huskarl-crypto-native](https://img.shields.io/crates/v/huskarl-crypto-native.svg?label=huskarl-crypto-native)](https://crates.io/crates/huskarl-crypto-native) [![docs.rs](https://img.shields.io/docsrs/huskarl-crypto-native)](https://docs.rs/huskarl-crypto-native)\
[![huskarl-crypto-webcrypto](https://img.shields.io/crates/v/huskarl-crypto-webcrypto.svg?label=huskarl-crypto-webcrypto)](https://crates.io/crates/huskarl-crypto-webcrypto) [![docs.rs](https://img.shields.io/docsrs/huskarl-crypto-webcrypto)](https://docs.rs/huskarl-crypto-webcrypto)\
[![huskarl-reqwest](https://img.shields.io/crates/v/huskarl-reqwest.svg?label=huskarl-reqwest)](https://crates.io/crates/huskarl-reqwest) [![docs.rs](https://img.shields.io/docsrs/huskarl-reqwest)](https://docs.rs/huskarl-reqwest)\
[![huskarl-redis](https://img.shields.io/crates/v/huskarl-redis.svg?label=huskarl-redis)](https://crates.io/crates/huskarl-redis) [![docs.rs](https://img.shields.io/docsrs/huskarl-redis)](https://docs.rs/huskarl-redis)\
[![huskarl-google-cloud](https://img.shields.io/crates/v/huskarl-google-cloud.svg?label=huskarl-google-cloud)](https://crates.io/crates/huskarl-google-cloud) [![docs.rs](https://img.shields.io/docsrs/huskarl-google-cloud)](https://docs.rs/huskarl-google-cloud)

Huskarl is a suite of Rust crates for obtaining, caching, and validating
OAuth 2.0 access tokens. It supports client applications and resource servers,
with pluggable HTTP, cryptography, and secret-storage backends.

## Documentation

Choose an entry point by what you want to do:

| Goal | Start here |
| --- | --- |
| Learn huskarl by building a working client | [Get your first access token](huskarl/docs/tutorial/first_token.md) |
| Add an OAuth client flow to an application | [Client how-to guides](huskarl/docs/guide/) |
| Validate tokens at a resource server | [Resource-server how-to guides](huskarl-resource-server/docs/guide/) |
| Work directly with JWTs, keys, or secrets | [Core how-to guides](huskarl-core/docs/guide/) |
| Keep keys and secrets in Google Cloud | [Google Cloud how-to guides](huskarl-google-cloud/docs/guide/) |
| Look up crates, modules, types, and methods | [API reference by crate](docs/README.md#reference) |
| Understand security and design decisions | [Explanation](docs/README.md#explanation) |

The [complete documentation map](docs/README.md) separates tutorials, how-to
guides, API reference, and explanation, and lists every workspace guide by
task.

## Framework and login integrations

Companion repositories provide application-facing integrations:

| Task | Repository |
| --- | --- |
| Protect an Axum API or add browser login | [huskarl-axum](https://github.com/huskarl-rs/huskarl-axum) — unreleased; see the repository for development setup |
| Protect an upstream service with Pingora | [huskarl-pingora](https://github.com/huskarl-rs/huskarl-pingora) |
| Integrate login and sessions into another framework | [huskarl-login](https://github.com/huskarl-rs/huskarl-login) |

These repositories use this workspace's grants and validators. For outgoing
service requests, start with the [client examples](huskarl/examples/README.md).

## Capabilities

- Client grants, token caching with single-flight acquisition, and request
  authorization headers.
- Resource-server validation using JWT access tokens or introspection, including
  DPoP proofs and `WWW-Authenticate` challenges.
- PKCE, PAR, JAR, JARM, DPoP, `private_key_jwt`, and mTLS support.
- Async backends for local keys, WebCrypto, Google Cloud KMS, and secret stores.
  KMS signing keys can remain remote; fetched client secrets enter process memory
  and use wrappers that redact `Debug` output.
- Type-safe builders and extensible strategy traits. Shared `Error` values
  describe operation failures; `TokenError` adds token-acquisition recovery.
- Bounded HTTP responses and JWKS sizes by default, plus linting, fuzzing,
  provider tests, and conformance-suite tests.

## Quick start

A client obtaining a token with the client-credentials grant
(`cargo add huskarl` and `cargo add huskarl-reqwest --features rustls-tls`):

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

    // RFC 8414 discovery; use oidc_fetch() for OpenID Connect discovery.
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
                .scope(vec!["read".to_owned()])
                .build(),
        )
        .await?;

    let _access_token = token_response.access_token();
    Ok(())
}
```

And a resource server validating RFC 9068 JWT access tokens against the
issuer's JWKS (`cargo add huskarl-resource-server` and
`cargo add huskarl-reqwest --features rustls-tls`):

```rust
use huskarl_resource_server::{
    core::Error,
    validator::rfc9068::Rfc9068Validator,
};

async fn build_validator(
    http_client: huskarl_reqwest::ReqwestClient,
) -> Result<Rfc9068Validator, Error> {
    Rfc9068Validator::builder()
        .issuer("https://as.example.com")
        .audience("https://api.example.com")
        .jwks_uri("https://as.example.com/jwks.json".parse().unwrap())
        .jwks_source(http_client)
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

The provider suite exercises flows against Keycloak, Dex, and
`node-oidc-provider` in CI. Okta tests are available separately and require a
configured tenant. Run the integration tasks from `integration/`:
`mise run matrix` reports coverage and `mise run providers:test` runs the suite.

The OpenID conformance harness covers OIDC and FAPI client plans. Coverage
varies by plan and variant; a passing test run is not formal certification.
See the [provider matrix](integration/README.md),
[conformance setup](integration/huskarl-conformance/README.md), and
[conformance coverage](integration/huskarl-conformance/docs/coverage.md) for
supported configurations and evidence.

## Crates

| Crate | Role |
|---|---|
| [`huskarl`](https://docs.rs/huskarl) | OAuth 2.0 **clients** (OIDC relying parties): grants, token cache, HTTP authorizer, dynamic registration |
| [`huskarl-resource-server`](https://docs.rs/huskarl-resource-server) | OAuth 2.0 **resource servers**: access-token validation (RFC 9068 and introspection), server-side `DPoP`, `WWW-Authenticate` |
| [`huskarl-core`](https://docs.rs/huskarl-core) | The shared **foundation**: JWT/JWK handling, crypto and secret traits, client authentication, `DPoP` primitives, server metadata, wire encoding, the `Error` type |
| [`huskarl-crypto-native`](https://docs.rs/huskarl-crypto-native) | Crypto backend built on the RustCrypto crates |
| [`huskarl-crypto-webcrypto`](https://docs.rs/huskarl-crypto-webcrypto) | Crypto backend built on `WebCrypto`, for WASM environments |
| [`huskarl-reqwest`](https://docs.rs/huskarl-reqwest) | [`reqwest`](https://docs.rs/reqwest)-backed HTTP client for the crates above |
| [`huskarl-redis`](https://docs.rs/huskarl-redis) | Redis-backed replay prevention: shares the JWT/`DPoP` `jti` seen-set across server replicas |
| [`huskarl-google-cloud`](https://docs.rs/huskarl-google-cloud) | Google Cloud backends: Cloud KMS signing, verification, and AEAD, plus Secret Manager secrets |

A rule of thumb for the split: if both a resource server and a client might
need it, it lives in `huskarl-core`.

## Design

Async strategy traits let applications supply transports, keys, secrets, and
stores. Grant-specific builders check required configuration at compile time;
constructed grants can be reused across requests.

For the rationale behind error handling, key refresh, token caching, and
validator selection, see the [explanation pages](docs/README.md#explanation).

## Supported specifications

### IETF

#### Core framework

- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 6750 - Bearer Token Usage

#### Token management

- RFC 7009 - Token Revocation
- RFC 7662 - Token Introspection
- RFC 9701 - JWT Response for Token Introspection

#### JWT / cryptography

- RFC 7515 - JSON Web Signature (JWS)
- RFC 7517 - JSON Web Key (JWK)
- RFC 7518 - JSON Web Algorithms (JWA)
- RFC 7519 - JSON Web Token (JWT)
- RFC 7521 - Assertion Framework for OAuth 2.0
- RFC 7523 - JWT Profile for Client Authentication and Authorization Grants
- RFC 7800 - Proof-of-Possession Key Semantics for JWTs

#### Security extensions

- RFC 7636 - PKCE
- RFC 8705 - mTLS Client Auth & Certificate-Bound Tokens
- RFC 8707 - Resource Indicators
- RFC 9101 - JWT-Secured Authorization Request (JAR)
- RFC 9126 - Pushed Authorization Requests (PAR)
- RFC 9449 - DPoP

#### Authorization flows

- RFC 8252 - OAuth 2.0 for Native Apps
- RFC 8628 - Device Authorization Grant
- RFC 8693 - Token Exchange

#### Discovery & metadata

- RFC 8414 - Authorization Server Metadata
- RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens
- RFC 9207 - Authorization Server Issuer Identification

#### Client lifecycle

- RFC 7591 - Dynamic Client Registration

### OpenID Foundation

#### Authentication

- OpenID Connect Core 1.0

#### Discovery & metadata

- OpenID Connect Discovery 1.0

#### Response modes

- OAuth 2.0 Multiple Response Type Encoding Practices
- OAuth 2.0 Form Post Response Mode
- JWT Secured Authorization Response Mode (JARM)

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
