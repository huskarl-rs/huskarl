<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme --manifest-path huskarl-resource-server/Cargo.toml

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

# OAuth 2.0 library for resource servers

A resource server has two jobs: validate the access token presented with a
request, and decide whether that token authorizes the request.

This crate does the first. A [`validator`](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/validator/) verifies the token
(signature/introspection, expiry, audience, and any sender-constraint
binding) and returns a [`ValidatedRequest`](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/validator/struct.ValidatedRequest.html)
carrying its claims — from which your application makes the second decision.
When validation fails, [`rejection`](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/rejection/) turns the failure into the matching
response: status code, `WWW-Authenticate` challenges, and `DPoP-Nonce`.

Framework users can start with the companion
[huskarl-axum](https://github.com/huskarl-rs/huskarl-axum) (unreleased) or
[huskarl-pingora](https://github.com/huskarl-rs/huskarl-pingora) adapters.
This crate supplies their framework-independent validation primitives.

## Documentation

- **Solve a task:** use the [how-to guides](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/guide/) to validate
  [RFC 9068 JWTs](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/guide/rfc9068/),
  [custom JWTs](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/guide/custom/), or tokens via
  [introspection](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/guide/introspection/); accept
  [several issuers](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/guide/multi_issuer/); or enforce
  [`DPoP`](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/guide/dpop/).
- **Understand the design:** read the [explanation](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/explanation/) of
  [validator choice](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/explanation/choosing_a_validator/), the
  [error model](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/explanation/error_handling/), and
  [multi-issuer routing](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/explanation/multi_issuer_routing/).
- **Look up the API:** use the crate modules and item pages in this reference.

## The huskarl ecosystem

This crate is one of three that fit together. Each carries its own how-to
guides and explanation in a `_docs` module:

- [`huskarl`](https://docs.rs/huskarl) — OAuth 2.0 **clients**: grants, token
  caching, and the request authorizer.
- **`huskarl-resource-server`** (this crate) — **resource servers**:
  access-token validation and request authorization.
- [`huskarl-core`](https://docs.rs/huskarl-core) — the shared **foundation**
  the other two build on.

## Example with RFC 9068 token validation:

```rust
use huskarl_resource_server::{core::http::HttpClient, validator::rfc9068::Rfc9068Validator};

let validator = Rfc9068Validator::builder()
    .issuer("https://issuer")
    .audience("audience")
    .jwks_uri("https://issuer/jwks.json".parse().unwrap())
    .jwks_source(http_client)
    .build()
    .await?;
```

<!-- cargo-reedme: end -->
