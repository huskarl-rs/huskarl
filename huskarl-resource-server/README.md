<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme --manifest-path huskarl-resource-server/Cargo.toml

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

# `OAuth2` library for resource servers.

A resource server has two jobs: validate the access token presented with a
request, and decide whether that token authorizes the request.

This crate does the first. A [`validator`](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/validator/) verifies the token
(signature/introspection, expiry, audience, and any sender-constraint
binding) and returns a [`ValidatedRequest`](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/validator/struct.ValidatedRequest.html)
carrying its claims — from which your application makes the second decision.

## The huskarl ecosystem

This crate is one of three that fit together. Each carries its own how-to
guides and explanation in a `_docs` module:

- [`huskarl`](https://docs.rs/huskarl) — `OAuth2` **clients**: grants, token
  caching, and the request authorizer.
- **`huskarl-resource-server`** (this crate) — **resource servers**:
  access-token validation and request authorization.
- [`huskarl-core`](https://docs.rs/huskarl-core) — the shared **foundation**
  the other two build on.

## Example with RFC 9068 token validation:

```rust
use std::sync::Arc;

use huskarl_resource_server::{
    core::{http::HttpClient, jwk::JwksSource},
    validator::rfc9068::Rfc9068Validator,
};

let validator = Rfc9068Validator::builder()
    .issuer("https://issuer")
    .audience("audience")
    .jws_verifier_factory(Arc::new(
        JwksSource::builder().http_client(http_client).build(),
    ))
    .build();
```

## Guides and explanation

The API items here are the reference docs. For task-oriented how-to guides
(validating RFC 9068, custom, introspection, and multi-issuer tokens) and
design explanation (choosing a validator, how multi-issuer routing stays
safe), see the [`_docs`](https://docs.rs/huskarl-resource-server/latest/huskarl_resource_server/_docs/) module.

<!-- cargo-reedme: end -->
