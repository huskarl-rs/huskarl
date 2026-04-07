<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

# `OAuth2` library for resource servers.

This library handles concerns of interest to `OAuth2` resource servers. The primary need
in this case is validating provided access tokens, and checking whether the authorization
matches the necessary level.

Currently this crate helps to handle the first of these; validating access tokens. It
then provides the context from those access tokens which let the server implement the
rest of the authorization checking.

## Example with RFC 9068 token validation:

```rust
use std::sync::Arc;
use huskarl_resource_server::core::jwk::JwksSource;
use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;

let validator = Rfc9068Validator::builder()
  .issuer("https://issuer")
  .audience("audience")
  .jws_verifier_factory(Arc::new(JwksSource::builder().http_client(http_client).build()))
  .build();
```

<!-- cargo-reedme: end -->
