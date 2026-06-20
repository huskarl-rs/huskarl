<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

The foundational traits and types for the huskarl `OAuth2` ecosystem.

Most applications depend on the higher-level `huskarl` crate (grants, token
cache, authorizer) rather than this crate directly. `huskarl-core` is the shared
base they build on: the one concrete [`Error`](https://docs.rs/huskarl-core/latest/huskarl_core/error/struct.Error.html)/[`ErrorKind`](https://docs.rs/huskarl-core/latest/huskarl_core/error/enum.ErrorKind.html), the
[`HttpClient`](https://docs.rs/huskarl-core/latest/huskarl_core/http/trait.HttpClient.html) abstraction, client authentication
([`client_auth`](https://docs.rs/huskarl-core/latest/huskarl_core/client_auth/)), `DPoP` ([`dpop`](https://docs.rs/huskarl-core/latest/huskarl_core/dpop/)), the JOSE primitives ([`jwt`](https://docs.rs/huskarl-core/latest/huskarl_core/jwt/), [`jwk`](https://docs.rs/huskarl-core/latest/huskarl_core/jwk/),
[`crypto`](https://docs.rs/huskarl-core/latest/huskarl_core/crypto/)), secret handling ([`secrets`](https://docs.rs/huskarl-core/latest/huskarl_core/secrets/)), and authorization-server metadata
([`server_metadata`](https://docs.rs/huskarl-core/latest/huskarl_core/server_metadata/)). Implement its traits to plug in a transport, crypto
backend, or secret source.

<!-- cargo-reedme: end -->
