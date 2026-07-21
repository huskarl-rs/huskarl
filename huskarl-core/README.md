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
base they build on — the utilities below are also useful on their own, whether
you are writing OAuth tooling or implementing a backend for the rest of the
ecosystem.

## The huskarl ecosystem

This crate is one of three that fit together. Each carries its own how-to guides
and explanation in a `_docs` module:

- [`huskarl`](https://docs.rs/huskarl) — `OAuth2` **clients**: grants, token
  caching, and the request authorizer.
- [`huskarl-resource-server`](https://docs.rs/huskarl-resource-server) —
  **resource servers**: access-token validation and request authorization.
- **`huskarl-core`** (this crate) — the shared **foundation** the other two
  build on.

## What’s here

- **JOSE primitives** — [`jwt`](https://docs.rs/huskarl-core/latest/huskarl_core/jwt/) builds, signs, and validates JWTs; [`jwk`](https://docs.rs/huskarl-core/latest/huskarl_core/jwk/)
  parses and produces JWK/JWKS wire types; [`crypto`](https://docs.rs/huskarl-core/latest/huskarl_core/crypto/) holds the signing,
  verification, and encryption traits plus a set of composable wrappers
  (multi-key, refreshable, retrying).
- **Secret handling** — [`secrets`](https://docs.rs/huskarl-core/latest/huskarl_core/secrets/) retrieves credentials from environment
  variables, files, or your own provider, behind redacted wrappers that keep
  them out of logs, with optional decoding and caching.
- **Client authentication** — [`client_auth`](https://docs.rs/huskarl-core/latest/huskarl_core/client_auth/) carries the ways a client
  authenticates to an authorization server (client secret, private-key JWT, or
  none).
- **`DPoP`** — [`dpop`](https://docs.rs/huskarl-core/latest/huskarl_core/dpop/) provides proof-of-possession binding for the
  authorization-server and resource-server flows, plus server-side nonce
  issuance and validation.
- **HTTP** — [`http`](https://docs.rs/huskarl-core/latest/huskarl_core/http/) defines the [`HttpClient`](https://docs.rs/huskarl-core/latest/huskarl_core/http/trait.HttpClient.html) seam that
  decouples the ecosystem from any specific HTTP implementation.
- **Authorization-server metadata** — [`server_metadata`](https://docs.rs/huskarl-core/latest/huskarl_core/server_metadata/) models RFC 8414 /
  OIDC discovery documents.
- **Wire encoding** — [`oauth_form`](https://docs.rs/huskarl-core/latest/huskarl_core/oauth_form/) serializes OAuth messages as
  `application/x-www-form-urlencoded`, including structured RFC 9396 values.
- **Errors** — the flows return the one concrete [`Error`](https://docs.rs/huskarl-core/latest/huskarl_core/error/struct.Error.html)/[`ErrorKind`](https://docs.rs/huskarl-core/latest/huskarl_core/error/enum.ErrorKind.html),
  which embeds cleanly in your own error type. A few subsystems return their
  own typed errors where the variants *are* the API — JWT validation
  ([`JwtValidationError`](https://docs.rs/huskarl-core/latest/huskarl_core/jwt/validator/enum.JwtValidationError.html)), low-level
  verification ([`crypto::verifier`](https://docs.rs/huskarl-core/latest/huskarl_core/crypto/verifier/)), and wire encoding
  ([`oauth_form::Error`](https://docs.rs/huskarl-core/latest/huskarl_core/oauth_form/enum.Error.html)) — design one `From` arm for [`Error`](https://docs.rs/huskarl-core/latest/huskarl_core/error/struct.Error.html) plus arms for
  the subsystem errors you call directly.

## Guides and explanation

The API items here are the **reference** documentation. For task-oriented how-to
guides — [building](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/) and
[validating](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/validating_a_jwt/) JWTs,
[providing secrets](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/providing_secrets/), and
[implementing a backend](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/implementing_a_backend/) — and design
explanation — [the error model](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/error_handling/),
[handling untrusted keys](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/untrusted_keys/), and
[composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/) — see the
[`_docs`](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/) module.

<!-- cargo-reedme: end -->
