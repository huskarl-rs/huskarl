/*!
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

## What's here

- **JOSE primitives** — [`jwt`] builds, signs, and validates JWTs; [`jwk`]
  parses and produces JWK/JWKS wire types; [`crypto`] holds the signing,
  verification, and encryption traits plus a set of composable wrappers
  (multi-key, refreshable, retrying).
- **Secret handling** — [`secrets`] retrieves credentials from environment
  variables, files, or your own provider, behind redacted wrappers that keep
  them out of logs, with optional decoding and caching.
- **Client authentication** — [`client_auth`] carries the ways a client
  authenticates to an authorization server (client secret, private-key JWT, or
  none).
- **`DPoP`** — [`dpop`] provides proof-of-possession binding for the
  authorization-server and resource-server flows, plus server-side nonce
  issuance and validation.
- **HTTP** — [`http`] defines the [`HttpClient`](http::HttpClient) seam that
  decouples the ecosystem from any specific HTTP implementation.
- **Authorization-server metadata** — [`server_metadata`] models RFC 8414 /
  OIDC discovery documents.
- **Wire encoding** — [`oauth_form`] serializes OAuth messages as
  `application/x-www-form-urlencoded`, including structured RFC 9396 values.
- **Errors** — flows return one concrete [`Error`] with a programmatic
  classification, which embeds cleanly in your own error type. A few subsystems return their
  own typed errors where the variants *are* the API — JWT validation
  ([`JwtValidationError`](jwt::validator::JwtValidationError)), low-level
  verification ([`crypto::verifier`]), and wire encoding
  ([`oauth_form::FormError`]) — design one `From` arm for [`Error`] plus arms for
  the subsystem errors you call directly.

## Guides and explanation

The API items here are the **reference** documentation. For task-oriented how-to
guides — [building](_docs::guide::signing_a_jwt) and
[validating](_docs::guide::validating_a_jwt) JWTs,
[providing secrets](_docs::guide::providing_secrets), and
[implementing a backend](_docs::guide::implementing_a_backend) — and design
explanation — [the error model](_docs::explanation::error_handling),
[handling untrusted keys](_docs::explanation::untrusted_keys), and
[composing crypto strategies](_docs::explanation::crypto_strategies) — see the
[`_docs`] module.
*/

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// The dyn-capable strategy traits are shared between native and wasm32 behind
// `Arc<dyn Trait>`. On wasm32 (single-threaded) the implementations are
// intentionally not `Send`/`Sync` (see `platform::MaybeSend`), which trips this
// lint even though the `Arc` never crosses a thread boundary there.
#![cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]

mod endpoint_url;
mod uuid;
mod well_known;

#[cfg(any(doc, docsrs))]
pub mod _docs;

pub mod authorization_details;
pub mod client_auth;
pub mod crypto;
pub mod dpop;
pub mod error;
pub mod http;
pub mod jwk;
pub mod jwt;
pub mod oauth_error;
pub mod oauth_form;
pub mod platform;
pub mod prelude;
pub mod resource_metadata;
pub mod secrets;
pub mod serde_utils;
pub mod server_metadata;

pub use authorization_details::AuthorizationDetail;
pub use endpoint_url::EndpointUrl;
pub use error::{Chain, Error, ErrorKind, RetryAdvice};
pub use oauth_error::{OAuthError, OAuthErrorCode, UnknownCode};
