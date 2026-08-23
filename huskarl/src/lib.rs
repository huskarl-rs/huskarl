/*!
An OAuth 2.0 client toolkit for obtaining, caching, and using access tokens.

Use a grant to obtain a token, wrap it in the cache to manage its lifecycle,
then use the HTTP authorizer to attach it to outgoing resource requests. Each
grant exposes only the parameters and interactive steps required by that flow.

## Documentation

- **Learn:** [get your first access token](_docs::tutorial::first_token) against
  a local authorization server.
- **Solve a task:** use the [how-to guides](_docs::guide) to configure a grant,
  choose [client authentication](_docs::guide::client_authentication), add
  [`DPoP`](_docs::guide::dpop), cache tokens, or authorize requests.
- **Understand the design:** read the [explanation](_docs::explanation) of the
  error model, refresh timing, token-source resolution, and shared stores.
- **Look up the API:** use the crate modules and item pages in this reference.

Most applications wrap a grant in an
[`InMemoryTokenCache`](cache::InMemoryTokenCache) and an
[`HttpAuthorizer`](authorizer::HttpAuthorizer) for the request path. Most
operations return [`Error`](core::Error); token acquisition returns
[`TokenError`], whose [`Recovery`] guides
application control flow. See [caching tokens and wiring an
authorizer](_docs::guide::caching) and the [error-handling
guide](_docs::guide::handling_errors).

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

Huskarl's client is verified against the official [OpenID conformance
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
grants add interactive steps first. Each has a [how-to guide](_docs::guide) with
setup and a worked example.

- [`ClientCredentialsGrant`](grant::client_credentials::ClientCredentialsGrant) — RFC 6749 §4.4
- [`RefreshGrant`](grant::refresh::RefreshGrant) — RFC 6749 §6
- [`AuthorizationCodeGrant`](grant::authorization_code::AuthorizationCodeGrant) — RFC 6749 §4.1
- [`DeviceAuthorizationGrant`](grant::device_authorization::DeviceAuthorizationGrant) — RFC 8628
- [`TokenExchangeGrant`](grant::token_exchange::TokenExchangeGrant) — RFC 8693
- [`JwtBearerGrant`](grant::jwt_bearer::JwtBearerGrant) — RFC 7523

Further grants — CIBA, provider-specific flows — can be implemented in this
crate or by external crates. The [`registration`] module implements OAuth 2.0
Dynamic Client Registration (RFC 7591).

*/

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![warn(clippy::pedantic)]
// bon's multiple `on(..., into)` clauses (e.g. `on(String, into), on(SecretString, into)`)
// trip this lint, which sees the repeated `into` token as a duplicated attribute.
#![allow(clippy::duplicated_attributes)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod serde_utils;

#[cfg(any(doc, docsrs))]
pub mod _docs;

pub mod authorizer;
pub mod cache;
pub mod grant;
pub mod prelude;
pub mod registration;
pub mod revocation;
pub mod token;
pub mod userinfo;

use std::sync::Arc;

#[doc(inline)]
pub use huskarl_core as core;

#[doc(inline)]
pub use crate::cache::{Recovery, TokenError, TokenOutcome};
#[doc(inline)]
pub use crate::grant::GrantOutcome;

/// A type-erased wrapper around a [`core::crypto::verifier::JwsVerifierPlatform`] for use as a feature-gated default.
#[derive(Debug, Clone)]
pub struct DefaultJwsVerifierPlatform(Arc<dyn core::crypto::verifier::JwsVerifierPlatform>);

impl From<DefaultJwsVerifierPlatform> for Arc<dyn core::crypto::verifier::JwsVerifierPlatform> {
    fn from(value: DefaultJwsVerifierPlatform) -> Self {
        value.0
    }
}

/// The default JWS verifier platform for native platforms.
#[cfg(all(
    feature = "default-jws-verifier-platform",
    not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))
))]
impl Default for DefaultJwsVerifierPlatform {
    fn default() -> Self {
        Self(Arc::new(huskarl_crypto_native::NativeVerifierPlatform))
    }
}

/// The default JWS verifier platform for WebAssembly/WebCrypto platforms.
#[cfg(all(
    feature = "default-jws-verifier-platform",
    all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))
))]
impl Default for DefaultJwsVerifierPlatform {
    fn default() -> Self {
        Self(Arc::new(
            huskarl_crypto_webcrypto::WebCryptoVerifierPlatform::default(),
        ))
    }
}

// Keep the list of control-flow error types in one explanatory document.
#[cfg(test)]
mod control_flow_error_types {
    // Public APIs returning these types expect callers to branch on variants.
    const EXCEPTIONS: &[&str] = &["PollError", "LoopbackError", "ParseCallbackError"];

    const CRATE_MODEL: &str = include_str!("../docs/explanation/error_handling.md");
    const CORE_MODEL: &str = include_str!("../../huskarl-core/docs/explanation/error_handling.md");

    // Each exception must be discoverable from the error-model explanation.
    #[test]
    fn every_exception_is_documented() {
        for name in EXCEPTIONS {
            assert!(
                CRATE_MODEL.contains(name),
                "{name} is returned instead of `Error` but the error-handling page \
                 does not mention it — a reader meeting it has nowhere to learn why"
            );
        }
    }

    // Core explains the generic model but does not enumerate this crate's
    // specialized control-flow errors.
    #[test]
    fn the_core_page_does_not_keep_a_second_list() {
        for name in EXCEPTIONS {
            assert!(
                !CORE_MODEL.contains(name),
                "the core error model names {name}, which puts the list of \
                 exceptions in two places again — state the rule there and leave \
                 the enumeration to this crate's page"
            );
        }
    }
}
