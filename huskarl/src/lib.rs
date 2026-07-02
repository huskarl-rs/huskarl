/*!
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

Huskarl's client is verified against the official [`OpenID` conformance
suite](https://openid.net/certification/). It passes the `OpenID Connect` Core
*Basic client* certification plan, plus the **FAPI 2.0 Security Profile** and
**Message Signing** client plans — these adding `private_key_jwt` client
authentication, `DPoP` sender-constrained tokens, and signed authorization
requests (JAR). The grants are additionally run end-to-end against real
authorization servers — Keycloak, Dex, `node-oidc-provider`, and Okta — in CI.
See the [repository](https://github.com/huskarl-rs/huskarl) for the full provider
matrix and conformance plans.

## Setup

1. Create a HTTP client instance (e.g. with `huskarl-reqwest`).
2. Get authorization server metadata (or OIDC discovery data) when appropriate (but not necessary).
3. Set up your client's authentication.
4. Create the grant, filling in its fields, and supplying the client authentication.

Once you have a grant, how exactly to use it depends on the grant. The simplest grants only
require the `exchange` call, which exchanges grant-specific parameters for a token at the token
endpoint.

Other grants act like workflows, with a set of steps required, which will also involve one
or more calls to the token endpoint.

## Grants provided in this crate:

- [`ClientCredentials`](grant::client_credentials::ClientCredentialsGrant)
  Allows a client to exchange its own credentials in return for an access token.
- [`Refresh`](grant::refresh::RefreshGrant)
  Allows a client which previously received a refresh token alongside an access token, to exchange
  it in return for an access token.
- [`AuthorizationCode`](grant::authorization_code::AuthorizationCodeGrant)
  Provides the ability for a client to send the interactive user a URL at which to authenticate;
  a code from a successful authentication is returned to the client, which can exchange it in
  return for an access token.
- [`DeviceAuthorization`](grant::device_authorization::DeviceAuthorizationGrant)
  Enables a client to provide a code and/or URL to an interactive user, which they can use to
  log in from another machine. They complete the requirements of login, and the authorization
  server is notified that it can provide the corresponding access token to the client.
- [`TokenExchange`](grant::token_exchange::TokenExchangeGrant)
  Allows the client to exchange an existing token for a new security token, supporting
  impersonation and delegation use cases.
- [`JwtBearer`](grant::jwt_bearer::JwtBearerGrant)
  Allows a client to present a caller-supplied signed JWT assertion (RFC 7523) in exchange for
  an access token; the assertion vouches for the principal the token is issued for.

Further grants — CIBA, provider-specific flows — can be implemented in this
crate or by external crates.

Beyond grants, the [`registration`] module implements OAuth 2.0 Dynamic Client Registration
(RFC 7591), letting a client register itself with an authorization server and obtain the
`client_id`/`client_secret` that drive the grants above.

## Examples

### Client Credentials Grant

```rust
# use huskarl::prelude::*;
# use huskarl::core::http::HttpClient;
# use huskarl::core::secrets::{EnvVarSecret, encodings::StringEncoding};
# use huskarl::core::server_metadata::AuthorizationServerMetadata;
# use huskarl::grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters};
# use huskarl::core::client_auth::ClientSecret;
#
# async fn example(http_client: impl HttpClient + 'static) {
# let issuer = "https://issuer";
# let client_id = "client_id";
# let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding).unwrap();
#
let metadata = AuthorizationServerMetadata::fetch()
    .http_client(&http_client)
    .issuer(issuer)
    .call()
    .await
    .unwrap();

let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
    .client_id(client_id)
    .http_client(http_client)
    .client_auth(ClientSecret::new(client_secret))
    .build();

let token_response = grant
    .exchange(
        ClientCredentialsGrantParameters::builder()
            .scopes(vec!["test"])
            .build(),
    )
    .await
    .unwrap();

println!(
    "Access token: {}",
    token_response.access_token().token().expose_secret()
);
# }
```

## Guides and explanation

The API items in this crate are the **reference** documentation. For
task-oriented how-to guides — setting up each grant, caching tokens, and
making authenticated requests — and design explanation (error handling,
sharing a refresh token store, refresh timing), see the [`_docs`] module.

Most applications wrap a grant in an
[`InMemoryTokenCache`](cache::InMemoryTokenCache) and an
[`HttpAuthorizer`](authorizer::HttpAuthorizer) for the request path; every
operation returns the one concrete [`Error`](core::Error) type, which embeds
in your own error enum. See [caching tokens and wiring an
authorizer](_docs::guide::caching) and [error
handling](_docs::explanation::error_handling).
*/

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
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
