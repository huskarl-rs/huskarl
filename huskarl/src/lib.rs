/*!
Huskarl provides tools for implementing secure `OAuth2` clients in rust.

This library provides a number of grant implementations, each of which is configured
with a set of parameters that define how the grant/workflow should progress.

The library also provides a caching layer for token responses; and a HTTP authorizer
that can be used to make authenticated requests to resource servers.

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

Further grants exist, could either be implemented for this library either in-crate, or can be
implemented by external crates. Examples include CIBA, JWT authorization, or provider-specific grants.

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

### Application state and error handling

Grants belong to the login path. For the request path, wrap a grant in a
token cache and an [`HttpAuthorizer`](authorizer::HttpAuthorizer) — workflow
types carry no type parameters, so they store directly in your application
state, and every operation returns the one concrete
[`Error`](core::Error) type, which embeds in your own error enum (hand-rolled
as below, or with `thiserror`'s `#[from]`). The
[`ReauthRequired`](core::ErrorKind::ReauthRequired) kind is the stable signal
that the interactive flow must run again.

```rust
# use huskarl::core::client_auth::NoAuth;
# use huskarl::core::http::HttpClient;
# use huskarl::grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters};
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{InMemoryRefreshTokenStore, InMemoryTokenCache},
    core::ErrorKind,
};

/// Plain types, no parameters: this struct names cleanly in app state.
struct App {
    authorizer: HttpAuthorizer,
}

enum AppError {
    /// The user must log in again.
    LoginRequired,
    /// Any other authorization failure.
    Auth(huskarl::core::Error),
}

impl From<huskarl::core::Error> for AppError {
    fn from(err: huskarl::core::Error) -> Self {
        if err.kind() == ErrorKind::ReauthRequired {
            AppError::LoginRequired
        } else {
            AppError::Auth(err)
        }
    }
}

# async fn example(http_client: impl HttpClient + 'static) -> Result<(), AppError> {
# let grant = ClientCredentialsGrant::builder()
#     .client_id("client-id")
#     .client_auth(NoAuth)
#     .token_endpoint("https://as.example.com/token")?
#     .http_client(http_client)
#     .build();
// `grant` is any grant, built as in the example above.
let cache = InMemoryTokenCache::builder()
    .grant(grant)
    .grant_parameters(ClientCredentialsGrantParameters::builder().build())
    .refresh_store(InMemoryRefreshTokenStore::default())
    .build();

let app = App {
    authorizer: HttpAuthorizer::builder().cache(cache).build(),
};

// Exchanges or refreshes as needed through the grant's own HTTP client;
// `?` lands in the app's error enum, with re-login distinguished.
let headers = app
    .authorizer
    .get_headers(&http::Method::GET, &"https://api.example.com/v1".parse().unwrap())
    .await?;
# drop(headers);
# Ok(())
# }
```

To survive restarts, persist only the refresh token by handing the cache a
custom [`RefreshTokenStore`](cache::RefreshTokenStore) (keychain- or
disk-backed); on startup the cache refreshes into a fresh access token. For
handing a freshly-obtained token from the login path to a running cache, use
[`prime`](cache::TokenCache::prime).
*/

#![forbid(unsafe_code)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod serde_utils;

pub mod authorizer;
pub mod cache;
pub mod grant;
pub mod prelude;
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
