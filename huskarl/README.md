<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Huskarl provides tools for implementing secure `OAuth2` clients in rust.

This library provides a number of grant implementations, each of which is configured
with a set of parameters that define how the grant/workflow should progress.

The library also provides a caching layer for token responses; and a HTTP authorizer
that can be used to make authenticated requests to resource servers.

## Setup

1. Create a HTTP client instance (e.g. with `huskarl-reqwest`).
2. Get authorization server metadata (or OIDC discovery data) when appropriate (but not necessary).
3. Set up your client’s authentication.
4. Create the grant, filling in its fields, and supplying the client authentication.

Once you have a grant, how exactly to use it depends on the grant. The simplest grants only
require the `exchange` call, which exchanges grant-specific parameters for a token at the token
endpoint.

Other grants act like workflows, with a set of steps required, which will also involve one
or more calls to the token endpoint.

## Grants provided in this crate:

- [`ClientCredentials`](https://docs.rs/huskarl/latest/huskarl/grant/client_credentials/struct.ClientCredentialsGrant.html)
  Allows a client to exchange its own credentials in return for an access token.
- [`Refresh`](https://docs.rs/huskarl/latest/huskarl/grant/refresh/struct.RefreshGrant.html)
  Allows a client which previously received a refresh token alongside an access token, to exchange
  it in return for an access token.
- [`AuthorizationCode`](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/grant/struct.AuthorizationCodeGrant.html)
  Provides the ability for a client to send the interactive user a URL at which to authenticate;
  a code from a successful authentication is returned to the client, which can exchange it in
  return for an access token.
- [`DeviceAuthorization`](https://docs.rs/huskarl/latest/huskarl/grant/device_authorization/grant/struct.DeviceAuthorizationGrant.html)
  Enables a client to provide a code and/or URL to an interactive user, which they can use to
  log in from another machine. They complete the requirements of login, and the authorization
  server is notified that it can provide the corresponding access token to the client.
- [`TokenExchange`](https://docs.rs/huskarl/latest/huskarl/grant/token_exchange/struct.TokenExchangeGrant.html)
  Allows the client to exchange an existing token for a new security token, supporting
  impersonation and delegation use cases.

Further grants exist, could either be implemented for this library either in-crate, or can be
implemented by external crates. Examples include CIBA, JWT authorization, or provider-specific grants.

## Examples

### Client Credentials Grant

```rust
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
```

### Application state and error handling

Grants belong to the login path. For the request path, wrap a grant in a
token cache and an [`HttpAuthorizer`](https://docs.rs/huskarl/latest/huskarl/authorizer/struct.HttpAuthorizer.html) — workflow
types carry no type parameters, so they store directly in your application
state, and every operation returns the one concrete
[`Error`](https://docs.rs/huskarl_core/latest/huskarl_core/error/struct.Error.html) type, which embeds in your own error enum (hand-rolled
as below, or with `thiserror`’s `#[from]`).

Errors carry three stable signals, checked in this order:
[`is_retryable`](https://docs.rs/huskarl/latest/huskarl/core/struct.Error.html#method.is_retryable) means the failure is transient
and the same call may succeed later — back off and retry, do **not** re-run
the interactive flow; [`ReauthRequired`](https://docs.rs/huskarl/latest/huskarl/core/enum.ErrorKind.html#variant.ReauthRequired)
means no token can be obtained automatically and the interactive flow must
run again; everything else is a genuine failure to log and surface.

```rust
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
    /// Transient failure — retry the request later.
    RetryLater(huskarl::core::Error),
    /// The user must log in again.
    LoginRequired,
    /// Any other authorization failure.
    Auth(huskarl::core::Error),
}

impl From<huskarl::core::Error> for AppError {
    fn from(err: huskarl::core::Error) -> Self {
        if err.is_retryable() {
            AppError::RetryLater(err)
        } else if err.kind() == ErrorKind::ReauthRequired {
            AppError::LoginRequired
        } else {
            AppError::Auth(err)
        }
    }
}

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
let uri: http::Uri = "https://api.example.com/v1".parse().unwrap();
let headers = app
    .authorizer
    .get_headers(&http::Method::GET, &uri)
    .await?;

// Send the request with your HTTP client, then feed the response headers
// back so DPoP nonce rotation and rejected tokens are tracked — see the
// authorizer module docs for the full request loop.
app.authorizer.process_response(&uri, &response_headers);
```

To survive restarts, persist only the refresh token by handing the cache a
custom [`RefreshTokenStore`](https://docs.rs/huskarl/latest/huskarl/cache/trait.RefreshTokenStore.html) (keychain- or
disk-backed); on startup the cache refreshes into a fresh access token. For
handing a freshly-obtained token from the login path to a running cache, use
[`prime`](https://docs.rs/huskarl/latest/huskarl/cache/trait.TokenCache.html#tymethod.prime).

<!-- cargo-reedme: end -->
