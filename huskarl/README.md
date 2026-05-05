<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo reedme

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

- [`ClientCredentials`](https://docs.rs/huskarl/0.5.1/huskarl/grant/client_credentials/struct.ClientCredentialsGrant.html)
  Allows a client to exchange its own credentials in return for an access token.
- [`Refresh`](https://docs.rs/huskarl/0.5.1/huskarl/grant/refresh/struct.RefreshGrant.html)
  Allows a client which previously received a refresh token alongside an access token, to exchange
  it in return for an access token.
- [`AuthorizationCode`](https://docs.rs/huskarl/0.5.1/huskarl/grant/authorization_code/grant/struct.AuthorizationCodeGrant.html)
  Provides the ability for a client to send the interactive user a URL at which to authenticate;
  a code from a successful authentication is returned to the client, which can exchange it in
  return for an access token.
- [`DeviceAuthorization`](https://docs.rs/huskarl/0.5.1/huskarl/grant/device_authorization/grant/struct.DeviceAuthorizationGrant.html)
  Enables a client to provide a code and/or URL to an interactive user, which they can use to
  log in from another machine. They complete the requirements of login, and the authorization
  server is notified that it can provide the corresponding access token to the client.
- [`TokenExchange`](https://docs.rs/huskarl/0.5.1/huskarl/grant/token_exchange/struct.TokenExchangeGrant.html)
  Allows the client to exchange an existing token for a new security token, supporting
  impersonation and delegation use cases.

Further grants exist, could either be implemented for this library either in-crate, or can be
implemented by external crates. Examples include CIBA, JWT authorization, or provider-specific grants.

## Examples

### Client Credentials Grant

```rust
let metadata = AuthorizationServerMetadata::builder()
    .http_client(&http_client)
    .issuer(issuer)
    .build()
    .await
    .unwrap();

let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
    .client_id(client_id)
    .client_auth(ClientSecret::new(client_secret))
    .dpop(NoDPoP)
    .build();

let token_response = grant
    .exchange(
        &http_client,
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

<!-- cargo-reedme: end -->
