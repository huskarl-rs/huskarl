# Client credentials grant

[`ClientCredentialsGrant`](crate::grant::client_credentials::ClientCredentialsGrant)
(RFC 6749 §4.4) is used when the client is acting on its own behalf, not on
behalf of a user.

## 1. Set up your HTTP client and client authentication

See [Setting up an HTTP client and client
authentication](crate::_docs::guide::setup) for the shared setup the rest of
this page assumes. Client credentials **requires** authentication: the client
acts on its own behalf, so its credentials *are* the grant. The examples below
use a `ClientSecret`.

## 2a. Set up the grant with authorization server metadata

```rust
use huskarl::{
    core::{client_auth::ClientSecret, server_metadata::AuthorizationServerMetadata},
    grant::client_credentials::ClientCredentialsGrant,
};
# use huskarl::core::http::HttpClient;
# use huskarl::core::secrets::EnvVarSecret;
# use huskarl::core::secrets::encodings::StringEncoding;
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder()
#     .build()
#     .await?;
#
# let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
# let client_auth: ClientSecret = ClientSecret::new(env_secret);

let metadata = AuthorizationServerMetadata::fetch()
    .http_client(&client)
    .issuer("https://my-issuer")
    .call()
    .await?;

let grant: ClientCredentialsGrant = ClientCredentialsGrant::builder_from_metadata(&metadata)
    .client_id("client_id")
    .http_client(client)
    .client_auth(client_auth)
    .build();
# Ok(())
# }
```

## 2b. Alternative: Set up the grant without metadata

```rust
use huskarl::{
    core::client_auth::ClientSecret, grant::client_credentials::ClientCredentialsGrant,
};
# use huskarl::core::http::HttpClient;
# use huskarl::core::secrets::EnvVarSecret;
# use huskarl::core::secrets::encodings::StringEncoding;
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder()
#     .build()
#     .await?;
#
# let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
# let client_auth: ClientSecret = ClientSecret::new(env_secret);

let grant: ClientCredentialsGrant = ClientCredentialsGrant::builder()
    .token_endpoint("https://my-server/token".parse()?)
    .client_id("client_id")
    .http_client(client)
    .client_auth(client_auth)
    .build();
# Ok(())
# }
```

## 3. Get an access token

```rust
use huskarl::prelude::*; // Imports OAuth2ExchangeGrant which defines the exchange call.
use huskarl::grant::client_credentials::ClientCredentialsGrantParameters;
use huskarl::token::AccessToken;
# use huskarl::grant::client_credentials::ClientCredentialsGrant;
use huskarl::core::client_auth::ClientSecret;
# use huskarl::core::http::HttpClient;
# use huskarl::core::secrets::EnvVarSecret;
# use huskarl::core::secrets::encodings::StringEncoding;
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder()
#     .build()
#     .await?;
#
# let client_auth: ClientSecret = ClientSecret::new(EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?);
#
# let grant: ClientCredentialsGrant = ClientCredentialsGrant::builder()
#     .token_endpoint("https://my-server/token".parse()?)
#     .client_id("client_id")
#     .http_client(client)
#     .client_auth(client_auth)
#     .build();

let params = ClientCredentialsGrantParameters::builder().scopes(vec!["read", "write"]).build();
let response = grant.exchange(params).await?;
let token: &AccessToken = response.access_token();

# Ok(())
# }
```
