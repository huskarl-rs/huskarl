# Token exchange grant

[`TokenExchangeGrant`](crate::grant::token_exchange::TokenExchangeGrant)
(RFC 8693) is used to issue a new security token by exchanging an existing
token, supporting impersonation and delegation without requiring user
re-authentication.

## 1. Set up your HTTP client and client authentication

See [Setting up an HTTP client and client
authentication](crate::_docs::guide::setup) for the shared setup the rest of
this page assumes. The grant presents an existing token as its authorization,
so authenticating the client is optional and independent — do it only if your
authorization server requires it, otherwise present none at all.

## 2a. Set up the grant with authorization server metadata

```rust
use huskarl::{
    core::{client_auth::ClientSecret, server_metadata::AuthorizationServerMetadata},
    grant::token_exchange::TokenExchangeGrant,
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

let grant: TokenExchangeGrant = TokenExchangeGrant::builder_from_metadata(&metadata)
    .client_id("client_id")
    .http_client(client)
    .client_auth(client_auth)
    .build();
# Ok(())
# }
```

## 2b. Alternative: Set up the grant without metadata

```rust
use huskarl::{core::client_auth::ClientSecret, grant::token_exchange::TokenExchangeGrant};
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

let grant: TokenExchangeGrant = TokenExchangeGrant::builder()
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
use huskarl::grant::token_exchange::{SecurityToken, SecurityTokenType, TokenExchangeGrantParameters};
use huskarl::token::AccessToken;
# use huskarl::grant::token_exchange::TokenExchangeGrant;
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
# let grant: TokenExchangeGrant = TokenExchangeGrant::builder()
#     .token_endpoint("https://my-server/token".parse()?)
#     .client_id("client_id")
#     .http_client(client)
#     .client_auth(client_auth)
#     .build();

let subject = SecurityToken::builder().token("eyToken").token_type(SecurityTokenType::AccessToken).build();
let params = TokenExchangeGrantParameters::builder().subject(subject).build();
let response = grant.exchange(params).await?;
let token: &AccessToken = response.access_token();

# Ok(())
# }
```
