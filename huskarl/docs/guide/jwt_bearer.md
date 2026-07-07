# JWT bearer grant

[`JwtBearerGrant`](crate::grant::jwt_bearer::JwtBearerGrant) (RFC 7523 §2.1) is
used to request an access token by presenting a JWT *assertion* that an
authority the authorization server trusts has signed. The assertion identifies
the principal the token is for; the client does not act on its own behalf (for
that, see [`client_credentials`](crate::grant::client_credentials)).

This grant carries a **caller-supplied, already-signed** assertion. The library
does not mint the assertion — see [Creating the assertion
JWT](#creating-the-assertion-jwt) below for how to build and sign one.

Note that the assertion (the *grant*) is independent of client authentication.
A client may still authenticate to the token endpoint separately — for example
with [`JwtBearer`](crate::core::client_auth::JwtBearer) (`private_key_jwt`) — in
addition to presenting a user assertion as the grant.

## 1. Set up your HTTP client and client authentication

See [Setting up an HTTP client and client
authentication](crate::_docs::guide::setup) for the shared setup the rest of
this page assumes. The assertion stands alone, so authenticating the client is
optional — do it only if your authorization server requires it.

## 2a. Set up the grant with authorization server metadata

```rust
use huskarl::{
    core::{client_auth::ClientSecret, server_metadata::AuthorizationServerMetadata},
    grant::jwt_bearer::JwtBearerGrant,
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

let grant: JwtBearerGrant = JwtBearerGrant::builder_from_metadata(&metadata)
    .client_id("client_id")
    .http_client(client)
    .client_auth(client_auth)
    .build();
# Ok(())
# }
```

## 2b. Alternative: Set up the grant without metadata

```rust
use huskarl::{core::client_auth::ClientSecret, grant::jwt_bearer::JwtBearerGrant};
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

let grant: JwtBearerGrant = JwtBearerGrant::builder()
    .token_endpoint("https://my-server/token".parse()?)
    .client_id("client_id")
    .http_client(client)
    .client_auth(client_auth)
    .build();
# Ok(())
# }
```

## 3. Get an access token

The `assertion` is the signed JWT from [Creating the assertion
JWT](#creating-the-assertion-jwt).

```rust
use huskarl::prelude::*; // Imports OAuth2ExchangeGrant which defines the exchange call.
use huskarl::grant::jwt_bearer::JwtBearerGrantParameters;
use huskarl::token::AccessToken;
# use huskarl::grant::jwt_bearer::JwtBearerGrant;
use huskarl::core::client_auth::ClientSecret;
# use huskarl::core::http::HttpClient;
# use huskarl::core::secrets::EnvVarSecret;
# use huskarl::core::secrets::encodings::StringEncoding;
# async fn run(assertion: String) -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder()
#     .build()
#     .await?;
#
# let client_auth: ClientSecret = ClientSecret::new(EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?);
#
# let grant: JwtBearerGrant = JwtBearerGrant::builder()
#     .token_endpoint("https://my-server/token".parse()?)
#     .client_id("client_id")
#     .http_client(client)
#     .client_auth(client_auth)
#     .build();

let params = JwtBearerGrantParameters::builder()
    .assertion(assertion)
    .scope(bon::vec!["read", "write"])
    .build();
let response = grant.exchange(params).await?;
let token: &AccessToken = response.access_token();

# Ok(())
# }
```

## Creating the assertion JWT

RFC 7523 §3 requires the assertion to be a JWT signed by an issuer the
authorization server trusts. The claims identify the trusted issuer of the
assertion (`iss`), the principal the token is for (`sub`), and the
authorization server as the audience (`aud`); `exp` and `iat` bound its
lifetime. Build and sign one with [`Jwt`](crate::core::jwt::Jwt) and a signer
selected from any
[`JwsSignerSelector`](crate::core::crypto::signer::JwsSignerSelector) (here, a
freshly generated key — in practice load a long-lived key the server trusts):

The [`SecretString`](crate::core::secrets::SecretString) returned by
`to_jws_compact` can be passed straight to
[`JwtBearerGrantParameters::builder().assertion(..)`](crate::grant::jwt_bearer::JwtBearerGrantParameters)
— the setter accepts any `Into<SecretString>` (`&str`, `String`, or
`SecretString`).

```rust
use std::time::Duration;

use huskarl::core::{crypto::signer::JwsSignerSelector as _, jwt::Jwt, secrets::SecretString};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

# async fn make_assertion() -> Result<SecretString, Box<dyn std::error::Error>> {
let key = PrivateKey::generate(GenerateAlgorithm::Es256, None)?;

let jwt = Jwt::builder()
    .iss("https://issuer.example.com") // who vouches for the assertion
    .sub("user@example.com") // the principal the token is for
    .audience("https://my-issuer") // the authorization server (aud)
    .issued_now_expires_after(Duration::from_secs(300))
    .claims(())
    .build();

let assertion = jwt.to_jws_compact(&*key.select_signer().await).await?;
Ok(assertion)
# }
```
