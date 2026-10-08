# Refresh token grant

[`RefreshGrant`](crate::grant::refresh::RefreshGrant) (RFC 6749 §6) is used to
obtain a new access token using a previously issued refresh token, without
requiring the user to re-authenticate.

## 1. Set up your HTTP client and client authentication

See [Setting up an HTTP client and client
authentication](crate::_docs::guide::setup) for the shared setup the rest of
this page assumes. When constructing a refresh grant directly (steps 2b/2c),
provide client authentication. A grant built via `to_refresh_grant` inherits it
from the parent grant.

## 2a. Create a refresh grant from an existing grant (most common)

The most common way to create a refresh grant is from another grant that has
already been configured. This inherits the same client authentication, `DPoP`,
and HTTP client settings without needing to repeat them.

```rust
use huskarl::{
    grant::{client_credentials::ClientCredentialsGrant, refresh::RefreshGrant},
    prelude::*,
};
# fn example(grant: &ClientCredentialsGrant) {
let refresh_grant: RefreshGrant = grant.to_refresh_grant();
# }
```

## 2b. Set up the grant directly with authorization server metadata

```rust
use huskarl::{
    core::{
        client_auth::ClientSecret,
        secrets::{EnvVarSecret, encodings::StringEncoding},
        server_metadata::AuthorizationServerMetadata,
    },
    grant::refresh::RefreshGrant,
};
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

let refresh_grant: RefreshGrant = RefreshGrant::builder_from_metadata(&metadata)
    .client_id("client_id")
    .http_client(client)
    .client_auth(client_auth)
    .build();
# Ok(())
# }
```

## 2c. Alternative: Set up the grant without metadata

```rust
use huskarl::{
    core::{
        client_auth::ClientSecret,
        secrets::{EnvVarSecret, encodings::StringEncoding},
    },
    grant::refresh::RefreshGrant,
};
# async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
# let client = huskarl_reqwest::ReqwestClient::builder()
#     .build()
#     .await?;
#
# let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
# let client_auth: ClientSecret = ClientSecret::new(env_secret);

let refresh_grant: RefreshGrant = RefreshGrant::builder()
    .token_endpoint("https://my-server/token".parse()?)
    .client_id("client_id")
    .http_client(client)
    .client_auth(client_auth)
    .build();
# Ok(())
# }
```

## 3. Exchange the refresh token for a new access token

```rust
use huskarl::{
    grant::refresh::{RefreshGrant, RefreshGrantParameters},
    prelude::*,
    token::{AccessToken, RefreshToken},
};
# async fn exchange(
#     refresh_grant: &RefreshGrant,
#     refresh_token: RefreshToken,
# ) -> Result<(), Box<dyn std::error::Error>> {

let params = RefreshGrantParameters::refresh_token(refresh_token);
let response = refresh_grant.exchange(params).await?;
let token: &AccessToken = response.access_token();
# Ok(())
# }
```

## Refresh tokens when using DPoP

Retain the returned [`RefreshToken`](crate::token::RefreshToken). If saving it,
serialize and deserialize the complete object: this preserves the secret,
key thumbprint, and OIDC request flag. `RefreshToken::new` does not restore
that flag. Pending authorization state is no longer needed.

For a public client using DPoP, keep the signing key available for as long as
you use the refresh token, even if the server returned a bearer access token.
If you rotate signing keys, keep the old key available to the signer. When the
stored refresh token contains a key thumbprint, the request fails before it is
sent if that key is unavailable.

For refresh tokens saved by older versions after a bearer response, no key
thumbprint was recorded. With DPoP configured, the refresh grant uses the
signer's current key. If it differs from the original key, the server may
reject the request with `invalid_grant`. Keep the original key as the current
key when using these tokens, or obtain a new refresh token through the
original grant flow.

For a confidential client, retain the original [client authentication
configuration](crate::_docs::guide::client_authentication). If you also use
DPoP and the refresh token has no stored binding, configure the signer with
the current key. A stored binding always requires its original key, including
for confidential clients. See the explanation below for legacy saved bindings.

For [OIDC key binding](crate::_docs::explanation::dpop_bindings#id-token-key-binding),
both client types must retain the original private key, even if the OP ignored
`bound_key` or issued bearer access tokens. Rotated refresh tokens preserve
the binding.

Refresh responses contain unvalidated ID tokens. When using `IdTokenValidator`,
set `.openid_bound_key_requested(...)` from the refresh token used in the request
to allow bound ID-token types. It does not check `cnf` or proof of possession.

See [DPoP bindings and client authentication](crate::_docs::explanation::dpop_bindings)
for how access-token and refresh-token bindings differ.
