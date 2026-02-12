/*!
Huskarl provides tools for implementing secure `OAuth2` clients in rust.

This library provides a number of grant implementations, each of which is configured
with a set of parameters that define how the grant/workflow should progress.

The library also provides a caching layer for token responses; and a HTTP authorizer
that can be used to make authenticated requests to resource servers.

## Examples

### Client Credentials Grant

```
# use huskarl::prelude::*;
# use huskarl::core::secrets::{EnvVarSecret, encodings::StringEncoding};
# use huskarl::core::server_metadata::AuthorizationServerMetadata;
# use huskarl::grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters};
# use huskarl::core::client_auth::ClientSecret;
# use huskarl::core::dpop::NoDPoP;
# use huskarl_reqwest::ReqwestClient;
# use huskarl_reqwest::mtls::NoMtls;
#
# async fn test() {
# let issuer = "https://issuer";
# let client_id = "client_id";
# let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding).unwrap();
# let http_client = ReqwestClient::builder().mtls(NoMtls).build().await.unwrap();
#
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
    token_response.access_token.expose_token()
);
# }
```
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
