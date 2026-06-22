//! Refresh token grant (RFC 6749 §6).
//!
//! Used to obtain a new access token using a previously issued refresh token,
//! without requiring the user to re-authenticate.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! The examples below use the `huskarl_reqwest` crate; see [Setting up an HTTP
//! client](crate::grant#setting-up-an-http-client) for the shared setup the rest
//! of this page assumes.
//!
//! ## 2. Set up client authentication (if not using `to_refresh_grant`)
//!
//! When constructing a refresh grant directly (steps 3b/3c), provide client
//! authentication — see [Setting up client
//! authentication](crate::grant#setting-up-client-authentication). A grant built
//! via `to_refresh_grant` inherits it from the parent grant.
//!
//! ## 3a. Create a refresh grant from an existing grant (most common)
//!
//! The most common way to create a refresh grant is from another grant that has
//! already been configured. This inherits the same client authentication, `DPoP`,
//! and HTTP client settings without needing to repeat them.
//!
//! ```rust
//! use huskarl::{
//!     grant::{client_credentials::ClientCredentialsGrant, refresh::RefreshGrant},
//!     prelude::*,
//! };
//! # fn example(grant: &ClientCredentialsGrant) {
//! let refresh_grant: RefreshGrant = grant.to_refresh_grant();
//! # }
//! ```
//!
//! ## 3b. Set up the grant directly with authorization server metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{
//!         client_auth::ClientSecret,
//!         secrets::{EnvVarSecret, encodings::StringEncoding},
//!         server_metadata::AuthorizationServerMetadata,
//!     },
//!     grant::refresh::RefreshGrant,
//! };
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let client_auth: ClientSecret = ClientSecret::new(env_secret);
//!
//! let metadata = AuthorizationServerMetadata::fetch()
//!     .http_client(&client)
//!     .issuer("https://my-issuer")
//!     .call()
//!     .await?;
//!
//! let refresh_grant: RefreshGrant = RefreshGrant::builder_from_metadata(&metadata)
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(client_auth)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 3c. Alternative: Set up the grant without metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{
//!         client_auth::ClientSecret,
//!         secrets::{EnvVarSecret, encodings::StringEncoding},
//!     },
//!     grant::refresh::RefreshGrant,
//! };
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let client_auth: ClientSecret = ClientSecret::new(env_secret);
//!
//! let refresh_grant: RefreshGrant = RefreshGrant::builder()
//!     .token_endpoint("https://my-server/token".parse()?)
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(client_auth)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Exchange the refresh token for a new access token
//!
//! ```rust
//! use huskarl::{
//!     grant::refresh::{RefreshGrant, RefreshGrantParameters},
//!     prelude::*,
//!     token::{AccessToken, RefreshToken},
//! };
//! # async fn exchange(
//! #     refresh_grant: &RefreshGrant,
//! #     refresh_token: RefreshToken,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//!
//! let params = RefreshGrantParameters::refresh_token(refresh_token);
//! let response = refresh_grant.exchange(params).await?;
//! let token: &AccessToken = response.access_token();
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use bon::Builder;
use serde::Serialize;

use crate::{
    core::{
        EndpointUrl,
        client_auth::ClientAuthentication,
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
        secrets::SecretString,
    },
    grant::core::{OAuth2ExchangeGrant, mk_scopes},
    token::RefreshToken,
};

/// An `OAuth2` refresh grant.
///
/// This grant is used to get a new access token, after receiving a
/// refresh token from a previous request to the token endpoint.
///
/// It allows potential extension of access to resource servers
/// after an access token expires, by asking the authorization server
/// for a new token. This offers the opportunity for the authorization
/// server to consider if continued access is appropriate.
///
/// See the [module documentation][crate::grant::refresh] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[derive(Clone, Builder)]
#[builder(on(String, into))]
pub struct RefreshGrant {
    /// The client ID. Omitted for a client that presents no identification
    /// (e.g. refreshing a token obtained by an anonymous grant).
    client_id: Option<String>,

    /// The HTTP client used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// The client authentication method. Omitted for a public client that does
    /// not authenticate to the token endpoint (RFC 6749 §6).
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Option<Arc<dyn ClientAuthentication>>,

    /// The `DPoP` signer. Defaults to [`NoDPoP`] (no token sender-constraining).
    #[builder(
        with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>,
        default = Arc::new(NoDPoP),
    )]
    dpop: Arc<dyn AuthorizationServerDPoP>,

    /// The issuer for tokens created by the authorization server.
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The URL of the token endpoint.
    #[from_metadata(path = "token_endpoint")]
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
    mtls_token_endpoint: Option<EndpointUrl>,

    /// The endpoint used for token requests: the mTLS alias when the HTTP
    /// client uses mTLS, the primary token endpoint otherwise.
    #[builder(skip = crate::grant::core::resolve_mtls_alias(http_client.as_ref(), &token_endpoint, mtls_token_endpoint.as_ref()))]
    effective_token_endpoint: EndpointUrl,

    /// Supported endpoint auth methods; used to auto-select basic or
    /// form auth for client secrets.
    #[from_metadata(path = "token_endpoint_auth_methods_supported")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl core::fmt::Debug for RefreshGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RefreshGrant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("mtls_token_endpoint", &self.mtls_token_endpoint)
            .finish_non_exhaustive()
    }
}

impl OAuth2ExchangeGrant for RefreshGrant {
    type Parameters = RefreshGrantParameters;
    type Form<'a> = RefreshGrantForm;

    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> Option<&dyn ClientAuthentication> {
        self.client_auth.as_deref()
    }

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn effective_token_endpoint(&self) -> &EndpointUrl {
        &self.effective_token_endpoint
    }

    fn dpop(&self) -> &dyn AuthorizationServerDPoP {
        self.dpop.as_ref()
    }

    fn http_client(&self) -> &dyn HttpClient {
        self.http_client.as_ref()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn to_refresh_grant(&self) -> RefreshGrant {
        self.clone()
    }

    fn bound_dpop_jkt(params: &Self::Parameters) -> Option<&str> {
        params.refresh_token.dpop_jkt()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        RefreshGrantForm {
            grant_type: "refresh_token",
            refresh_token: params.refresh_token.token().clone(),
            scope: params.scope,
            resource: params.resource,
        }
    }
}

/// Parameters when requesting a token using the refresh grant.
#[derive(Debug, Clone, Builder)]
pub struct RefreshGrantParameters {
    /// The refresh token to use in the refresh token request.
    refresh_token: RefreshToken,
    /// Scopes for downscoping (must be previously granted scopes).
    #[builder(required, default, name = "scopes", with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    scope: Option<String>,
    /// The target resource(s) for the access token.
    resource: Option<Vec<String>>,
}

impl RefreshGrantParameters {
    /// Implements a simple set of parameters to the grant including just the refresh token.
    ///
    /// This is enough for most use cases; the builder exists as an extensible
    /// API where arbitrary extra fields may be added in future.
    #[must_use]
    pub fn refresh_token(token: RefreshToken) -> Self {
        Self::builder().refresh_token(token).build()
    }
}

/// Refresh grant body.
#[derive(Debug, Serialize)]
pub struct RefreshGrantForm {
    grant_type: &'static str,
    refresh_token: SecretString,
    scope: Option<String>,
    resource: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_form_serializes_token_as_plain_string() {
        let form = RefreshGrantForm {
            grant_type: "refresh_token",
            refresh_token: SecretString::new("my-refresh-token"),
            scope: None,
            resource: None,
        };
        let encoded = crate::core::oauth_form::to_string(&form).unwrap();
        assert_eq!(
            encoded,
            "grant_type=refresh_token&refresh_token=my-refresh-token"
        );
    }

    #[test]
    fn refresh_form_resource_serializes_as_repeated_keys() {
        let form = RefreshGrantForm {
            grant_type: "refresh_token",
            refresh_token: SecretString::new("tok"),
            scope: None,
            resource: Some(vec![
                "https://api.example.com".to_string(),
                "https://other.example.com".to_string(),
            ]),
        };
        let encoded = crate::core::oauth_form::to_string(&form).unwrap();
        assert!(
            encoded.contains("resource=https%3A%2F%2Fapi.example.com"),
            "first resource not found in: {encoded}"
        );
        assert!(
            encoded.contains("resource=https%3A%2F%2Fother.example.com"),
            "second resource not found in: {encoded}"
        );
        assert!(
            !encoded.contains(','),
            "resource values should not be comma-joined: {encoded}"
        );
    }
}
