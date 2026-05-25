//! Refresh token grant (RFC 6749 §6).
//!
//! Used to obtain a new access token using a previously issued refresh token,
//! without requiring the user to re-authenticate.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! A HTTP client needs to be configured. Using the `huskarl_reqwest` crate:
//!
//! ```rust
//! use huskarl_reqwest::{ReqwestClient, mtls::NoMtls};
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().mtls(NoMtls).build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 2. Set up client authentication (if not using `to_refresh_grant`).
//!
//! When constructing a refresh grant directly (steps 3b/3c), client authentication
//! must be provided. Any `ClientAuthentication` implementation can be used.
//! See the client credentials grant for an example using `ClientSecret`.
//!
//! ## 3a. Create a refresh grant from an existing grant (most common)
//!
//! The most common way to create a refresh grant is from another grant that has
//! already been configured. This inherits the same client authentication and `DPoP`
//! settings without needing to repeat them.
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::NoAuth, dpop::NoDPoP},
//!     grant::{client_credentials::ClientCredentialsGrant, refresh::RefreshGrant},
//!     prelude::*,
//! };
//! # fn example(grant: &ClientCredentialsGrant<NoAuth, NoDPoP>) {
//! let refresh_grant: RefreshGrant<NoAuth, NoDPoP> = grant.to_refresh_grant();
//! # }
//! ```
//!
//! ## 3b. Set up the grant directly with authorization server metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{
//!         client_auth::ClientSecret,
//!         dpop::NoDPoP,
//!         secrets::{EnvVarSecret, encodings::StringEncoding},
//!         server_metadata::AuthorizationServerMetadata,
//!     },
//!     grant::refresh::RefreshGrant,
//! };
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .mtls(NoMtls)
//! #     .build()
//! #     .await?;
//! #
//! # let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let client_auth: ClientSecret<EnvVarSecret> = ClientSecret::new(env_secret);
//!
//! let metadata = AuthorizationServerMetadata::fetch()
//!     .http_client(&client)
//!     .issuer("https://my-issuer")
//!     .call()
//!     .await?;
//!
//! let refresh_grant: RefreshGrant<ClientSecret<EnvVarSecret>, NoDPoP> =
//!     RefreshGrant::builder_from_metadata(&metadata)
//!         .client_id("client_id")
//!         .client_auth(client_auth)
//!         .dpop(NoDPoP)
//!         .build();
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
//!         dpop::NoDPoP,
//!         secrets::{EnvVarSecret, encodings::StringEncoding},
//!     },
//!     grant::refresh::RefreshGrant,
//! };
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! #
//! # let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let client_auth: ClientSecret<EnvVarSecret> = ClientSecret::new(env_secret);
//!
//! let refresh_grant: RefreshGrant<ClientSecret<EnvVarSecret>, NoDPoP> = RefreshGrant::builder()
//!     .token_endpoint("https://my-server/token")?
//!     .client_id("client_id")
//!     .client_auth(client_auth)
//!     .dpop(NoDPoP)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Exchange the refresh token for a new access token
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::NoAuth, dpop::NoDPoP},
//!     grant::refresh::{RefreshGrant, RefreshGrantParameters},
//!     prelude::*,
//!     token::{AccessToken, RefreshToken},
//! };
//! # async fn exchange(
//! #     client: &huskarl_reqwest::ReqwestClient,
//! #     refresh_grant: &RefreshGrant<NoAuth, NoDPoP>,
//! #     refresh_token: RefreshToken,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//!
//! let params = RefreshGrantParameters::refresh_token(refresh_token);
//! let response = refresh_grant.exchange(client, params).await?;
//! let token: &AccessToken = response.access_token();
//! # Ok(())
//! # }
//! ```

use bon::Builder;
use serde::Serialize;

use crate::{
    core::server_metadata::AuthorizationServerMetadata,
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
#[huskarl_macros::grant]
#[derive(Debug, Clone, Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct RefreshGrant {}

impl<
    Auth: crate::core::client_auth::ClientAuthentication + 'static,
    D: crate::core::dpop::AuthorizationServerDPoP + 'static,
> RefreshGrant<Auth, D>
{
    /// Configure the grant from authorization server metadata.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> RefreshGrantBuilder<Auth, D, SetCommonMetadata> {
        RefreshGrant::builder().with_common_metadata(metadata)
    }
}

#[huskarl_macros::grant_impl]
impl<
    Auth: crate::core::client_auth::ClientAuthentication + 'static,
    D: crate::core::dpop::AuthorizationServerDPoP + 'static,
> OAuth2ExchangeGrant for RefreshGrant<Auth, D>
{
    type Parameters = RefreshGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = RefreshGrantForm;

    fn to_refresh_grant(&self) -> RefreshGrant<Auth, D> {
        self.clone()
    }

    fn bound_dpop_jkt(params: &Self::Parameters) -> Option<&str> {
        params.refresh_token.dpop_jkt()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        RefreshGrantForm {
            grant_type: "refresh_token",
            refresh_token: params.refresh_token,
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
    refresh_token: RefreshToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<Vec<String>>,
}
