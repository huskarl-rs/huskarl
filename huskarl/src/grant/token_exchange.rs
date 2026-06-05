//! Token exchange grant (RFC 8693).
//!
//! Used to issue a new security token by exchanging an existing token, supporting
//! impersonation and delegation without requiring user re-authentication.
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
//! ## 2. Set up client authentication (if necessary).
//!
//! This example shows the use of a client secret as credentials, but any `ClientAuthentication`
//! implementation can be used.
//!
//! ```rust
//! use huskarl::core::{
//!     client_auth::ClientSecret,
//!     secrets::{EnvVarSecret, encodings::StringEncoding},
//! };
//!
//! # async fn setup_client_auth() -> Result<(), Box<dyn std::error::Error>> {
//! let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! let client_auth: ClientSecret<EnvVarSecret> = ClientSecret::new(env_secret);
//! # Ok(())
//! # }
//! ```
//!
//! ## 3a. Set up the grant with authorization server metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{
//!         client_auth::ClientSecret, dpop::NoDPoP, server_metadata::AuthorizationServerMetadata,
//!     },
//!     grant::token_exchange::TokenExchangeGrant,
//! };
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
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
//! let grant: TokenExchangeGrant<ClientSecret<EnvVarSecret>> =
//!     TokenExchangeGrant::builder_from_metadata(&metadata)
//!         .client_id("client_id")
//!         .client_auth(client_auth)
//!         .dpop(NoDPoP)
//!         .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 3b. Alternative: Set up the grant without metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::ClientSecret, dpop::NoDPoP},
//!     grant::token_exchange::TokenExchangeGrant,
//! };
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
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
//! let grant: TokenExchangeGrant<ClientSecret<EnvVarSecret>> = TokenExchangeGrant::builder()
//!     .token_endpoint("https://my-server/token")?
//!     .client_id("client_id")
//!     .client_auth(client_auth)
//!     .dpop(NoDPoP)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Get an access token.
//!
//! ```rust
//! use huskarl::prelude::*; // Imports OAuth2ExchangeGrant which defines the exchange call.
//! use huskarl::grant::token_exchange::{SecurityToken, SecurityTokenType, TokenExchangeGrantParameters};
//! use huskarl::token::AccessToken;
//! # use huskarl::grant::token_exchange::TokenExchangeGrant;
//! use huskarl::core::client_auth::ClientSecret;
//! # use huskarl::core::dpop::NoDPoP;
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .mtls(NoMtls)
//! #     .build()
//! #     .await?;
//! #
//! # let client_auth: ClientSecret<EnvVarSecret> = ClientSecret::new(EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?);
//! #
//! # let grant: TokenExchangeGrant<ClientSecret<EnvVarSecret>> = TokenExchangeGrant::builder()
//! #     .token_endpoint("https://my-server/token")?
//! #     .client_id("client_id")
//! #     .client_auth(client_auth)
//! #     .dpop(NoDPoP)
//! #     .build();
//!
//! let subject = SecurityToken::builder().token("eyToken").token_type(SecurityTokenType::AccessToken).build();
//! let params = TokenExchangeGrantParameters::builder().subject(subject).build();
//! let response = grant.exchange(&client, params).await?;
//! let token: &AccessToken = response.access_token();
//!
//! # Ok(())
//! # }
//! ```

use bon::Builder;
use serde::Serialize;

use crate::{
    core::{
        EndpointUrl,
        client_auth::ClientAuthentication,
        dpop::{AuthorizationServerDPoP, NoDPoP},
    },
    grant::{
        core::{OAuth2ExchangeGrant, mk_scopes},
        refresh::RefreshGrant,
    },
};

/// An `OAuth2` token exchange grant.
///
/// This grant is used to issue a new security token by exchanging an existing
/// token, without requiring user re-authentication. It supports impersonation
/// and delegation use cases by allowing the exchange of one token type for another.
///
/// See the [module documentation][crate::grant::token_exchange] for a usage guide.
#[huskarl_macros::from_metadata(metadata = crate::core::server_metadata::AuthorizationServerMetadata)]
#[huskarl_macros::try_builder]
#[derive(Debug, Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct TokenExchangeGrant<Auth: ClientAuthentication, D: AuthorizationServerDPoP = NoDPoP> {
    /// The client ID.
    client_id: String,

    /// The client authentication method.
    client_auth: Auth,

    /// The `DPoP` signer.
    dpop: D,

    /// The issuer for tokens created by the authorization server.
    #[from_metadata(path = "issuer")]
    issuer: Option<String>,

    /// The URL of the token endpoint.
    #[from_metadata(path = "token_endpoint")]
    #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
    #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
    mtls_token_endpoint: Option<EndpointUrl>,

    /// Supported endpoint auth methods; used to auto-select basic or
    /// form auth for client secrets.
    #[from_metadata(path = "token_endpoint_auth_methods_supported")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication + Clone + 'static, D: AuthorizationServerDPoP + 'static>
    OAuth2ExchangeGrant for TokenExchangeGrant<Auth, D>
{
    type Parameters = TokenExchangeGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = TokenExchangeGrantForm;

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.client_auth
    }

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn mtls_token_endpoint(&self) -> Option<&EndpointUrl> {
        self.mtls_token_endpoint.as_ref()
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.dpop
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn to_refresh_grant(&self) -> RefreshGrant<Auth, D> {
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.token_endpoint.clone())
            .unwrap_or_else(|e| match e {})
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        TokenExchangeGrantForm {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            resource: params.resource,
            audience: params.audience,
            scope: params.scope,
            requested_token_type: params.requested_token_type,
            subject_token: params.subject.token,
            subject_token_type: params.subject.token_type,
            actor_token: params.actor.as_ref().map(|t| t.token.clone()),
            actor_token_type: params.actor.as_ref().map(|t| t.token_type.clone()),
        }
    }
}

/// Parameters when requesting a token using the token exchange grant.
#[derive(Debug, Clone, Builder)]
pub struct TokenExchangeGrantParameters {
    /// The security token to exchange (the subject of the exchange).
    #[builder(into)]
    subject: SecurityToken,
    /// The URI of a resource server where the requested token will be used.
    resource: Option<Vec<String>>,
    /// The logical name of the target service or resource where the requested token will be used.
    #[builder(into)]
    audience: Option<String>,
    /// The requested scope(s) for the issued security token.
    #[builder(required, default, name = "scopes", with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    scope: Option<String>,
    /// The type of the requested security token (e.g. `urn:ietf:params:oauth:token-type:access_token`).
    #[builder(into)]
    requested_token_type: Option<String>,
    /// An optional security token representing the party acting on behalf of the subject.
    #[builder(into)]
    actor: Option<SecurityToken>,
}

/// A security token used as the subject or actor in a token exchange.
#[derive(Debug, Clone, Builder)]
pub struct SecurityToken {
    /// The raw token string.
    #[builder(into)]
    token: String,
    /// The type of the token.
    token_type: SecurityTokenType,
}

/// The type of a [`SecurityToken`] in an RFC 8693 token exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum SecurityTokenType {
    /// `urn:ietf:params:oauth:token-type:access_token`
    #[serde(rename = "urn:ietf:params:oauth:token-type:access_token")]
    AccessToken,
    /// `urn:ietf:params:oauth:token-type:refresh_token`
    #[serde(rename = "urn:ietf:params:oauth:token-type:refresh_token")]
    RefreshToken,
    /// `urn:ietf:params:oauth:token-type:id_token`
    #[serde(rename = "urn:ietf:params:oauth:token-type:id_token")]
    IdToken,
    /// `urn:ietf:params:oauth:token-type:saml1`
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml1")]
    Saml1,
    /// `urn:ietf:params:oauth:token-type:saml2`
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml2")]
    Saml2,
    /// `urn:ietf:params:oauth:token-type:jwt`
    #[serde(rename = "urn:ietf:params:oauth:token-type:jwt")]
    Jwt,
    /// An extension token type not covered by the standard variants.
    #[serde(untagged)]
    Other(String),
}

/// Token exchange grant body.
#[derive(Debug, Serialize)]
pub struct TokenExchangeGrantForm {
    grant_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_token_type: Option<String>,
    subject_token: String,
    subject_token_type: SecurityTokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_token_type: Option<SecurityTokenType>,
}
