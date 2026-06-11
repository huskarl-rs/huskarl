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
//! use huskarl_reqwest::ReqwestClient;
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().build().await?;
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
//! let client_auth: ClientSecret = ClientSecret::new(env_secret);
//! # Ok(())
//! # }
//! ```
//!
//! ## 3a. Set up the grant with authorization server metadata
//!
//! ```rust
//! use huskarl::{
//!     core::{client_auth::ClientSecret, server_metadata::AuthorizationServerMetadata},
//!     grant::token_exchange::TokenExchangeGrant,
//! };
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
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
//! let grant: TokenExchangeGrant = TokenExchangeGrant::builder_from_metadata(&metadata)
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(client_auth)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## 3b. Alternative: Set up the grant without metadata
//!
//! ```rust
//! use huskarl::{core::client_auth::ClientSecret, grant::token_exchange::TokenExchangeGrant};
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let env_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let client_auth: ClientSecret = ClientSecret::new(env_secret);
//!
//! let grant: TokenExchangeGrant = TokenExchangeGrant::builder()
//!     .token_endpoint("https://my-server/token")?
//!     .client_id("client_id")
//!     .http_client(client)
//!     .client_auth(client_auth)
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
//! # use huskarl::core::http::HttpClient;
//! # use huskarl::core::secrets::EnvVarSecret;
//! # use huskarl::core::secrets::encodings::StringEncoding;
//! # async fn setup_grant() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = huskarl_reqwest::ReqwestClient::builder()
//! #     .build()
//! #     .await?;
//! #
//! # let client_auth: ClientSecret = ClientSecret::new(EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?);
//! #
//! # let grant: TokenExchangeGrant = TokenExchangeGrant::builder()
//! #     .token_endpoint("https://my-server/token")?
//! #     .client_id("client_id")
//! #     .http_client(client)
//! #     .client_auth(client_auth)
//! #     .build();
//!
//! let subject = SecurityToken::builder().token("eyToken").token_type(SecurityTokenType::AccessToken).build();
//! let params = TokenExchangeGrantParameters::builder().subject(subject).build();
//! let response = grant.exchange(params).await?;
//! let token: &AccessToken = response.access_token();
//!
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
#[derive(Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct TokenExchangeGrant {
    /// The client ID.
    client_id: String,

    /// The HTTP client used for token requests.
    #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
    http_client: Arc<dyn HttpClient>,

    /// The client authentication method.
    #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
    client_auth: Arc<dyn ClientAuthentication>,

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
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be converted via
    /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
    #[from_metadata(path = "token_endpoint")]
    #[builder(with = |url: impl crate::core::IntoEndpointUrl| -> Result<_, crate::core::Error> {
        crate::core::IntoEndpointUrl::into_endpoint_url(url)
    })]
    token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be converted via
    /// [`IntoEndpointUrl`](crate::core::IntoEndpointUrl).
    #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
    #[builder(with = |url: impl crate::core::IntoEndpointUrl| -> Result<_, crate::core::Error> {
        crate::core::IntoEndpointUrl::into_endpoint_url(url)
    })]
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

impl core::fmt::Debug for TokenExchangeGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenExchangeGrant")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("mtls_token_endpoint", &self.mtls_token_endpoint)
            .finish_non_exhaustive()
    }
}

impl OAuth2ExchangeGrant for TokenExchangeGrant {
    type Parameters = TokenExchangeGrantParameters;
    type Form<'a> = TokenExchangeGrantForm;

    /// Subject and actor tokens may be exchanged repeatedly while they remain valid.
    fn reusable_parameters(&self) -> bool {
        true
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> &dyn ClientAuthentication {
        self.client_auth.as_ref()
    }

    // Deliberately returns the build-time-resolved endpoint, not the raw
    // `token_endpoint` builder input.
    #[allow(clippy::misnamed_getters)]
    fn token_endpoint(&self) -> &EndpointUrl {
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
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .http_client(self.http_client.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.effective_token_endpoint.clone())
            .expect("an EndpointUrl converts to itself infallibly")
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
