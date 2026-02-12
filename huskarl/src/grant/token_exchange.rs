//! Token exchange grant (RFC 8693).
//!
//! Used to issue a new access token using an existing token.

use bon::Builder;
use serde::Serialize;

use crate::{
    core::server_metadata::AuthorizationServerMetadata,
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
#[huskarl_macros::grant]
#[derive(Debug, Builder)]
#[builder(state_mod(name = "builder"), on(String, into))]
pub struct TokenExchangeGrant {}

impl<
    Auth: crate::core::client_auth::ClientAuthentication + 'static,
    D: crate::core::dpop::AuthorizationServerDPoP + 'static,
> TokenExchangeGrant<Auth, D>
{
    /// Configure the grant from authorization server metadata.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> TokenExchangeGrantBuilder<Auth, D, SetCommonMetadata> {
        TokenExchangeGrant::builder().with_common_metadata(metadata)
    }
}

#[huskarl_macros::grant_impl]
impl<
    Auth: crate::core::client_auth::ClientAuthentication + Clone + 'static,
    D: crate::core::dpop::AuthorizationServerDPoP + 'static,
> OAuth2ExchangeGrant for TokenExchangeGrant<Auth, D>
{
    type Parameters = TokenExchangeGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = TokenExchangeGrantForm;

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
