//! Refresh token grant (RFC 6749 §6).
//!
//! Used to obtain a new access token using a previously issued refresh token,
//! without requiring the user to re-authenticate.

use std::borrow::Cow;

use bon::Builder;
use serde::Serialize;

use crate::{
    EndpointUrl, IntoEndpointUrl,
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::{
        core::{OAuth2ExchangeGrant, RefreshableGrant, mk_scopes},
        refresh::builder::{SetIssuer, SetTokenEndpoint, SetTokenEndpointAuthMethodsSupported},
    },
    server_metadata::AuthorizationServerMetadata,
    token::RefreshToken,
};

#[derive(Debug, Clone, Builder)]
#[builder(state_mod(name = "builder"))]
pub struct RefreshGrant<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static = NoDPoP,
> {
    // -- User-supplied fields --
    /// The client ID.
    #[builder(into)]
    client_id: Cow<'static, str>,

    /// The client authentication method.
    client_auth: Auth,

    /// The `DPoP` signer.
    dpop: D,

    // -- Metadata fields --
    /// The issuer for tokens created by the authorization server.
    #[builder(into)]
    issuer: Option<String>,

    /// The URL of the token endpoint.
    #[builder(setters(name = "token_endpoint_url"))]
    token_endpoint: EndpointUrl,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static>
    RefreshGrant<Auth, D>
{
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> RefreshGrantBuilder<
        Auth,
        D,
        SetTokenEndpointAuthMethodsSupported<SetTokenEndpoint<SetIssuer<builder::Empty>>>,
    > {
        Self::builder()
            .issuer(metadata.issuer.clone())
            .token_endpoint_url(metadata.token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
            )
    }
}

impl<Auth: ClientAuthentication, D: AuthorizationServerDPoP, S: builder::State>
    RefreshGrantBuilder<Auth, D, S>
{
    /// Sets the token endpoint URL.
    ///
    /// Accepts any type that implements [`IntoEndpointUrl`], including
    /// `&str`, [`String`], [`Url`](url::Url), [`Uri`](http::Uri), and
    /// [`EndpointUrl`].
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed as a valid URI.
    pub fn token_endpoint<U: IntoEndpointUrl>(
        self,
        url: U,
    ) -> Result<RefreshGrantBuilder<Auth, D, builder::SetTokenEndpoint<S>>, U::Error>
    where
        S::TokenEndpoint: builder::IsUnset,
    {
        Ok(self.token_endpoint_url(url.into_endpoint_url()?))
    }
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static> OAuth2ExchangeGrant
    for RefreshGrant<Auth, D>
{
    type Parameters = RefreshGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;

    type Form<'a> = RefreshGrantForm;

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.client_auth
    }

    fn client_id(&self) -> &Cow<'static, str> {
        &self.client_id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.dpop
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        RefreshGrantForm {
            grant_type: "refresh_token",
            refresh_token: params.refresh_token,
            scope: params.scope,
        }
    }
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static> RefreshableGrant
    for RefreshGrant<Auth, D>
where
    Self: Clone,
{
    type ClientAuth = Auth;
    type DPoP = D;

    fn to_refresh_grant(&self) -> RefreshGrant<Self::ClientAuth, Self::DPoP> {
        self.clone()
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
}

/// Refresh grant body.
#[derive(Debug, Serialize)]
pub struct RefreshGrantForm {
    grant_type: &'static str,
    refresh_token: RefreshToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}
