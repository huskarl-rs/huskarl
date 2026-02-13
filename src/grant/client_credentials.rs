//! Client credentials grant (RFC 6749 §4.4).
//!
//! Used when the client is acting on its own behalf, not on behalf of a user.

use std::borrow::Cow;

use bon::Builder;
use serde::Serialize;

use crate::{
    EndpointUrl, IntoEndpointUrl,
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::{
        client_credentials::builder::{SetTokenEndpoint, SetTokenEndpointAuthMethodsSupported},
        core::{OAuth2ExchangeGrant, RefreshableGrant, mk_scopes},
        refresh::RefreshGrant,
    },
    server_metadata::AuthorizationServerMetadata,
};

/// An `OAuth2` client credentials grant.
///
/// This grant is used for machine-to-machine authentication where no user
/// interaction is required. The client authenticates directly with the
/// authorization server using its own credentials.
#[derive(Debug, Builder)]
#[builder(
    start_fn(vis = "", name = "builder_internal"),
    state_mod(name = "builder"),
    generics(setters(name = "conv_{}"))
)]
pub struct ClientCredentialsGrant<Auth: ClientAuthentication, D: AuthorizationServerDPoP = NoDPoP> {
    /// The `DPoP` signer.
    #[builder(setters(vis = "", name = "dpop_internal"))]
    dpop: Option<D>,

    // -- User-supplied fields --
    /// The client ID.
    #[builder(into)]
    client_id: Cow<'static, str>,

    /// The client authentication method.
    client_auth: Auth,

    // -- Metadata fields --
    /// The URL of the token endpoint.
    #[builder(setters(name = "token_endpoint_url"))]
    token_endpoint: EndpointUrl,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication + 'static> ClientCredentialsGrant<Auth> {
    pub fn builder() -> ClientCredentialsGrantBuilder<Auth, NoDPoP> {
        ClientCredentialsGrant::<Auth, NoDPoP>::builder_internal()
    }

    pub fn build_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> ClientCredentialsGrantBuilder<
        Auth,
        NoDPoP,
        SetTokenEndpointAuthMethodsSupported<SetTokenEndpoint<builder::Empty>>,
    > {
        Self::builder()
            .token_endpoint_url(metadata.token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
            )
    }
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static, S: builder::State>
    ClientCredentialsGrantBuilder<Auth, D, S>
where
    S::Dpop: builder::IsUnset,
{
    /// The `DPoP` signer.
    pub fn dpop<D1: AuthorizationServerDPoP + 'static>(
        self,
        dpop: D1,
    ) -> ClientCredentialsGrantBuilder<Auth, D1, builder::SetDpop<S>> {
        self.conv_d().dpop_internal(dpop)
    }

    /// The `DPoP` signer.
    pub fn maybe_dpop<D1: AuthorizationServerDPoP + 'static>(
        self,
        dpop: Option<D1>,
    ) -> ClientCredentialsGrantBuilder<Auth, D1, builder::SetDpop<S>> {
        self.conv_d().maybe_dpop_internal(dpop)
    }
}

impl<Auth: ClientAuthentication, D: AuthorizationServerDPoP, S: builder::State>
    ClientCredentialsGrantBuilder<Auth, D, S>
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
    ) -> Result<ClientCredentialsGrantBuilder<Auth, D, builder::SetTokenEndpoint<S>>, U::Error>
    where
        S::TokenEndpoint: builder::IsUnset,
    {
        Ok(self.token_endpoint_url(url.into_endpoint_url()?))
    }
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static> OAuth2ExchangeGrant
    for ClientCredentialsGrant<Auth, D>
{
    type Parameters = ClientCredentialsGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = ClientCredentialsGrantForm;

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.client_auth
    }

    fn client_id(&self) -> &Cow<'static, str> {
        &self.client_id
    }

    fn dpop(&self) -> Option<&Self::DPoP> {
        self.dpop.as_ref()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        ClientCredentialsGrantForm {
            grant_type: "client_credentials",
            scope: params.scope,
        }
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }
}

impl<Auth: ClientAuthentication + Clone + 'static, D: AuthorizationServerDPoP + Clone + 'static>
    RefreshableGrant for ClientCredentialsGrant<Auth, D>
{
    type ClientAuth = Auth;
    type DPoP = D;

    fn to_refresh_grant(&self) -> RefreshGrant<Auth, D> {
        RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .client_auth(self.client_auth.clone())
            .maybe_dpop(self.dpop.clone())
            .token_endpoint(self.token_endpoint.clone())
            .unwrap_or_else(|e: std::convert::Infallible| match e {})
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }
}

/// Parameters when requesting a token using the client credentials grant.
#[derive(Debug, Clone, Builder)]
pub struct ClientCredentialsGrantParameters {
    #[builder(required, default, name = "scopes", with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    scope: Option<String>,
}

/// Client credentials grant body.
#[derive(Debug, Serialize)]
pub struct ClientCredentialsGrantForm {
    grant_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}
