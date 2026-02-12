//! Refresh token grant (RFC 6749 §6).
//!
//! Used to obtain a new access token using a previously issued refresh token,
//! without requiring the user to re-authenticate.

use std::borrow::Cow;

use bon::Builder;
use http::{Uri, uri::InvalidUri};
use serde::Serialize;
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::core::{OAuth2ExchangeGrant, RefreshableGrant},
    token::RefreshToken,
};

#[derive(Debug, Clone, Builder)]
#[builder(state_mod(name = "builder"))]
pub struct RefreshGrant<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static = NoDPoP,
> {
    /// The `DPoP` signer.
    dpop: Option<D>,

    // -- User-supplied fields --
    /// The client ID.
    #[builder(into)]
    client_id: Cow<'static, str>,

    /// The client authentication method.
    client_auth: Auth,

    // -- Metadata fields --
    /// The URL of the token endpoint.
    #[builder(setters(name = "token_endpoint_uri"))]
    token_endpoint: Uri,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication, D: AuthorizationServerDPoP, S: builder::State>
    RefreshGrantBuilder<Auth, D, S>
{
    pub fn token_endpoint(
        self,
        url: Url,
    ) -> Result<RefreshGrantBuilder<Auth, D, builder::SetTokenEndpoint<S>>, InvalidUri>
    where
        S::TokenEndpoint: builder::IsUnset,
    {
        Ok(self.token_endpoint_uri(url.to_string().parse::<Uri>()?))
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

    fn token_endpoint(&self) -> &Uri {
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
        RefreshGrantForm {
            grant_type: "refresh_token",
            refresh_token: params.refresh_token,
            scope: params.scopes.and_then(crate::grant::core::mk_scopes),
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
    #[builder(into)]
    scopes: Option<Vec<String>>,
}

/// Refresh grant body.
#[derive(Debug, Serialize)]
pub struct RefreshGrantForm {
    grant_type: &'static str,
    refresh_token: RefreshToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}
