use std::borrow::Cow;

use bon::Builder;
use serde::Serialize;

use crate::{
    EndpointUrl,
    client_auth::ClientAuthentication,
    dpop::AuthorizationServerDPoP,
    grant::{
        authorization_code::{grant::AuthorizationCodeGrant, jar::Jar},
        core::{OAuth2ExchangeGrant, RefreshableGrant},
        refresh,
    },
};

/// Parameters passed to each token request.
#[derive(Debug, Clone, Builder)]
pub struct AuthorizationCodeGrantParameters {
    /// The temporary authorization code received from the redirect callback.
    #[builder(into)]
    pub code: String,
    /// The PKCE verifier.
    #[builder(into)]
    pub pkce_verifier: Option<String>,
}

/// Authorization code grant body.
#[derive(Debug, Serialize)]
pub struct AuthorizationCodeGrantForm<'a> {
    grant_type: &'static str,
    code: String,
    redirect_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<String>,
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static, J: Jar + 'static>
    OAuth2ExchangeGrant for AuthorizationCodeGrant<Auth, D, J>
{
    type Parameters = AuthorizationCodeGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = AuthorizationCodeGrantForm<'a>;

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

    fn dpop(&self) -> Option<&Self::DPoP> {
        self.dpop.as_ref()
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        Self::Form {
            grant_type: "authorization_code",
            code: params.code,
            redirect_uri: &self.redirect_uri,
            code_verifier: params.pkce_verifier,
        }
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }
}

impl<
    Auth: ClientAuthentication + Clone + 'static,
    D: AuthorizationServerDPoP + Clone + 'static,
    J: Jar + 'static,
> RefreshableGrant for AuthorizationCodeGrant<Auth, D, J>
{
    type ClientAuth = Auth;
    type DPoP = D;

    fn to_refresh_grant(&self) -> refresh::RefreshGrant<Self::ClientAuth, Self::DPoP> {
        refresh::RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .client_auth(self.client_auth.clone())
            .maybe_dpop(self.dpop.clone())
            .token_endpoint_url(self.token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }
}
