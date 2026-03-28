//! Refresh token grant (RFC 6749 §6).
//!
//! Used to obtain a new access token using a previously issued refresh token,
//! without requiring the user to re-authenticate.

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
