//! Client credentials grant (RFC 6749 §4.4).
//!
//! Used when the client is acting on its own behalf, not on behalf of a user.

use std::borrow::Cow;

use bon::Builder;
use serde::Serialize;
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::core::{OAuth2ExchangeGrant, mk_scopes},
};

/// An `OAuth2` client credentials grant.
///
/// This grant is used for machine-to-machine authentication where no user
/// interaction is required. The client authenticates directly with the
/// authorization server using its own credentials.
#[derive(Debug, Builder)]
pub struct ClientCredentialsGrant<Auth: ClientAuthentication, D: AuthorizationServerDPoP = NoDPoP> {
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
    token_endpoint: Url,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication + 'static, DPoP: AuthorizationServerDPoP + 'static>
    OAuth2ExchangeGrant for ClientCredentialsGrant<Auth, DPoP>
{
    type Parameters = ClientCredentialsGrantParameters;
    type ClientAuth = Auth;
    type DPoP = DPoP;
    type Form<'a> = ClientCredentialsGrantForm;

    fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.client_auth
    }

    fn client_id(&self) -> &str {
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

/// Parameters when requesting a token.
#[derive(Debug, Clone, Builder)]
pub struct ClientCredentialsGrantParameters {
    #[builder(required, name = "scopes", with = |scopes: impl IntoIterator<Item = impl Into<String>>| mk_scopes(scopes))]
    scope: Option<String>,
}

/// Client credentials grant body.
#[derive(Debug, Serialize)]
pub struct ClientCredentialsGrantForm {
    grant_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}
