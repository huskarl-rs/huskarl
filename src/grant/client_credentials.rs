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
        client_credentials::builder::{
            SetIssuer, SetTokenEndpoint, SetTokenEndpointAuthMethodsSupported,
        },
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
#[builder(state_mod(name = "builder"))]
pub struct ClientCredentialsGrant<Auth: ClientAuthentication, D: AuthorizationServerDPoP = NoDPoP> {
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
    ClientCredentialsGrant<Auth, D>
{
    /// Configure the grant from authorization server metadata.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> ClientCredentialsGrantBuilder<
        Auth,
        D,
        SetTokenEndpointAuthMethodsSupported<SetTokenEndpoint<SetIssuer<builder::Empty>>>,
    > {
        Self::builder()
            .issuer(metadata.issuer.clone())
            .token_endpoint_url(metadata.token_endpoint.clone())
            .token_endpoint_auth_methods_supported(
                metadata.token_endpoint_auth_methods_supported.clone(),
            )
    }

    /// Create a client credentials builder from a `httpmock` `MockServer`.
    ///
    /// # Panics
    ///
    /// Panics if the token endpoint returned from httpmock is not a valid URL.
    #[cfg(all(test, not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))))]
    pub fn builder_from_httpmock(
        server: &httpmock::MockServer,
        prefix: &str,
    ) -> ClientCredentialsGrantBuilder<Auth, D, SetTokenEndpoint<builder::Empty>> {
        Self::builder()
            .token_endpoint(server.url(format!("{prefix}/token")))
            .expect("URL comes from httpmock, and only test code")
    }
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static, S: builder::State>
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

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.dpop
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
            .maybe_issuer(self.issuer.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
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

impl Default for ClientCredentialsGrantParameters {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl ClientCredentialsGrantParameters {
    /// Create an empty set of parameters for requesting a token.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }
}

/// Client credentials grant body.
#[derive(Debug, Serialize)]
pub struct ClientCredentialsGrantForm {
    grant_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[cfg(all(test, not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))))]
mod tests {
    use std::sync::LazyLock;

    use httpmock::MockServer;
    use serde_json::json;

    use crate::{
        client_auth::NoAuth,
        crypto::signer::native::Es256PrivateKey,
        dpop::{DPoP, NoDPoP},
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    };

    static MOCK_SERVER: LazyLock<MockServer> = LazyLock::new(MockServer::start);
    static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

    #[tokio::test]
    async fn test_exchange() {
        use crate::prelude::*;
        use httpmock::prelude::*;

        let grant = ClientCredentialsGrant::builder_from_httpmock(&MOCK_SERVER, "/no_dpop")
            .client_id("client")
            .client_auth(NoAuth)
            .dpop(NoDPoP)
            .build();

        let mock = MOCK_SERVER
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/no_dpop/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header_missing("DPoP")
                    .form_urlencoded_tuple("grant_type", "client_credentials")
                    .form_urlencoded_tuple("client_id", "client");
                then.status(200)
                    .header("Content-Type", "application/json")
                    .json_body(json!({
                        "access_token": "access_token",
                        "token_type": "Bearer",
                    }));
            })
            .await;

        let response = grant
            .exchange(
                &HTTP_CLIENT,
                ClientCredentialsGrantParameters::builder().build(),
            )
            .await;

        mock.assert();
        let response = response.unwrap();
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.access_token.expose_token(), "access_token");
    }

    #[tokio::test]
    async fn test_exchange_with_dpop() {
        use crate::prelude::*;
        use httpmock::prelude::*;

        let grant = ClientCredentialsGrant::builder_from_httpmock(&MOCK_SERVER, "/with_dpop")
            .client_id("client")
            .client_auth(NoAuth)
            .dpop(DPoP::builder().signer(Es256PrivateKey::generate()).build())
            .build();

        let mock = MOCK_SERVER
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/with_dpop/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header_exists("DPoP")
                    .form_urlencoded_tuple("grant_type", "client_credentials")
                    .form_urlencoded_tuple("client_id", "client");
                then.status(200)
                    .header("Content-Type", "application/json")
                    .json_body(json!({
                        "access_token": "access_token",
                        "token_type": "DPoP",
                    }));
            })
            .await;

        let response = grant
            .exchange(
                &HTTP_CLIENT,
                ClientCredentialsGrantParameters::builder().build(),
            )
            .await;

        mock.assert();
        let response = response.unwrap();
        assert_eq!(response.token_type, "DPoP");
        assert_eq!(response.access_token.expose_token(), "access_token");
    }
}
