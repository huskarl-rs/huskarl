use std::borrow::Cow;

use crate::{
    EndpointUrl, IntoEndpointUrl,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::authorization_code::{
        grant::builder::{SetDpop, SetJar},
        jar::{Jar, NoJar},
    },
};
use bon::Builder;

use crate::{
    client_auth::ClientAuthentication,
    grant::authorization_code::grant::builder::{
        SetAuthorizationEndpoint, SetAuthorizationResponseIssParameterSupported, SetIssuer,
        SetPushedAuthorizationRequestEndpoint, SetRequirePushedAuthorizationRequests,
        SetTokenEndpoint, SetTokenEndpointAuthMethodsSupported,
    },
    server_metadata::AuthorizationServerMetadata,
};

/// The authorization code grant (RFC 6749 §4.1).
///
/// # Examples
///
/// ## Simple flow example (public `OAuth2` client, no `DPoP`).
///
/// ```rust, no_run
/// use huskarl::server_metadata::AuthorizationServerMetadata;
/// use huskarl::grant::authorization_code::AuthorizationCodeGrant;
/// use huskarl::client_auth::NoAuth;
///
/// let metadata: AuthorizationServerMetadata = todo!();
///
/// let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
///     .unwrap()
///     .client_id("my_client_id")
///     .client_auth(NoAuth)
///     .redirect_uri("https://redirect_url")
///     .build();
/// ```
#[derive(Debug, Clone, Builder)]
#[builder(
    start_fn(vis = "", name = "builder_internal"),
    state_mod(name = "builder"),
    generics(setters(name = "conv_{}"))
)]
pub struct AuthorizationCodeGrant<
    Auth: ClientAuthentication,
    D: AuthorizationServerDPoP = NoDPoP,
    J: Jar = NoJar,
> {
    /// The `DPoP` configuration.
    #[builder(setters(vis = "", name = "dpop_internal"))]
    pub(super) dpop: Option<D>,

    #[builder(setters(vis = "", name = "jar_internal"))]
    pub(super) jar: Option<J>,

    // -- User-supplied fields --
    /// The client ID.
    #[builder(into)]
    pub(super) client_id: Cow<'static, str>,

    /// The client authentication method.
    pub(super) client_auth: Auth,

    // -- Metadata fields --
    /// The URL of the token endpoint.
    #[builder(setters(name = "token_endpoint_url"))]
    pub(super) token_endpoint: EndpointUrl,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    #[builder(into)]
    pub(super) token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// The authorization endpoint (RFC 6749 §3.1).
    #[builder(setters(name = "authorization_endpoint_url"))]
    pub(super) authorization_endpoint: EndpointUrl,

    /// The expected issuer.
    #[builder(into)]
    pub(super) issuer: Option<String>,

    /// The pushed authorization request endpoint (RFC 9126 §5).
    #[builder(setters(name = "pushed_authorization_request_endpoint_url"))]
    pub(super) pushed_authorization_request_endpoint: Option<EndpointUrl>,

    /// Set to true if the provider requires PAR requests only (RFC 9126 §5).
    ///
    /// The value is usually set using authorization server metadata (RFC 8414).
    #[builder(default = false)]
    pub(super) require_pushed_authorization_requests: bool,

    /// Set to true if the provider supports the `iss` parameter in the authorization code callback (RFC 9207).
    #[builder(default = false)]
    pub(super) authorization_response_iss_parameter_supported: bool,

    // -- User-supplied grant-specific fields --
    /// A redirect URL registered with the authorization server.
    #[builder(into)]
    pub(super) redirect_uri: String,

    /// Set to true to prefer PAR when available.
    #[builder(default = true)]
    pub(super) prefer_pushed_authorization_requests: bool,
}

impl<Auth: ClientAuthentication + 'static> AuthorizationCodeGrant<Auth> {
    pub fn builder() -> AuthorizationCodeGrantBuilder<Auth, NoDPoP, NoJar> {
        AuthorizationCodeGrant::<Auth, NoDPoP>::builder_internal()
    }
}

impl<Auth: ClientAuthentication + 'static> AuthorizationCodeGrant<Auth, NoDPoP, NoJar> {
    /// Configure the flow from authorization server metadata.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        AuthorizationCodeGrantBuilder<
            Auth,
            NoDPoP,
            NoJar,
            SetAuthorizationResponseIssParameterSupported<
                SetRequirePushedAuthorizationRequests<
                    SetPushedAuthorizationRequestEndpoint<
                        SetIssuer<
                            SetAuthorizationEndpoint<
                                SetTokenEndpointAuthMethodsSupported<SetTokenEndpoint>,
                            >,
                        >,
                    >,
                >,
            >,
        >,
    > {
        metadata
            .authorization_endpoint
            .as_ref()
            .map(|authorization_endpoint| {
                AuthorizationCodeGrant::builder()
                    .token_endpoint_url(metadata.token_endpoint.clone())
                    .token_endpoint_auth_methods_supported(
                        metadata.token_endpoint_auth_methods_supported.clone(),
                    )
                    .authorization_endpoint_url(authorization_endpoint.clone())
                    .issuer(metadata.issuer.clone())
                    .maybe_pushed_authorization_request_endpoint_url(
                        metadata.pushed_authorization_request_endpoint.clone(),
                    )
                    .require_pushed_authorization_requests(
                        metadata.require_pushed_authorization_requests,
                    )
                    .authorization_response_iss_parameter_supported(
                        metadata.authorization_response_iss_parameter_supported,
                    )
            })
    }
}

impl<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
    S: builder::State,
> AuthorizationCodeGrantBuilder<Auth, D, J, S>
{
    pub fn dpop<D1: AuthorizationServerDPoP + 'static>(
        self,
        dpop: D1,
    ) -> AuthorizationCodeGrantBuilder<Auth, D1, J, SetDpop<S>>
    where
        S::Dpop: builder::IsUnset,
    {
        self.conv_d().dpop_internal(dpop)
    }

    pub fn jar<J1: Jar + 'static>(
        self,
        jar: J1,
    ) -> AuthorizationCodeGrantBuilder<Auth, D, J1, SetJar<S>>
    where
        S::Jar: builder::IsUnset,
    {
        self.conv_j().jar_internal(jar)
    }

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
    ) -> Result<AuthorizationCodeGrantBuilder<Auth, D, J, builder::SetTokenEndpoint<S>>, U::Error>
    where
        S::TokenEndpoint: builder::IsUnset,
    {
        Ok(self.token_endpoint_url(url.into_endpoint_url()?))
    }

    /// Sets the authorization endpoint URL.
    ///
    /// Accepts any type that implements [`IntoEndpointUrl`], including
    /// `&str`, [`String`], [`Url`](url::Url), [`Uri`](http::Uri), and
    /// [`EndpointUrl`].
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed as a valid URI.
    pub fn authorization_endpoint<U: IntoEndpointUrl>(
        self,
        url: U,
    ) -> Result<
        AuthorizationCodeGrantBuilder<Auth, D, J, builder::SetAuthorizationEndpoint<S>>,
        U::Error,
    >
    where
        S::AuthorizationEndpoint: builder::IsUnset,
    {
        Ok(self.authorization_endpoint_url(url.into_endpoint_url()?))
    }

    /// Sets the pushed authorization request endpoint URL.
    ///
    /// Accepts any type that implements [`IntoEndpointUrl`], including
    /// `&str`, [`String`], [`Url`](url::Url), [`Uri`](http::Uri), and
    /// [`EndpointUrl`].
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed as a valid URI.
    pub fn pushed_authorization_request_endpoint<U: IntoEndpointUrl>(
        self,
        url: U,
    ) -> Result<
        AuthorizationCodeGrantBuilder<
            Auth,
            D,
            J,
            builder::SetPushedAuthorizationRequestEndpoint<S>,
        >,
        U::Error,
    >
    where
        S::PushedAuthorizationRequestEndpoint: builder::IsUnset,
    {
        Ok(self.pushed_authorization_request_endpoint_url(url.into_endpoint_url()?))
    }
}
