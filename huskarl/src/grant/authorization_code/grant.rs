use std::{marker::PhantomData, sync::Arc};

use bon::Builder;
use serde::{Deserialize, Serialize};

use crate::{
    core::{
        BoxedError, EndpointUrl,
        client_auth::ClientAuthentication,
        crypto::verifier::JwsVerifierPlatform,
        crypto::verifier::{BoxedJwsVerifier, JwsVerifierFactory},
        dpop::AuthorizationServerDPoP,
        platform::MaybeSendSync,
        server_metadata::AuthorizationServerMetadata,
    },
    grant::{
        authorization_code::{
            grant::builder::{
                SetAuthorizationEndpoint, SetAuthorizationResponseIssParameterSupported,
                SetCodeChallengeMethodsSupported, SetJwksUri,
                SetMtlsPushedAuthorizationRequestEndpoint, SetPushedAuthorizationRequestEndpoint,
                SetRequirePushedAuthorizationRequests, State,
            },
            jar::{Jar, NoJar},
        },
        core::OAuth2ExchangeGrant,
        refresh,
    },
};

/// The authorization code grant (RFC 6749 §4.1).
///
/// # Examples
///
/// ## Simple flow example (public `OAuth2` client, no `DPoP`).
///
/// ```rust, no_run
/// use huskarl::core::server_metadata::AuthorizationServerMetadata;
/// use huskarl::grant::authorization_code::{AuthorizationCodeGrant, NoJar};
/// use huskarl::core::client_auth::NoAuth;
/// use huskarl::core::dpop::NoDPoP;
///
/// let metadata: AuthorizationServerMetadata = todo!();
///
/// let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
///     .unwrap()
///     .client_id("my_client_id")
///     .client_auth(NoAuth)
///     .redirect_uri("https://redirect_url")
///     .dpop(NoDPoP)
///     .jar(NoJar)
///     .build();
/// ```
#[huskarl_macros::grant(vis(pub(super)))]
#[derive(Clone)]
pub struct AuthorizationCodeGrant<
    J: Jar = NoJar,
    IdClaims: Clone + for<'de> Deserialize<'de> + 'static = (),
> {
    /// The JWS verifier to use when verifying JWS signatures.
    ///
    /// This field is populated from the values of `jwks_uri`, `jws_verifier_platform`,
    /// and `jws_verifier_factory` at build time.
    pub(super) jws_verifier: Option<BoxedJwsVerifier>,

    pub(super) jar: J,

    /// The authorization endpoint (RFC 6749 §3.1).
    pub(super) authorization_endpoint: EndpointUrl,

    /// The pushed authorization request endpoint (RFC 9126 §5).
    pub(super) pushed_authorization_request_endpoint: Option<EndpointUrl>,

    /// The mTLS alias for the pushed authorization request endpoint (RFC 8705 §5).
    pub(super) mtls_pushed_authorization_request_endpoint: Option<EndpointUrl>,

    /// Set to true if the provider requires PAR requests only (RFC 9126 §5).
    ///
    /// The value is usually set using authorization server metadata (RFC 8414).
    pub(super) require_pushed_authorization_requests: bool,

    /// Set to true if the provider supports the `iss` parameter in the authorization code callback (RFC 9207).
    pub(super) authorization_response_iss_parameter_supported: bool,

    /// Contains the supported code challenge methods (RFC 8152 §7.1).
    ///
    /// The default is `S256`; this is different to the default value if authorization server
    /// metadata does not include the field (the default at that layer is an empty list).
    pub(super) code_challenge_methods_supported: Vec<String>,

    // -- User-supplied grant-specific fields --
    /// A redirect URL registered with the authorization server.
    pub(super) redirect_uri: String,

    /// Set to true to prefer PAR when available.
    pub(super) prefer_pushed_authorization_requests: bool,

    _phantom: PhantomData<IdClaims>,
}

#[huskarl_macros::grant_new]
#[bon::bon]
impl<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
    IdClaims: Clone + for<'de> Deserialize<'de> + 'static,
> AuthorizationCodeGrant<Auth, D, J, IdClaims>
{
    /// Creates a new [`AuthorizationCodeGrant`] instance.
    #[builder(
        state_mod(name = "builder"),
        generics(setters(vis = "", name = "with_{}_internal")),
        on(String, into)
    )]
    pub async fn new(
        /// The JAR (JWT Secured Authorization Request) implementation to use when making requests to the authorization server.
        ///
        /// With JAR, the parameters of the initial request to the authorization server are signed
        /// using a JWT, instead of being passed as URL query parameters.
        ///
        /// This adds authenticity (request comes from the client) and integrity (request cannot be tampered with) to the request.
        ///
        /// There are two built-in implementations:
        /// - [`crate::grant::authorization_code::jar::Jar`]
        ///     This implements JAR signing (when understood by the authorization server).
        /// - [`crate::grant::authorization_code::jar::NoJar`]
        ///     No JAR is implemented when this variant is used.
        jar: J,
        #[endpoint_url] jwks_uri: Option<EndpointUrl>,
        #[endpoint_url] authorization_endpoint: EndpointUrl,
        #[endpoint_url] pushed_authorization_request_endpoint: Option<EndpointUrl>,
        #[endpoint_url] mtls_pushed_authorization_request_endpoint: Option<EndpointUrl>,
        #[builder(default)] require_pushed_authorization_requests: bool,
        #[builder(default)] authorization_response_iss_parameter_supported: bool,
        #[builder(default = vec!["S256".to_string()])] code_challenge_methods_supported: Vec<
            String,
        >,
        redirect_uri: String,
        #[builder(default = true)] prefer_pushed_authorization_requests: bool,
        #[cfg(not(feature = "default-jws-verifier-platform"))] jws_verifier_platform: Option<
            Arc<dyn JwsVerifierPlatform>,
        >,
        #[cfg(feature = "default-jws-verifier-platform")]
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        jws_verifier_factory: Option<Arc<dyn JwsVerifierFactory>>,
    ) -> Result<Self, BoxedError> {
        #[cfg(feature = "default-jws-verifier-platform")]
        let jws_verifier_platform = Some(jws_verifier_platform);

        let jws_verifier = if let Some(jws_verifier_platform) = jws_verifier_platform.clone()
            && let Some(jws_verifier_factory) = jws_verifier_factory.clone()
        {
            Some(
                jws_verifier_factory
                    .build(jwks_uri.as_ref(), jws_verifier_platform)
                    .await?,
            )
        } else {
            None
        };

        Ok(Self {
            jws_verifier,
            client_id,
            client_auth,
            dpop,
            jar,
            token_endpoint,
            token_endpoint_auth_methods_supported,
            authorization_endpoint,
            issuer,
            pushed_authorization_request_endpoint,
            mtls_token_endpoint,
            mtls_pushed_authorization_request_endpoint,
            require_pushed_authorization_requests,
            authorization_response_iss_parameter_supported,
            code_challenge_methods_supported,
            redirect_uri,
            prefer_pushed_authorization_requests,
            _phantom: PhantomData,
        })
    }
}

impl<Auth: ClientAuthentication + 'static, D: AuthorizationServerDPoP + 'static, J: Jar + 'static>
    AuthorizationCodeGrant<Auth, D, J, ()>
{
    /// Configure the grant from authorization server metadata.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        AuthorizationCodeGrantBuilder<
            Auth,
            D,
            J,
            (),
            SetMtlsPushedAuthorizationRequestEndpoint<
                SetAuthorizationEndpoint<
                    SetJwksUri<
                        SetPushedAuthorizationRequestEndpoint<
                            SetCodeChallengeMethodsSupported<
                                SetAuthorizationResponseIssParameterSupported<
                                    SetRequirePushedAuthorizationRequests<SetCommonMetadata>,
                                >,
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
                    .with_common_metadata(metadata)
                    .require_pushed_authorization_requests(
                        metadata.require_pushed_authorization_requests,
                    )
                    .authorization_response_iss_parameter_supported(
                        metadata.authorization_response_iss_parameter_supported,
                    )
                    .code_challenge_methods_supported(
                        metadata.code_challenge_methods_supported.clone(),
                    )
                    .maybe_pushed_authorization_request_endpoint_internal(
                        metadata.pushed_authorization_request_endpoint.clone(),
                    )
                    .maybe_jwks_uri_internal(metadata.jwks_uri.clone())
                    .authorization_endpoint_internal(authorization_endpoint.clone())
                    .maybe_mtls_pushed_authorization_request_endpoint_internal(
                        metadata
                            .mtls_endpoint_aliases
                            .as_ref()
                            .and_then(|a| a.pushed_authorization_request_endpoint.clone()),
                    )
            })
    }
}

impl<
    Auth: ClientAuthentication + 'static,
    D: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
    IdClaims: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static,
    S: State,
> AuthorizationCodeGrantBuilder<Auth, D, J, IdClaims, S>
{
    /// Sets the ID claims type for the authorization code grant.
    pub fn with_id_claims<C: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static>(
        self,
    ) -> AuthorizationCodeGrantBuilder<Auth, D, J, C, S> {
        self.with_id_claims_internal()
    }
}

/// Parameters passed to each token request.
#[derive(Debug, Clone, Builder)]
pub struct AuthorizationCodeGrantParameters {
    /// The bound `DPoP` JWT thumbprint, if any has already been computed.
    #[builder(into)]
    pub dpop_jkt: Option<String>,
    /// The temporary authorization code received from the redirect callback.
    #[builder(into)]
    pub code: String,
    /// The PKCE verifier.
    #[builder(into)]
    pub pkce_verifier: Option<String>,
    /// The target resource(s) for the access token.
    pub resource: Option<Vec<String>>,
}

/// Authorization code grant body.
#[derive(Debug, Serialize)]
pub struct AuthorizationCodeGrantForm<'a> {
    grant_type: &'static str,
    code: String,
    redirect_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<Vec<String>>,
}

#[huskarl_macros::grant_impl]
impl<
    Auth: ClientAuthentication + Clone + 'static,
    D: AuthorizationServerDPoP + 'static,
    J: Jar + 'static,
    IdClaims: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static,
> OAuth2ExchangeGrant for AuthorizationCodeGrant<Auth, D, J, IdClaims>
{
    type Parameters = AuthorizationCodeGrantParameters;
    type ClientAuth = Auth;
    type DPoP = D;
    type Form<'a> = AuthorizationCodeGrantForm<'a>;

    fn bound_dpop_jkt(params: &Self::Parameters) -> Option<&str> {
        params.dpop_jkt.as_deref()
    }

    fn to_refresh_grant(&self) -> refresh::RefreshGrant<Self::ClientAuth, Self::DPoP> {
        refresh::RefreshGrant::builder()
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
        Self::Form {
            grant_type: "authorization_code",
            code: params.code,
            redirect_uri: &self.redirect_uri,
            code_verifier: params.pkce_verifier,
            resource: params.resource,
        }
    }
}
