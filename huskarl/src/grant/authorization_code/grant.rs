use std::{collections::HashSet, marker::PhantomData, sync::Arc};

use bon::Builder;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    core::{
        EndpointUrl, Error, ErrorKind,
        client_auth::ClientAuthentication,
        crypto::verifier::{JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform},
        dpop::AuthorizationServerDPoP,
        http::HttpClient,
        platform::MaybeSendSync,
    },
    grant::{
        authorization_code::{grant::builder::State, jar::Jar},
        core::OAuth2ExchangeGrant,
        refresh,
    },
};

/// The authorization code grant (RFC 6749 §4.1).
///
/// See the [module documentation][crate::grant::authorization_code] for a usage guide.
#[allow(clippy::struct_excessive_bools)] // independent protocol switches, not a state machine
#[derive(Clone)]
pub struct AuthorizationCodeGrant<IdClaims: Clone + for<'de> Deserialize<'de> + 'static = ()> {
    /// The client ID.
    pub(super) client_id: String,

    /// The HTTP client used for token and PAR requests.
    pub(super) http_client: Arc<dyn HttpClient>,

    /// The client authentication method.
    pub(super) client_auth: Arc<dyn ClientAuthentication>,

    /// The `DPoP` signer.
    pub(super) dpop: Arc<dyn AuthorizationServerDPoP>,

    /// The issuer for tokens created by the authorization server.
    pub(super) issuer: Option<String>,

    /// The URL of the token endpoint.
    pub(super) token_endpoint: EndpointUrl,

    /// The mTLS alias for the token endpoint (RFC 8705 §5).
    pub(super) mtls_token_endpoint: Option<EndpointUrl>,

    /// Supported endpoint auth methods; used to auto-select basic or
    /// form auth for client secrets.
    pub(super) token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// The JWS verifier to use when verifying JWS signatures.
    ///
    /// This field is populated from the values of `jwks_uri`, `jws_verifier_platform`,
    /// and `jws_verifier_factory` at build time.
    pub(super) jws_verifier: Option<Arc<dyn JwsVerifier>>,

    pub(super) jar: Arc<dyn Jar>,

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

    /// Contains the supported code challenge methods (RFC 8414 §2).
    ///
    /// `S256` is used unless this advertises `plain` without `S256`. An empty
    /// list (metadata that omits the optional field) still gets `S256`: PKCE
    /// is required by current best practice (RFC 9700 §2.1.1) and servers
    /// ignore unrecognized request parameters (RFC 6749 §3.1).
    pub(super) code_challenge_methods_supported: Vec<String>,

    // -- User-supplied grant-specific fields --
    /// A redirect URL registered with the authorization server.
    pub(super) redirect_uri: String,

    /// Set to true to disable PKCE (RFC 7636) entirely.
    ///
    /// PKCE is otherwise always applied, as required by current best practice
    /// (RFC 9700 §2.1.1). Only disable it for an authorization server that
    /// rejects requests containing PKCE parameters.
    pub(super) disable_pkce: bool,

    /// Set to true to prefer PAR when available.
    pub(super) prefer_pushed_authorization_requests: bool,

    /// If set, restricts accepted ID token signature algorithms to this set.
    ///
    /// When set, the [`crate::token::id_token::IdTokenValidator`] will reject any ID token whose `alg` header
    /// is not in this set. Use a single-element set to enforce a specific registered
    /// algorithm (`id_token_signed_response_alg`), or a multi-element set to enforce
    /// a policy (e.g. the FAPI 2.0 allowed algorithms: PS256, ES256, `EdDSA`).
    pub(super) allowed_id_token_signed_response_algs: Option<HashSet<String>>,

    _phantom: PhantomData<IdClaims>,
}

#[huskarl_macros::from_metadata(
    metadata = crate::core::server_metadata::AuthorizationServerMetadata,
    method(name = "builder_from_metadata_internal", vis = "")
)]
#[huskarl_macros::try_builder]
#[bon::bon]
impl<IdClaims: Clone + DeserializeOwned + 'static> AuthorizationCodeGrant<IdClaims> {
    /// Creates a new [`AuthorizationCodeGrant`] instance.
    ///
    /// This is the workhorse constructor; callers use [`Self::builder()`]
    /// (which starts with `IdClaims = ()`) and can switch to a typed claim
    /// set via [`with_id_claims`][AuthorizationCodeGrantBuilder::with_id_claims]
    /// on the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if a `jws_verifier_factory` is supplied without a
    /// `jws_verifier_platform`, or if building the JWS verifier from `jwks_uri`
    /// fails.
    #[builder(
        start_fn(name = "builder_internal", vis = ""),
        state_mod(name = "builder"),
        generics(setters(vis = "", name = "with_{}_internal")),
        on(String, into)
    )]
    pub async fn new(
        /// The client ID.
        client_id: String,
        /// The HTTP client used for token and PAR requests.
        #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
        http_client: Arc<dyn HttpClient>,
        /// The client authentication method.
        #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
        client_auth: Arc<dyn ClientAuthentication>,
        /// The `DPoP` signer.
        #[builder(with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>)]
        dpop: Arc<dyn AuthorizationServerDPoP>,
        /// The issuer for tokens created by the authorization server.
        #[from_metadata(path = "issuer")]
        issuer: Option<String>,
        /// The URL of the token endpoint.
        #[from_metadata(path = "token_endpoint")]
        #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
        token_endpoint: EndpointUrl,
        /// The mTLS alias for the token endpoint (RFC 8705 §5).
        #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
        #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
        mtls_token_endpoint: Option<EndpointUrl>,
        /// Supported endpoint auth methods; used to auto-select basic or
        /// form auth for client secrets.
        #[from_metadata(path = "token_endpoint_auth_methods_supported")]
        token_endpoint_auth_methods_supported: Option<Vec<String>>,
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
        #[builder(with = |jar: impl Jar + 'static| Arc::new(jar) as Arc<dyn Jar>)]
        jar: Arc<dyn Jar>,
        #[from_metadata(path = "jwks_uri?")]
        #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
        jwks_uri: Option<EndpointUrl>,
        #[from_metadata(path = "authorization_endpoint?")]
        #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
        authorization_endpoint: EndpointUrl,
        #[from_metadata(path = "pushed_authorization_request_endpoint?")]
        #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
        pushed_authorization_request_endpoint: Option<EndpointUrl>,
        #[from_metadata(path = "mtls_endpoint_aliases?.pushed_authorization_request_endpoint?")]
        #[try_setter(crate::core::IntoEndpointUrl::into_endpoint_url)]
        mtls_pushed_authorization_request_endpoint: Option<EndpointUrl>,
        #[from_metadata(path = "require_pushed_authorization_requests")]
        #[builder(default)]
        require_pushed_authorization_requests: bool,
        #[from_metadata(path = "authorization_response_iss_parameter_supported")]
        #[builder(default)]
        authorization_response_iss_parameter_supported: bool,
        #[from_metadata(path = "code_challenge_methods_supported")]
        #[builder(default = vec!["S256".to_string()])]
        code_challenge_methods_supported: Vec<String>,
        redirect_uri: String,
        /// Set to true to disable PKCE (RFC 7636) entirely.
        ///
        /// PKCE is otherwise always applied, as required by current best practice
        /// (RFC 9700 §2.1.1). Only disable it for an authorization server that
        /// rejects requests containing PKCE parameters.
        #[builder(default)]
        disable_pkce: bool,
        #[builder(default = true)] prefer_pushed_authorization_requests: bool,
        allowed_id_token_signed_response_algs: Option<HashSet<String>>,
        #[cfg(not(feature = "default-jws-verifier-platform"))] jws_verifier_platform: Option<
            Arc<dyn JwsVerifierPlatform>,
        >,
        #[cfg(feature = "default-jws-verifier-platform")]
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        jws_verifier_factory: Option<Arc<dyn JwsVerifierFactory>>,
    ) -> Result<Self, Error> {
        #[cfg(feature = "default-jws-verifier-platform")]
        let jws_verifier_platform = Some(jws_verifier_platform);

        let jws_verifier = match (jws_verifier_platform.clone(), jws_verifier_factory.clone()) {
            (Some(platform), Some(factory)) => {
                Some(factory.build(jwks_uri.as_ref(), platform).await?)
            }
            (None, Some(_)) => {
                return Err(Error::new(
                    ErrorKind::Config,
                    super::error::MissingJwsVerifierPlatformSnafu.build(),
                ));
            }
            (Some(_) | None, None) => None,
        };

        Ok(AuthorizationCodeGrant {
            jws_verifier,
            client_id,
            http_client,
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
            disable_pkce,
            prefer_pushed_authorization_requests,
            allowed_id_token_signed_response_algs,
            _phantom: PhantomData,
        })
    }
}

/// Specialized public entry points for the default `IdClaims = ()` case.
///
/// `builder()` and `builder_from_metadata()` forward to the bon- and
/// macro-generated `_internal` workhorses living on the fully-generic impl;
/// `IdClaims` is fixed to `()` here so callers don't need to turbofish. Users
/// who want a typed claim set chain `with_id_claims::<C>()` on the returned
/// builder before any other setter.
impl AuthorizationCodeGrant<()> {
    /// Returns a builder for an authorization code grant, with `IdClaims`
    /// defaulting to `()` (call [`with_id_claims`][AuthorizationCodeGrantBuilder::with_id_claims]
    /// to switch to a typed claim set).
    pub fn builder() -> AuthorizationCodeGrantBuilder<()> {
        Self::builder_internal()
    }

    /// Configure the grant from authorization server metadata.
    ///
    /// Returns `None` if `metadata.authorization_endpoint` is absent.
    #[must_use]
    pub fn builder_from_metadata(
        metadata: &crate::core::server_metadata::AuthorizationServerMetadata,
    ) -> Option<
        AuthorizationCodeGrantBuilder<(), AuthorizationCodeGrantBuilderFromMetadataInternalState>,
    > {
        Self::builder_from_metadata_internal(metadata)
    }
}

/// Builder-level `with_id_claims` — switches the `IdClaims` parameter of the
/// builder before any setter is called. Works because bon's experimental
/// `generics(setters(...))` on `fn new` generated `with_id_claims_internal`
/// to perform the type-state move.
impl<IdClaims: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static, S: State>
    AuthorizationCodeGrantBuilder<IdClaims, S>
{
    /// Sets the ID claims type for the authorization code grant.
    pub fn with_id_claims<C: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static>(
        self,
    ) -> AuthorizationCodeGrantBuilder<C, S> {
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

impl<IdClaims: Clone + for<'de> Deserialize<'de> + MaybeSendSync + 'static> OAuth2ExchangeGrant
    for AuthorizationCodeGrant<IdClaims>
{
    type Parameters = AuthorizationCodeGrantParameters;
    type Form<'a> = AuthorizationCodeGrantForm<'a>;

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> &dyn ClientAuthentication {
        self.client_auth.as_ref()
    }

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn mtls_token_endpoint(&self) -> Option<&EndpointUrl> {
        self.mtls_token_endpoint.as_ref()
    }

    fn dpop(&self) -> &dyn AuthorizationServerDPoP {
        self.dpop.as_ref()
    }

    fn http_client(&self) -> &dyn HttpClient {
        self.http_client.as_ref()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn bound_dpop_jkt(params: &Self::Parameters) -> Option<&str> {
        params.dpop_jkt.as_deref()
    }

    fn to_refresh_grant(&self) -> refresh::RefreshGrant {
        refresh::RefreshGrant::builder()
            .client_id(self.client_id.clone())
            .maybe_issuer(self.issuer.clone())
            .http_client(self.http_client.clone())
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_endpoint(self.token_endpoint.clone())
            .expect("an EndpointUrl converts to itself infallibly")
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
