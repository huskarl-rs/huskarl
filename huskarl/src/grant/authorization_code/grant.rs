use std::{collections::HashSet, sync::Arc};

use bon::Builder;
use serde::Serialize;

use crate::{
    core::{
        EndpointUrl, Error, ErrorKind,
        client_auth::ClientAuthentication,
        crypto::verifier::{JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform},
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
    },
    grant::{
        authorization_code::jar::{Jar, NoJar},
        core::OAuth2ExchangeGrant,
        refresh,
    },
};

/// The authorization code grant (RFC 6749 §4.1).
///
/// See the [module documentation][crate::grant::authorization_code] for a usage guide.
#[allow(clippy::struct_excessive_bools)] // independent protocol switches, not a state machine
#[derive(Clone)]
pub struct AuthorizationCodeGrant {
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

    /// The URL of the token endpoint, as published in authorization server
    /// metadata (before RFC 8705 §5 mTLS-alias resolution).
    pub(super) token_endpoint: EndpointUrl,

    /// The token endpoint used for token requests: the RFC 8705 §5 mTLS alias
    /// when the HTTP client uses mTLS, the primary token endpoint otherwise.
    pub(super) effective_token_endpoint: EndpointUrl,

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

    /// The pushed authorization request endpoint (RFC 9126 §5), resolved at
    /// build time to the RFC 8705 §5 mTLS alias when the HTTP client uses mTLS.
    pub(super) pushed_authorization_request_endpoint: Option<EndpointUrl>,

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
}

impl AuthorizationCodeGrant {
    /// The OAuth 2.0 client identifier this grant authenticates as.
    ///
    /// Exposed so callers can supply the `client_id` parameter for flows that
    /// need it outside the grant itself — notably OIDC RP-Initiated Logout,
    /// where it lets the OP identify the RP (and thus honor
    /// `post_logout_redirect_uri`) when no `id_token_hint` is available.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

#[huskarl_macros::from_metadata(
    metadata = crate::core::server_metadata::AuthorizationServerMetadata
)]
#[bon::bon]
impl AuthorizationCodeGrant {
    /// Creates a new [`AuthorizationCodeGrant`] instance.
    ///
    /// Callers use [`Self::builder()`], or [`Self::builder_from_metadata()`]
    /// to pre-populate the endpoint fields from server metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if a `jws_verifier_factory` is supplied without a
    /// `jws_verifier_platform`, or if building the JWS verifier from `jwks_uri`
    /// fails.
    #[builder(on(String, into))]
    pub async fn new(
        /// The client ID.
        client_id: String,
        /// The HTTP client used for token and PAR requests.
        #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
        http_client: Arc<dyn HttpClient>,
        /// The client authentication method.
        #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
        client_auth: Arc<dyn ClientAuthentication>,
        /// The `DPoP` signer. Defaults to [`NoDPoP`] (no token sender-constraining).
        #[builder(
            with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>,
            default = Arc::new(NoDPoP),
        )]
        dpop: Arc<dyn AuthorizationServerDPoP>,
        /// The issuer for tokens created by the authorization server.
        #[from_metadata(path = "issuer")]
        issuer: Option<String>,
        /// The URL of the token endpoint.
        #[from_metadata(path = "token_endpoint")]
        token_endpoint: EndpointUrl,
        /// The mTLS alias for the token endpoint (RFC 8705 §5).
        #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
        mtls_token_endpoint: Option<EndpointUrl>,
        /// Supported endpoint auth methods; used to auto-select basic or
        /// form auth for client secrets.
        #[from_metadata(path = "token_endpoint_auth_methods_supported")]
        token_endpoint_auth_methods_supported: Option<Vec<String>>,
        /// The [`Jar`] implementation used to JWT-secure the authorization
        /// request (RFC 9101). Defaults to [`NoJar`] — no request object; see the
        /// trait for what JAR provides and how to supply one.
        #[builder(
            with = |jar: impl Jar + 'static| Arc::new(jar) as Arc<dyn Jar>,
            default = Arc::new(NoJar),
        )]
        jar: Arc<dyn Jar>,
        #[from_metadata(path = "jwks_uri?")] jwks_uri: Option<EndpointUrl>,
        #[from_metadata(path = "authorization_endpoint?")] authorization_endpoint: EndpointUrl,
        #[from_metadata(path = "pushed_authorization_request_endpoint?")]
        pushed_authorization_request_endpoint: Option<EndpointUrl>,
        #[from_metadata(path = "mtls_endpoint_aliases?.pushed_authorization_request_endpoint?")]
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
        /// Restricts accepted ID token signature algorithms to this set.
        ///
        /// When built via
        /// [`builder_from_metadata`](Self::builder_from_metadata), this is
        /// seeded from the server's `id_token_signing_alg_values_supported`
        /// (OIDC Discovery 1.0 §3), pinning the ID-token `alg` to what the
        /// issuer advertises (the insecure `none` value is dropped, and is
        /// rejected unconditionally regardless). On the plain
        /// [`builder`](Self::builder) path it is unset unless supplied
        /// explicitly; left unset, any algorithm the verifier supports is
        /// accepted.
        #[from_metadata(
            with = |m: &crate::core::server_metadata::AuthorizationServerMetadata| m
                .id_token_signing_alg_values_supported
                .as_ref()
                .map(|algs| {
                    algs.iter()
                        .filter(|a| *a != "none")
                        .cloned()
                        .collect::<HashSet<String>>()
                })
                .filter(|algs| !algs.is_empty()),
            maybe
        )]
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

        let effective_token_endpoint = crate::grant::core::resolve_mtls_alias(
            http_client.as_ref(),
            &token_endpoint,
            mtls_token_endpoint.as_ref(),
        );
        let pushed_authorization_request_endpoint =
            pushed_authorization_request_endpoint.map(|par| {
                crate::grant::core::resolve_mtls_alias(
                    http_client.as_ref(),
                    &par,
                    mtls_pushed_authorization_request_endpoint.as_ref(),
                )
            });

        Ok(AuthorizationCodeGrant {
            client_id,
            http_client,
            client_auth,
            dpop,
            issuer,
            token_endpoint,
            effective_token_endpoint,
            token_endpoint_auth_methods_supported,
            jws_verifier,
            jar,
            authorization_endpoint,
            pushed_authorization_request_endpoint,
            require_pushed_authorization_requests,
            authorization_response_iss_parameter_supported,
            code_challenge_methods_supported,
            redirect_uri,
            disable_pkce,
            prefer_pushed_authorization_requests,
            allowed_id_token_signed_response_algs,
        })
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
    code_verifier: Option<String>,
    resource: Option<Vec<String>>,
}

impl OAuth2ExchangeGrant for AuthorizationCodeGrant {
    type Parameters = AuthorizationCodeGrantParameters;
    type Form<'a> = AuthorizationCodeGrantForm<'a>;

    fn client_id(&self) -> Option<&str> {
        Some(&self.client_id)
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn client_auth(&self) -> Option<&dyn ClientAuthentication> {
        Some(self.client_auth.as_ref())
    }

    fn token_endpoint(&self) -> &EndpointUrl {
        &self.token_endpoint
    }

    fn effective_token_endpoint(&self) -> &EndpointUrl {
        &self.effective_token_endpoint
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
            .token_endpoint(self.effective_token_endpoint.clone())
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
