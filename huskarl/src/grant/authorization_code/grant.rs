use std::{collections::HashSet, sync::Arc};

use bon::Builder;
use serde::Serialize;

use crate::{
    core::{
        EndpointUrl, Error, RetryAdvice,
        client_auth::ClientAuthentication,
        crypto::{
            signer::AsymmetricJwsSignerSelector,
            verifier::{JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform},
        },
        dpop::{AuthorizationServerDPoP, NoDPoP},
        http::HttpClient,
        jwk::{JwksSource, JwksStartup},
    },
    grant::{
        authorization_code::{
            jar::{Jar, NoJar},
            types::ResponseMode,
        },
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

    /// The mTLS alias for the token endpoint (RFC 8705 §5). Retained alongside
    /// the resolved `effective_token_endpoint` so a derived grant can re-resolve
    /// it rather than inherit a flattened endpoint pair.
    pub(super) mtls_token_endpoint: Option<EndpointUrl>,

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
    /// The builder rejects setting this without a
    /// `pushed_authorization_request_endpoint`, so when it is `true` an
    /// endpoint is guaranteed to be present.
    /// Extra labels applied to this grant's metrics.
    #[cfg(feature = "metrics")]
    pub(super) metric_labels: Vec<::metrics::Label>,

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
    pub redirect_uri: String,

    /// Whether PKCE (RFC 7636) is disabled; see the `new` builder.
    pub(super) disable_pkce: bool,

    /// Whether flows on this grant follow OIDC semantics; `None` infers from
    /// the request scope containing `openid`. See the `new` builder.
    pub(super) oidc: Option<bool>,

    /// Whether to send the OIDC `nonce` parameter; `None` follows the grant's
    /// OIDC-ness (see `oidc`). See the `new` builder.
    pub(super) send_oidc_nonce: Option<bool>,

    /// The `response_mode` sent on authorization requests; `None` omits the
    /// parameter. See the `new` builder.
    pub(super) response_mode: Option<ResponseMode>,

    /// Set to true to prefer PAR when available.
    pub(super) prefer_pushed_authorization_requests: bool,

    /// If set, restricts accepted ID token signature algorithms; see the `new`
    /// builder.
    pub(super) allowed_id_token_signed_response_algs: Option<HashSet<String>>,

    /// If set, restricts accepted JARM response signature algorithms; see the
    /// `new` builder.
    pub(super) allowed_authorization_signed_response_algs: Option<HashSet<String>>,
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

    /// Binds a per-session `DPoP` key, returning a grant that signs with it.
    ///
    /// Derived grants share the grant's server-scoped `DPoP` nonce, so one
    /// grant per authorization server serves every session. Bind the same key
    /// before [`start`](Self::start) and [`complete`](Self::complete);
    /// `complete` rejects a key that differs from the one bound at
    /// authorization time.
    ///
    /// # Errors
    ///
    /// Returns an error unless the configured `DPoP` is
    /// [`SessionKeyedDPoP`](crate::core::dpop::SessionKeyedDPoP).
    pub fn with_session_dpop_key(
        &self,
        key: impl AsymmetricJwsSignerSelector + 'static,
    ) -> Result<Self, Error> {
        Ok(Self {
            dpop: self.dpop.with_session_key(Arc::new(key))?,
            ..self.clone()
        })
    }
}

/// Resolves the grant's JWS verifier: a supplied factory as-is, otherwise a
/// default [`JwksSource`] built only when a verifier could be needed and a
/// `jwks_uri` is present.
async fn resolve_jws_verifier(
    factory: Option<Arc<dyn JwsVerifierFactory>>,
    platform: Option<Arc<dyn JwsVerifierPlatform>>,
    http_client: &Arc<dyn HttpClient>,
    jwks_uri: Option<&EndpointUrl>,
    oidc: Option<bool>,
    response_mode: Option<ResponseMode>,
) -> Result<Option<Arc<dyn JwsVerifier>>, Error> {
    let require_platform = |platform: Option<Arc<dyn JwsVerifierPlatform>>| {
        platform.ok_or_else(|| {
            Error::new(
                RetryAdvice::No,
                super::error::MissingJwsVerifierPlatformSnafu.build(),
            )
        })
    };

    // A supplied factory is honored as-is, `jwks_uri` or not (it may carry its
    // own keys — a KMS/enclave signer, or a static JWKS).
    if let Some(factory) = factory {
        let platform = require_platform(platform)?;
        return Ok(Some(factory.build(jwks_uri, platform).await?));
    }

    let jarm = response_mode.is_some_and(ResponseMode::is_jwt_secured);

    // `oidc(false)` without JARM declares the flow non-OIDC: build no default
    // verifier and fetch no JWKS. A surprise ID token is then rejected as
    // unvalidatable — supply a factory to validate one anyway. A missing
    // `jwks_uri` likewise leaves the default `JwksSource` with no key source.
    if (oidc == Some(false) && !jarm) || jwks_uri.is_none() {
        return Ok(None);
    }

    let platform = require_platform(platform)?;
    // Fail-fast only on declared need (`oidc(true)` or JARM). An inferred flow
    // (`oidc` unset — the scope decides at `start()`) is unknown at build time,
    // so come up lazily (`SeedEmpty`): a failed initial fetch is not fatal and
    // the verifier self-heals when a token first needs it.
    let startup = if oidc == Some(true) || jarm {
        JwksStartup::FailFast
    } else {
        JwksStartup::SeedEmpty
    };
    let default = JwksSource::builder()
        .http_client(Arc::clone(http_client))
        .startup(startup)
        .build();
    Ok(Some(default.build(jwks_uri, platform).await?))
}

#[huskarl_macros::from_metadata(
    metadata = crate::core::server_metadata::AuthorizationServerMetadata
)]
#[bon::bon]
impl AuthorizationCodeGrant {
    /// Configures an [`AuthorizationCodeGrant`].
    ///
    /// Callers use [`Self::builder()`], or [`Self::builder_from_metadata()`]
    /// to pre-populate the endpoint fields from server metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if a `jws_verifier_factory` is supplied without a
    /// `jws_verifier_platform`, if building the JWS verifier from `jwks_uri`
    /// fails, if `require_pushed_authorization_requests` is set without a
    /// `pushed_authorization_request_endpoint` (honoring the requirement would
    /// be impossible, and ignoring it would silently downgrade PAR), or if
    /// `oidc(true)` or a JWT-secured `response_mode` is set without a JWS
    /// verifier or issuer.
    #[builder(on(String, into), builder_type(doc {
        /// Configures an [`AuthorizationCodeGrant`].
        ///
        /// Required and optional inputs are marked on their setter methods.
        /// Prefer [`AuthorizationCodeGrant::builder_from_metadata`] when
        /// discovery metadata is available; it fills endpoints, issuer,
        /// supported algorithms, and protocol capability switches before
        /// returning this builder.
    }))]
    pub async fn new(
        /// Extra labels applied to this grant's metrics.
        #[cfg(feature = "metrics")]
        #[builder(default)]
        metric_labels: Vec<::metrics::Label>,
        /// The OAuth 2.0 client identifier registered with the authorization
        /// server.
        client_id: String,
        /// The transport used for discovery-backed JWKS loading, PAR, and token
        /// requests.
        #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
        http_client: Arc<dyn HttpClient>,
        /// How the client authenticates to the token and PAR endpoints.
        ///
        /// Use [`NoAuth`](crate::core::client_auth::NoAuth) for a public client
        /// that sends only its `client_id`.
        #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
        client_auth: Arc<dyn ClientAuthentication>,
        /// The `DPoP` signer. Defaults to [`NoDPoP`] (no token sender-constraining).
        #[builder(
            with = |dpop: impl AuthorizationServerDPoP + 'static| Arc::new(dpop) as Arc<dyn AuthorizationServerDPoP>,
            default = Arc::new(NoDPoP),
        )]
        dpop: Arc<dyn AuthorizationServerDPoP>,
        /// The authorization server's exact issuer identifier.
        ///
        /// It is required for OIDC, JARM, RFC 9207 response-issuer validation,
        /// and client-authentication methods that use the issuer as an
        /// assertion audience. [`builder_from_metadata`](Self::builder_from_metadata)
        /// supplies it from discovery metadata.
        #[from_metadata(path = "issuer")]
        issuer: Option<String>,
        /// The canonical token endpoint URL, before mTLS alias resolution.
        #[from_metadata(path = "token_endpoint")]
        token_endpoint: EndpointUrl,
        /// The mTLS alias for the token endpoint (RFC 8705 §5).
        #[from_metadata(path = "mtls_endpoint_aliases?.token_endpoint?")]
        mtls_token_endpoint: Option<EndpointUrl>,
        /// Authentication methods advertised for the token endpoint.
        ///
        /// [`ClientSecret`](crate::core::client_auth::ClientSecret) uses this
        /// list to choose HTTP Basic or form authentication. `None` leaves that
        /// choice unconstrained by metadata.
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
        /// The authorization server's JWKS endpoint.
        ///
        /// The default verifier loads keys from this endpoint. It may be
        /// omitted when a custom `jws_verifier_factory` supplies its own keys,
        /// or when neither OIDC nor JARM validation is used.
        #[from_metadata(path = "jwks_uri?")]
        jwks_uri: Option<EndpointUrl>,
        /// The endpoint to which the user agent is redirected to begin
        /// authorization.
        #[from_metadata(path = "authorization_endpoint?")]
        authorization_endpoint: EndpointUrl,
        /// The PAR endpoint (RFC 9126), when the server offers one.
        #[from_metadata(path = "pushed_authorization_request_endpoint?")]
        pushed_authorization_request_endpoint: Option<EndpointUrl>,
        /// The mTLS alias for the PAR endpoint (RFC 8705 §5).
        #[from_metadata(path = "mtls_endpoint_aliases?.pushed_authorization_request_endpoint?")]
        mtls_pushed_authorization_request_endpoint: Option<EndpointUrl>,
        /// Whether every authorization request must use PAR.
        ///
        /// Defaults to `false`. Building fails when this is `true` and no PAR
        /// endpoint is configured.
        #[from_metadata(path = "require_pushed_authorization_requests")]
        #[builder(default)]
        require_pushed_authorization_requests: bool,
        /// Whether the server promises RFC 9207 response-issuer support.
        ///
        /// Defaults to `false`. When enabled, every successful callback must
        /// contain `iss`, and it must exactly match `issuer`.
        #[from_metadata(path = "authorization_response_iss_parameter_supported")]
        #[builder(default)]
        authorization_response_iss_parameter_supported: bool,
        /// PKCE transformation methods the server advertises.
        ///
        /// Defaults to `S256`. `S256` is preferred whenever available; `plain`
        /// is used only when it is advertised without `S256`.
        #[from_metadata(path = "code_challenge_methods_supported")]
        #[builder(default = vec!["S256".to_string()])]
        code_challenge_methods_supported: Vec<String>,
        /// A redirect URI registered for this client.
        ///
        /// The same value is sent in the authorization and token requests.
        redirect_uri: String,
        /// Set to true to disable PKCE (RFC 7636) entirely.
        ///
        /// PKCE is otherwise always applied, as required by current best practice
        /// (RFC 9700 §2.1.1). Only disable it for an authorization server that
        /// rejects requests containing PKCE parameters.
        #[builder(default)]
        disable_pkce: bool,
        /// Overrides OIDC semantics, inferred by default from the request
        /// scope containing `openid`. An OIDC flow sends a `nonce`, requires
        /// ID-token validation to be configured at
        /// [`start`](AuthorizationCodeGrant::start), and requires an ID token
        /// in the token response (OIDC Core 1.0 §3.1.3.3) unless the server
        /// narrows `openid` out of the granted scope. `false`: `openid` is an
        /// ordinary scope (an ID token returned anyway is still validated).
        /// `true`: OIDC regardless of scope, and granted-scope narrowing no
        /// longer excuses a missing ID token.
        oidc: Option<bool>,
        /// Controls whether the OIDC `nonce` parameter (OIDC Core 1.0 §3.1.2.1)
        /// is sent in the authorization request. By default it follows the
        /// grant's OIDC-ness (see `oidc`); `true`/`false` force the wire
        /// parameter on or off without affecting ID-token semantics.
        send_oidc_nonce: Option<bool>,
        /// The `response_mode` authorization-request parameter
        /// ([`ResponseMode`]). `None` (the default) omits it, leaving the
        /// server's default for the flow — `query` for the code flow.
        response_mode: Option<ResponseMode>,
        /// Whether to use PAR whenever an endpoint is available.
        ///
        /// Defaults to `true`. Set it to `false` to send a normal authorization
        /// request unless the server requires PAR.
        #[builder(default = true)]
        prefer_pushed_authorization_requests: bool,
        /// Restricts accepted ID token signature algorithms to this set: the
        /// [`IdTokenValidator`](crate::token::id_token::IdTokenValidator) rejects
        /// any ID token whose `alg` header is not listed. Use a single-element
        /// set to pin one algorithm, or several to enforce a policy (e.g. the
        /// FAPI 2.0 set: PS256, ES256, `EdDSA`).
        ///
        /// [`builder_from_metadata`](Self::builder_from_metadata) seeds it from
        /// the server's `id_token_signing_alg_values_supported` (OIDC Discovery
        /// 1.0 §3), minus the insecure `none` (which is rejected
        /// unconditionally). The plain [`builder`](Self::builder) leaves it unset,
        /// accepting any algorithm the verifier supports.
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
        /// Restricts accepted JARM response signature algorithms to this set
        /// (see `response_mode`); any `alg` outside it is rejected.
        ///
        /// [`builder_from_metadata`](Self::builder_from_metadata) seeds it from
        /// the server's `authorization_signing_alg_values_supported` (JARM
        /// §4), minus the insecure `none` (which is rejected
        /// unconditionally). The plain [`builder`](Self::builder) leaves it unset,
        /// accepting any algorithm the verifier supports.
        #[from_metadata(
            with = |m: &crate::core::server_metadata::AuthorizationServerMetadata| m
                .authorization_signing_alg_values_supported
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
        allowed_authorization_signed_response_algs: Option<HashSet<String>>,
        /// Platform operations used by the JWS verifier.
        ///
        /// Required when the default verifier must load and verify keys and
        /// the crate has no platform-default verifier feature enabled.
        #[cfg(not(feature = "default-jws-verifier-platform"))]
        jws_verifier_platform: Option<Arc<dyn JwsVerifierPlatform>>,
        /// Platform operations used by the JWS verifier.
        ///
        /// Defaults to [`DefaultJwsVerifierPlatform`](crate::DefaultJwsVerifierPlatform).
        #[cfg(feature = "default-jws-verifier-platform")]
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        /// Factory that builds the JWS verifier for ID tokens (OIDC) and JARM
        /// responses.
        ///
        /// Defaults to a [`JwksSource`] wired from `http_client`: with a
        /// `jwks_uri`, verification is zero-config; without one, there is no
        /// verifier. A supplied factory is honored as-is, including with no
        /// `jwks_uri` (it may carry its own keys).
        #[builder(
            with = |factory: impl JwsVerifierFactory + 'static| Arc::new(factory) as Arc<dyn JwsVerifierFactory>,
        )]
        jws_verifier_factory: Option<Arc<dyn JwsVerifierFactory>>,
    ) -> Result<Self, Error> {
        #[cfg(feature = "default-jws-verifier-platform")]
        let jws_verifier_platform = Some(jws_verifier_platform);

        let jws_verifier = resolve_jws_verifier(
            jws_verifier_factory,
            jws_verifier_platform,
            &http_client,
            jwks_uri.as_ref(),
            oidc,
            response_mode,
        )
        .await?;

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

        // A grant that must use PAR (client policy, or AS metadata setting
        // `require_pushed_authorization_requests`) but has no endpoint to push
        // to could only ever proceed by silently downgrading to a plain
        // authorization request — fail construction instead.
        if require_pushed_authorization_requests && pushed_authorization_request_endpoint.is_none()
        {
            return Err(Error::new(
                RetryAdvice::No,
                super::error::RequiredParEndpointMissingSnafu.build(),
            ));
        }

        // `oidc(true)` declares every flow OIDC, so a grant that could never
        // validate the required ID token (OIDC Core 1.0 §3.1.3.3) fails
        // here; inferred (scope-based) flows are checked at `start`.
        if oidc == Some(true) {
            if jws_verifier.is_none() {
                return Err(Error::new(
                    RetryAdvice::No,
                    super::error::OidcRequiresVerifierSnafu.build(),
                ));
            }
            if issuer.is_none() {
                return Err(Error::new(
                    RetryAdvice::No,
                    super::error::OidcRequiresIssuerSnafu.build(),
                ));
            }
        }

        // A JWT-secured response mode makes every callback a JARM JWT, so a
        // grant that could never validate one fails here.
        if response_mode.is_some_and(ResponseMode::is_jwt_secured) {
            if jws_verifier.is_none() {
                return Err(Error::new(
                    RetryAdvice::No,
                    super::error::JarmRequiresVerifierSnafu.build(),
                ));
            }
            if issuer.is_none() {
                return Err(Error::new(
                    RetryAdvice::No,
                    super::error::JarmRequiresIssuerSnafu.build(),
                ));
            }
        }

        Ok(AuthorizationCodeGrant {
            client_id,
            http_client,
            client_auth,
            dpop,
            issuer,
            token_endpoint,
            mtls_token_endpoint,
            effective_token_endpoint,
            token_endpoint_auth_methods_supported,
            jws_verifier,
            jar,
            authorization_endpoint,
            pushed_authorization_request_endpoint,
            #[cfg(feature = "metrics")]
            metric_labels,
            require_pushed_authorization_requests,
            authorization_response_iss_parameter_supported,
            code_challenge_methods_supported,
            redirect_uri,
            disable_pkce,
            oidc,
            send_oidc_nonce,
            response_mode,
            prefer_pushed_authorization_requests,
            allowed_id_token_signed_response_algs,
            allowed_authorization_signed_response_algs,
        })
    }
}

/// Parameters passed to each token request.
#[derive(Debug, Clone, Builder)]
#[builder(on(String, into))]
pub struct AuthorizationCodeGrantParameters {
    /// The bound `DPoP` JWT thumbprint, if any has already been computed.
    pub(super) dpop_jkt: Option<String>,
    /// The temporary authorization code received from the redirect callback.
    pub(super) code: String,
    /// The PKCE verifier.
    pub(super) pkce_verifier: Option<String>,
    /// The target resource(s) for the access token.
    pub(super) resource: Option<Vec<String>>,
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

    fn jws_verifier(&self) -> Option<Arc<dyn JwsVerifier>> {
        self.jws_verifier.clone()
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
            .maybe_mtls_token_endpoint(self.mtls_token_endpoint.clone())
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
