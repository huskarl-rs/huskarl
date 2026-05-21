//! RFC 7662 Token Introspection support.
//!
//! [`IntrospectionValidator`] validates access tokens by calling an authorization server's
//! token introspection endpoint, rather than validating JWT signatures locally.
//! This enables validation of opaque tokens and authoritative revocation status checks.
//!
//! Optionally supports RFC 9701 (JWT Response for Introspection) when a
//! `jws_verifier_factory` is provided.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! A HTTP client needs to be configured. Using the `huskarl_reqwest` crate:
//!
//! ```rust
//! use huskarl_reqwest::{ReqwestClient, mtls::NoMtls};
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().mtls(NoMtls).build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 2. Set up client authentication
//!
//! The introspection endpoint requires the resource server to authenticate to the
//! authorization server. This example uses a client secret, but any
//! `ClientAuthentication` implementation can be used.
//!
//! ```rust
//! use huskarl_resource_server::core::{
//!     client_auth::ClientSecret,
//!     secrets::{EnvVarSecret, encodings::StringEncoding},
//! };
//!
//! # async fn setup_client_auth() -> Result<(), Box<dyn std::error::Error>> {
//! let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! let client_auth: ClientSecret<EnvVarSecret> = ClientSecret::new(client_secret);
//! # Ok(())
//! # }
//! ```
//!
//! ## 3a. Build the validator from authorization server metadata
//!
//! Note: `builder_from_metadata` returns `None` if the server does not advertise
//! an introspection endpoint.
//!
//! ```rust
//! use huskarl_resource_server::core::{
//!     client_auth::ClientSecret,
//!     secrets::{EnvVarSecret, encodings::StringEncoding},
//!     server_metadata::AuthorizationServerMetadata,
//! };
//! use huskarl_resource_server::validator::introspection::IntrospectionValidator;
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().mtls(NoMtls).build().await?;
//! # let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//!
//! let metadata = AuthorizationServerMetadata::builder()
//!     .issuer("https://my-issuer")
//!     .http_client(&http_client)
//!     .build()
//!     .await?;
//!
//! let validator = IntrospectionValidator::builder_from_metadata(&metadata)
//!     .expect("authorization server does not support token introspection")
//!     .client_id("my-resource-server")
//!     .client_auth(ClientSecret::new(client_secret))
//!     .http_client(http_client.clone())
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 3b. Alternative: Build without authorization server metadata
//!
//! ```rust
//! use huskarl_resource_server::core::{
//!     IntoEndpointUrl as _,
//!     client_auth::ClientSecret,
//!     secrets::{EnvVarSecret, encodings::StringEncoding},
//! };
//! use huskarl_resource_server::validator::introspection::IntrospectionValidator;
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().mtls(NoMtls).build().await?;
//! # let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//!
//! let validator = IntrospectionValidator::builder()
//!     .client_id("my-resource-server")
//!     .issuer("https://my-issuer")
//!     .introspection_endpoint(
//!         "https://my-issuer/oauth/introspect".into_endpoint_url()?,
//!     )
//!     .client_auth(ClientSecret::new(client_secret))
//!     .http_client(http_client.clone())
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Validate a request
//!
//! Call [`IntrospectionValidator::validate_request`] with the HTTP request headers, method,
//! and URI. The [`outcome`][crate::validator::ValidationResult::outcome] field of the result is:
//! - `Ok(None)` — no authentication header was present
//! - `Ok(Some(_))` — the token was active; the request is authenticated
//! - `Err(_)` — a token was present but inactive or the introspection call failed
//!
//! ```rust
//! # use huskarl_resource_server::core::{
//! #     client_auth::ClientSecret,
//! #     secrets::{EnvVarSecret, encodings::StringEncoding},
//! #     server_metadata::AuthorizationServerMetadata,
//! # };
//! # use huskarl_resource_server::validator::introspection::IntrospectionValidator;
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().mtls(NoMtls).build().await?;
//! # let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let metadata = AuthorizationServerMetadata::builder().issuer("https://my-issuer").http_client(&http_client).build().await?;
//! # let validator = IntrospectionValidator::builder_from_metadata(&metadata).expect("").client_id("my-resource-server").client_auth(ClientSecret::new(client_secret)).http_client(http_client.clone()).build().await?;
//! use http::{HeaderValue, Method, Uri, header::AUTHORIZATION};
//!
//! let mut headers = http::HeaderMap::new();
//! headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer mF_9.B5f-4.1JqM"));
//! let method = Method::GET;
//! let uri = Uri::from_static("https://api.example.com/resource");
//!
//! let result = validator.validate_request(&headers, &method, &uri, None).await;
//!
//! match result.outcome {
//!     Ok(Some(validated)) => println!("Authenticated: subject={:?}", validated.subject),
//!     Ok(None) => println!("No authentication provided"),
//!     Err(e) => println!("Introspection failed: {e}"),
//! }
//! # Ok(())
//! # }
//! ```

pub mod error;

use std::{marker::PhantomData, sync::Arc};

pub use error::IntrospectionValidateError;
use http::HeaderName;
use serde::Deserialize;
use snafu::ResultExt as _;

use crate::{
    core::{
        BoxedError, EndpointUrl,
        client_auth::ClientAuthentication,
        crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
        http::HttpClient,
        jwk::JwksSource,
        jwt::BoxedJtiUniquenessChecker,
        platform::{Duration, MaybeSendSync},
        server_metadata::AuthorizationServerMetadata,
    },
    introspection::TokenIntrospection,
    validator::{
        AccessTokenValidator, ValidatedRequest, ValidationResult,
        binding::{DPoPBindingChecker, check_token_binding},
        dpop_nonce::{DpopNonceChecker, NoNonceCheck},
        dpop_proof::DpopProofValidator,
        extract::extract_token,
        introspection::{
            error::{BindingSnafu, CallSnafu, ExtractSnafu},
            introspection_validator_builder::{
                SetDpopNonceChecker, SetIntrospectionEndpoint, SetIssuer, SetJwksUri, State,
            },
        },
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        observe::{OnValidate, ValidationOutcome},
    },
};

/// Validates access tokens by calling an authorization server's RFC 7662 token introspection
/// endpoint.
///
/// Supports both opaque tokens and JWT tokens. Optionally supports RFC 9701
/// (JWT Response for Introspection) when configured with a `jws_verifier_factory`.
///
/// Supports DPoP token binding validation when configured with a `jws_verifier_platform`.
///
/// Use [`IntrospectionValidator::builder`] to construct an instance.
pub struct IntrospectionValidator<
    Auth: ClientAuthentication,
    C: HttpClient,
    N: DpopNonceChecker,
    Claims = (),
> {
    token_introspection: TokenIntrospection<Auth>,
    http_client: C,
    dpop_binding_checker: DPoPBindingChecker<N>,
    token_header: HeaderName,
    on_validate: Option<Arc<dyn OnValidate>>,
    issuer: Option<String>,
    require_mtls: bool,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<
    Auth: ClientAuthentication,
    C: HttpClient + Clone + 'static,
    N: DpopNonceChecker,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
> IntrospectionValidator<Auth, C, N, Claims>
{
    /// Creates a new [`IntrospectionValidator`].
    #[builder(
        start_fn(vis = "", name = "builder_internal"),
        generics(setters(vis = "", name = "with_{}_internal")),
        on(String, into)
    )]
    pub async fn new(
        /// The client ID of this resource server, used for authenticating to the introspection
        /// endpoint.
        client_id: String,
        /// The issuer URL of the authorization server.
        ///
        /// Used for client authentication methods that require an audience (e.g.
        /// `private_key_jwt`) and for RFC 9701 JWT response issuer (`iss`) validation.
        issuer: Option<String>,
        /// The URL of the token introspection endpoint.
        introspection_endpoint: EndpointUrl,
        /// The client authentication strategy.
        client_auth: Auth,
        /// If `true`, adds `Accept: application/token-introspection+jwt` to introspection
        /// requests, requesting an RFC 9701 JWT response.
        ///
        /// The AS may still respond with JSON even when this is `true`.
        #[builder(default)]
        request_jwt_response: bool,
        /// HTTP client for calling the introspection endpoint (also used by default to get JWKS keys).
        http_client: C,
        /// Allowed algorithms for DPoP proof signature verification.
        ///
        /// If `None`, any algorithm supported by the verifier is accepted.
        #[builder(into)]
        allowed_dpop_signing_algorithms: Option<Vec<String>>,
        /// Maximum accepted age of a DPoP proof. Defaults to 60 seconds.
        #[builder(default = Duration::from_secs(60))]
        max_dpop_proof_age: Duration,
        /// If `true`, Bearer tokens are rejected — all tokens must be DPoP-bound.
        ///
        /// Advertised as `dpop_bound_access_tokens_required` in RFC 9728 metadata.
        #[builder(default)]
        require_dpop: bool,
        /// If `true`, tokens without a `cnf.x5t#S256` certificate binding are rejected.
        ///
        /// Advertised as `tls_client_certificate_bound_access_tokens` in RFC 9728 metadata.
        #[builder(default)]
        require_mtls: bool,
        /// JWKS URI for RFC 9701 JWT response validation.
        ///
        /// Must be provided together with `jws_verifier_factory` to enable JWT response
        /// validation.
        jwks_uri: Option<EndpointUrl>,
        /// Cryptographic platform for JWS verification.
        ///
        /// Used for JWT response (RFC 9701) and DPoP proof verification. When the
        /// `default-jws-verifier-platform` feature is enabled, defaults to the platform default.
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        /// DPoP nonce checker.
        #[builder(setters(vis = "", name = "dpop_nonce_checker_internal"))]
        dpop_nonce_checker: Option<N>,
        /// DPoP JTI uniqueness checker.
        dpop_jti_checker: Option<BoxedJtiUniquenessChecker>,
        /// JWS verifier factory for RFC 9701 JWT response validation.
        ///
        /// When provided (along with `jwks_uri`), a [`JwtValidator`] is built that validates
        /// the outer JWT of introspection responses with content type
        /// `application/token-introspection+jwt`. If the AS returns a JWT response without a
        /// validator configured, [`IntrospectionCallError::UnexpectedJwtResponse`] is returned.
        ///
        /// [`JwtValidator`]: crate::core::token::validator::JwtValidator
        #[builder(default = Arc::new(JwksSource::builder().http_client(http_client.clone()).build()))]
        jws_verifier_factory: Arc<dyn JwsVerifierFactory>,
        /// The HTTP header to extract the access token from.
        ///
        /// Defaults to `Authorization`.
        #[builder(default = http::header::AUTHORIZATION)]
        token_header: HeaderName,
        /// Optional callback invoked after each [`validate_request`](Self::validate_request) call.
        ///
        /// Use this to record metrics, emit log events, or trigger alerts.
        on_validate: Option<Arc<dyn OnValidate>>,
    ) -> Result<Self, BoxedError> {
        let token_introspection = TokenIntrospection::builder()
            .client_id(client_id.clone())
            .maybe_issuer(issuer.clone())
            .introspection_endpoint(introspection_endpoint)
            .client_auth(client_auth)
            .request_jwt_response(request_jwt_response)
            .maybe_jwks_uri(jwks_uri)
            .jws_verifier_factory(jws_verifier_factory)
            .jws_verifier_platform(jws_verifier_platform.clone())
            .build()
            .await?;

        Ok(Self {
            token_introspection,
            http_client,
            dpop_binding_checker: DPoPBindingChecker {
                dpop_nonce_checker,
                proof_validator: DpopProofValidator::builder()
                    .jws_verifier_platform(jws_verifier_platform)
                    .max_proof_age(max_dpop_proof_age)
                    .maybe_allowed_signing_algorithms(allowed_dpop_signing_algorithms)
                    .maybe_jti_checker(dpop_jti_checker)
                    .build(),
                required: require_dpop,
            },
            token_header,
            on_validate,
            issuer,
            require_mtls,
            _phantom: PhantomData,
        })
    }
}

impl<Auth: ClientAuthentication, C: HttpClient + Clone + 'static>
    IntrospectionValidator<Auth, C, NoNonceCheck, ()>
{
    /// Creates a builder for [`IntrospectionValidator`].
    ///
    /// Call [`.with_claims::<T>()`][IntrospectionValidatorBuilder::with_claims] on the builder
    /// to specify a custom claims type. The default is `()` (no extra claims).
    pub fn builder() -> IntrospectionValidatorBuilder<Auth, C, NoNonceCheck, ()> {
        IntrospectionValidator::builder_internal()
    }

    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `jwks_uri` and `authorization_server` from the metadata. Validation
    /// rules are implemented by the authorization server. Call
    /// `.with_claims::<MyClaims>()` to use a custom claims type.
    #[allow(clippy::type_complexity)]
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        IntrospectionValidatorBuilder<
            Auth,
            C,
            NoNonceCheck,
            (),
            SetJwksUri<SetIntrospectionEndpoint<SetIssuer>>,
        >,
    > {
        metadata
            .introspection_endpoint
            .as_ref()
            .map(|introspection_endpoint| {
                Self::builder()
                    .issuer(metadata.issuer.clone())
                    .introspection_endpoint(introspection_endpoint.clone())
                    .maybe_jwks_uri(metadata.jwks_uri.clone())
            })
    }
}

impl<
    Auth: ClientAuthentication,
    C: HttpClient + Clone + 'static,
    N: DpopNonceChecker,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
    S: State,
> IntrospectionValidatorBuilder<Auth, C, N, Claims, S>
{
    /// Sets the claims type for the validator.
    pub fn with_claims<Claims1: for<'de> Deserialize<'de> + Clone + 'static>(
        self,
    ) -> IntrospectionValidatorBuilder<Auth, C, N, Claims1, S> {
        self.with_claims_internal()
    }

    /// Sets the DPoP nonce checker for the validator.
    pub fn dpop_nonce_checker<N1: DpopNonceChecker>(
        self,
        dpop_nonce_checker: N1,
    ) -> IntrospectionValidatorBuilder<Auth, C, N1, Claims, SetDpopNonceChecker<S>>
    where
        S::DpopNonceChecker: introspection_validator_builder::IsUnset,
    {
        self.with_n_internal()
            .dpop_nonce_checker_internal(dpop_nonce_checker)
    }
}

impl<
    Auth: ClientAuthentication,
    C: HttpClient,
    N: DpopNonceChecker,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
> IntrospectionValidator<Auth, C, N, Claims>
{
    /// Returns metadata describing how this validator is configured.
    ///
    /// The resource is the URL of the protected resource.
    ///
    /// See [`ProvideValidatorMetadata`] for use in generic contexts.
    pub fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        ValidatorMetadata {
            realm: None,
            authorization_servers: self.issuer.as_ref().map(|s| vec![s.clone()]),
            dpop_signing_alg_values_supported: self
                .dpop_binding_checker
                .proof_validator
                .allowed_signing_algorithms()
                .map(<[_]>::to_vec),
            dpop_bound_access_tokens_required: Some(self.dpop_binding_checker.required),
            resource: resource.map(|r| r.to_owned()),
            bearer_methods_supported: Some(vec!["header"]),
        }
    }

    /// Validates an access token by calling the introspection endpoint.
    ///
    /// Returns `Ok(None)` if no token was present in the request headers,
    /// `Ok(Some(_))` if the token was successfully validated, or `Err(_)` if
    /// a token was present but invalid.
    pub async fn validate_request(
        &self,
        headers: &http::HeaderMap,
        http_method: &http::Method,
        http_uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> ValidationResult<
        Claims,
        IntrospectionValidateError<
            <Auth as ClientAuthentication>::Error,
            C::Error,
            C::ResponseError,
        >,
    > {
        let (dpop_nonce, outcome) = self
            .validate_inner(headers, http_method, http_uri, client_cert_der)
            .await;

        if let Some(cb) = &self.on_validate {
            use crate::introspection::IntrospectionCallError;
            let validation_outcome = match &outcome {
                Ok(Some(_)) => ValidationOutcome::Success,
                Ok(None) => ValidationOutcome::NoToken,
                Err(IntrospectionValidateError::Extract { .. }) => ValidationOutcome::ExtractError,
                Err(IntrospectionValidateError::Binding { .. }) => ValidationOutcome::BindingError,
                Err(IntrospectionValidateError::Call { source, .. }) => {
                    if matches!(source, IntrospectionCallError::TokenInactive) {
                        ValidationOutcome::InvalidToken
                    } else {
                        ValidationOutcome::CallError
                    }
                }
            };
            cb.on_validate(validation_outcome);
        }

        ValidationResult {
            outcome,
            dpop_nonce,
        }
    }

    async fn validate_inner(
        &self,
        headers: &http::HeaderMap,
        http_method: &http::Method,
        http_uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> (
        Option<String>,
        Result<
            Option<ValidatedRequest<Claims>>,
            IntrospectionValidateError<
                <Auth as ClientAuthentication>::Error,
                C::Error,
                C::ResponseError,
            >,
        >,
    ) {
        // 1. Extract token
        let (token_type, access_token) =
            match extract_token(headers, &self.token_header).context(ExtractSnafu) {
                Err(e) => return (None, Err(e)),
                Ok(None) => return (None, Ok(None)),
                Ok(Some(v)) => v,
            };

        // 2. Introspect (checks active internally)
        let validated = match self
            .token_introspection
            .introspect::<_, Claims>(&self.http_client, &access_token)
            .await
            .context(CallSnafu { token_type })
        {
            Err(e) => return (None, Err(e)),
            Ok(v) => v,
        };

        // 3. Binding check
        let (dpop_nonce, binding_result) = check_token_binding(
            token_type,
            validated.cnf.as_ref(),
            &access_token,
            &self.dpop_binding_checker,
            self.require_mtls,
            headers,
            http_method,
            http_uri,
            client_cert_der,
        )
        .await;

        let outcome = binding_result
            .context(BindingSnafu { token_type })
            .map(|()| Some(validated));

        (dpop_nonce, outcome)
    }
}

impl<
    Auth: ClientAuthentication,
    C: HttpClient,
    N: DpopNonceChecker,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
> ProvideValidatorMetadata for IntrospectionValidator<Auth, C, N, Claims>
{
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.validator_metadata(resource)
    }
}

impl<
    Auth: ClientAuthentication,
    C: HttpClient,
    N: DpopNonceChecker,
    Claims: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static,
> AccessTokenValidator for IntrospectionValidator<Auth, C, N, Claims>
{
    type Claims = Claims;
    type Error = IntrospectionValidateError<
        <Auth as ClientAuthentication>::Error,
        C::Error,
        C::ResponseError,
    >;

    async fn validate_request(
        &self,
        headers: &http::HeaderMap,
        method: &http::Method,
        uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> ValidationResult<Self::Claims, Self::Error> {
        self.validate_request(headers, method, uri, client_cert_der)
            .await
    }
}
