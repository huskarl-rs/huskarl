//! RFC 7662 Token Introspection support.
//!
//! [`IntrospectionValidator`] validates access tokens by calling an authorization server's
//! token introspection endpoint, rather than validating JWT signatures locally.
//! This enables validation of opaque tokens and authoritative revocation status checks.
//!
//! Optionally supports RFC 9701 (JWT Response for Introspection) when a
//! `jws_verifier_factory` is provided.

pub mod error;

pub use error::IntrospectionValidateError;
use huskarl_core::jwk::JwksSource;
use huskarl_core::server_metadata::AuthorizationServerMetadata;

use std::marker::PhantomData;
use std::sync::Arc;

use http::HeaderName;
use serde::Deserialize;
use snafu::ResultExt as _;

use crate::core::BoxedError;
use crate::core::EndpointUrl;
use crate::core::client_auth::ClientAuthentication;
use crate::core::crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform};
use crate::core::http::HttpClient;
use crate::core::platform::{Duration, MaybeSendSync};
use crate::introspection::TokenIntrospection;
use crate::validator::binding::DPoPBindingChecker;
use crate::validator::binding::check_token_binding;
use crate::validator::extract::extract_token;
use crate::validator::introspection::error::{BindingSnafu, CallSnafu, ExtractSnafu};
use crate::validator::introspection::introspection_validator_builder::SetIntrospectionEndpoint;
use crate::validator::introspection::introspection_validator_builder::SetIssuer;
use crate::validator::introspection::introspection_validator_builder::SetJwksUri;
use crate::validator::introspection::introspection_validator_builder::State;
use crate::validator::{
    AccessTokenValidator, ValidatedRequest,
    metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    observe::{OnValidate, ValidationOutcome},
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
pub struct IntrospectionValidator<Auth: ClientAuthentication, C: HttpClient, Claims> {
    token_introspection: TokenIntrospection<Auth>,
    http_client: C,
    dpop_binding_checker: DPoPBindingChecker,
    token_header: HeaderName,
    client_id: String,
    on_validate: Option<Arc<dyn OnValidate>>,
    issuer: Option<String>,
    require_mtls: bool,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<
    Auth: ClientAuthentication,
    C: HttpClient + Clone + 'static,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
> IntrospectionValidator<Auth, C, Claims>
{
    /// Creates a new [`IntrospectionValidator`].
    #[builder(
        start_fn(vis = "", name = "builder_internal"),
        generics(setters(vis = "", name = "with_{}_internal"))
    )]
    pub async fn new(
        /// The client ID of this resource server, used for authenticating to the introspection
        /// endpoint.
        #[builder(into)]
        client_id: String,
        /// The issuer URL of the authorization server.
        ///
        /// Used for client authentication methods that require an audience (e.g.
        /// `private_key_jwt`) and for RFC 9701 JWT response issuer (`iss`) validation.
        #[builder(into)]
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
        #[builder(default = false)]
        require_dpop: bool,
        /// If `true`, tokens without a `cnf.x5t#S256` certificate binding are rejected.
        ///
        /// Advertised as `tls_client_certificate_bound_access_tokens` in RFC 9728 metadata.
        #[builder(default = false)]
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
        /// Receives the [`ValidationOutcome`] and the `client_id` identifying this validator.
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
                max_proof_age: max_dpop_proof_age,
                jws_verifier_platform,
                allowed_signing_algorithms: allowed_dpop_signing_algorithms,
                required: require_dpop,
            },
            token_header,
            client_id,
            on_validate,
            issuer,
            require_mtls,
            _phantom: PhantomData,
        })
    }
}

impl<
    Auth: ClientAuthentication,
    C: HttpClient + Clone + 'static,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
    S: State,
> IntrospectionValidatorBuilder<Auth, C, Claims, S>
{
    /// Sets the claims type for the introspection validator.
    pub fn with_claims<Claims1: Clone + for<'de> Deserialize<'de> + 'static>(
        self,
    ) -> IntrospectionValidatorBuilder<Auth, C, Claims1, S> {
        self.with_claims_internal()
    }
}

impl<Auth: ClientAuthentication, C: HttpClient + Clone + 'static>
    IntrospectionValidator<Auth, C, ()>
{
    /// Creates a builder for [`IntrospectionValidator`].
    ///
    /// Call [`.with_claims::<T>()`][IntrospectionValidatorBuilder::with_claims] on the builder
    /// to specify a custom claims type. The default is `()` (no extra claims).
    pub fn builder() -> IntrospectionValidatorBuilder<Auth, C, ()> {
        IntrospectionValidator::builder_internal()
    }
}

impl<Auth: ClientAuthentication, C: HttpClient + Clone + 'static>
    IntrospectionValidator<Auth, C, ()>
{
    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `jwks_uri` and `authorization_server` from the metadata. Validation
    /// rules are implemented by the authorization server. Call
    /// `.with_claims::<MyClaims>()` to use a custom claims type.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        IntrospectionValidatorBuilder<Auth, C, (), SetJwksUri<SetIntrospectionEndpoint<SetIssuer>>>,
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

impl<Auth: ClientAuthentication, C: HttpClient, Claims: for<'de> Deserialize<'de> + Clone + 'static>
    IntrospectionValidator<Auth, C, Claims>
{
    /// Returns metadata describing how this validator is configured.
    ///
    /// See [`ProvideValidatorMetadata`] for use in generic contexts.
    pub fn validator_metadata(&self) -> ValidatorMetadata {
        ValidatorMetadata {
            authorization_servers: self.issuer.as_ref().map(|s| vec![s.clone()]),
            dpop_signing_alg_values_supported: self
                .dpop_binding_checker
                .allowed_signing_algorithms
                .clone(),
            dpop_bound_access_tokens_required: Some(self.dpop_binding_checker.required),
            resource: None,
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
    ) -> Result<
        Option<ValidatedRequest<Claims>>,
        IntrospectionValidateError<
            <Auth as ClientAuthentication>::Error,
            C::Error,
            C::ResponseError,
        >,
    > {
        let result = self
            .validate_inner(headers, http_method, http_uri, client_cert_der)
            .await;

        if let Some(cb) = &self.on_validate {
            use crate::introspection::IntrospectionCallError;
            let outcome = match &result {
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
            cb.on_validate(outcome, &self.client_id);
        }

        result
    }

    async fn validate_inner(
        &self,
        headers: &http::HeaderMap,
        http_method: &http::Method,
        http_uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> Result<
        Option<ValidatedRequest<Claims>>,
        IntrospectionValidateError<
            <Auth as ClientAuthentication>::Error,
            C::Error,
            C::ResponseError,
        >,
    > {
        // 1. Extract token
        let Some((token_type, access_token)) =
            extract_token(headers, &self.token_header).context(ExtractSnafu)?
        else {
            return Ok(None);
        };

        // 2. Introspect (checks active internally)
        let validated = self
            .token_introspection
            .introspect::<_, Claims>(&self.http_client, &access_token)
            .await
            .context(CallSnafu { token_type })?;

        // 3. Binding check
        check_token_binding(
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
        .await
        .context(BindingSnafu { token_type })?;

        Ok(Some(validated))
    }
}

impl<Auth: ClientAuthentication, C: HttpClient, Claims: for<'de> Deserialize<'de> + Clone + 'static>
    ProvideValidatorMetadata for IntrospectionValidator<Auth, C, Claims>
{
    fn validator_metadata(&self) -> ValidatorMetadata {
        self.validator_metadata()
    }
}

impl<
    Auth: ClientAuthentication,
    C: HttpClient,
    Claims: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static,
> AccessTokenValidator for IntrospectionValidator<Auth, C, Claims>
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
    ) -> Result<Option<ValidatedRequest<Self::Claims>>, Self::Error> {
        self.validate_request(headers, method, uri, client_cert_der)
            .await
    }
}
