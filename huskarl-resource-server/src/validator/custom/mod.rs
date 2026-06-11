//! Custom access token validator for non-RFC-9068 authorization servers.
//!
//! Use [`CustomValidator`] when your authorization server issues JWT access tokens that
//! do not conform to RFC 9068. Validation rules are configured via
//! [`AccessTokenValidationRules`] or through individual builder methods such as
//! `.audience()`, `.issuer()`, and `.subject()`. For RFC 9068-compliant authorization
//! servers, use [`crate::validator::rfc9068::Rfc9068Validator`] instead.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! A HTTP client needs to be configured. Using the `huskarl_reqwest` crate:
//!
//! ```rust
//! use huskarl_reqwest::ReqwestClient;
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 2a. Build the validator from authorization server metadata
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use huskarl_resource_server::{
//!     core::{
//!         jwk::JwksSource, jwt::validator::ClaimCheck,
//!         server_metadata::AuthorizationServerMetadata,
//!     },
//!     validator::custom::CustomValidator,
//! };
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//!
//! let metadata = AuthorizationServerMetadata::fetch()
//!     .http_client(&http_client)
//!     .issuer("https://my-issuer")
//!     .call()
//!     .await?;
//!
//! let validator = CustomValidator::builder_from_metadata(&metadata)
//!     .audience(ClaimCheck::required_value("api://my-resource"))
//!     .jws_verifier_factory(Arc::new(
//!         JwksSource::builder()
//!             .http_client(http_client.clone())
//!             .build(),
//!     ))
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 2b. Alternative: Build without authorization server metadata
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use huskarl_resource_server::{
//!     core::{IntoEndpointUrl as _, jwk::JwksSource, jwt::validator::ClaimCheck},
//!     validator::custom::CustomValidator,
//! };
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//!
//! let validator = CustomValidator::builder()
//!     .authorization_server("https://my-issuer")
//!     .audience(ClaimCheck::required_value("api://my-resource"))
//!     .jwks_uri("https://my-issuer/.well-known/jwks.json".into_endpoint_url()?)
//!     .jws_verifier_factory(Arc::new(
//!         JwksSource::builder()
//!             .http_client(http_client.clone())
//!             .build(),
//!     ))
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 3. Validate a request
//!
//! Call [`CustomValidator::validate_request`] with the HTTP request headers, method, and URI.
//! The [`outcome`][crate::validator::ValidationResult::outcome] field of the result is:
//! - `Ok(None)` — no authentication header was present
//! - `Ok(Some(_))` — a valid token was found; the request is authenticated
//! - `Err(_)` — a token was present but invalid
//!
//! ```rust
//! # use std::sync::Arc;
//! # use huskarl_resource_server::core::{
//! #     jwk::JwksSource,
//! #     jwt::validator::ClaimCheck,
//! #     server_metadata::AuthorizationServerMetadata,
//! # };
//! # use huskarl_resource_server::validator::custom::CustomValidator;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//! # let metadata = AuthorizationServerMetadata::fetch().http_client(&http_client).issuer("https://my-issuer").call().await?;
//! # let validator = CustomValidator::builder_from_metadata(&metadata).audience(ClaimCheck::required_value("api://my-resource")).jws_verifier_factory(Arc::new(JwksSource::builder().http_client(http_client.clone()).build())).build().await?;
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
//!     Err(e) => println!("Validation failed: {e}"),
//! }
//! # Ok(())
//! # }
//! ```

use std::{marker::PhantomData, sync::Arc, time::Duration};

use bon::Builder;
use http::HeaderName;
use serde::Deserialize;

use crate::{
    AccessTokenValidator,
    core::{
        EndpointUrl, Error,
        crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
        jwt::{
            JtiUniquenessChecker,
            validator::{ClaimCheck, JwtValidator},
        },
        platform::MaybeSendSync,
        server_metadata::AuthorizationServerMetadata,
    },
    validator::{
        ValidationResult,
        binding::DPoPBindingChecker,
        common::ValidatorInner,
        custom::custom_validator_builder::{SetAuthorizationServer, SetJwksUri},
        dpop_nonce::DpopNonceChecker,
        dpop_proof::DpopProofValidator,
        error::ValidateHeadersError,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        observe::{OnValidate, ValidationOutcome},
    },
};

/// A validator for access tokens from non-RFC-9068-compliant authorization servers.
///
/// Use [`AccessTokenValidationRules`] to configure which claims are required and how
/// they are validated. For RFC 9068-compliant authorization servers, prefer
/// [`crate::validator::rfc9068::Rfc9068Validator`].
pub struct CustomValidator<Claims = ()> {
    inner: ValidatorInner,
    authorization_server: Option<String>,
    on_validate: Option<Arc<dyn OnValidate>>,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> CustomValidator<Claims> {
    /// Creates a new [`CustomValidator`].
    #[builder(
        start_fn(vis = "", name = "builder_internal"),
        generics(setters(vis = "", name = "with_{}_internal")),
        on(String, into)
    )]
    pub async fn new(
        /// Validation rules for the access token.
        #[builder(field)]
        rules: AccessTokenValidationRules,
        /// Allowed algorithms for access token signature verification.
        ///
        /// If `None`, any algorithm supported by the verifier is accepted.
        #[builder(into)]
        allowed_signing_algorithms: Option<Vec<String>>,
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
        /// The issuer URI of the authorization server, for RFC 9728 metadata.
        ///
        /// If provided, included in [`ValidatorMetadata::authorization_servers`].
        /// Independent of the `iss` check in [`AccessTokenValidationRules`].
        authorization_server: Option<String>,
        /// JWKS URI for fetching the authorization server's signing keys.
        jwks_uri: Option<EndpointUrl>,
        /// Factory for creating JWS verifiers for access token signature verification.
        jws_verifier_factory: Arc<dyn JwsVerifierFactory>,
        /// Access token JTI uniqueness checker.
        token_jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
        /// DPoP nonce checker.
        #[builder(with = |checker: impl DpopNonceChecker + 'static| Arc::new(checker) as Arc<dyn DpopNonceChecker>)]
        dpop_nonce_checker: Option<Arc<dyn DpopNonceChecker>>,
        /// DPoP JTI uniqueness checker.
        dpop_jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
        /// Cryptographic platform for JWS verification.
        ///
        /// Used for both access token and DPoP proof verification. When the
        /// `default-jws-verifier-platform` feature is enabled, defaults to the platform default.
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        /// The HTTP header to extract the access token from.
        ///
        /// Defaults to `Authorization`.
        #[builder(default = http::header::AUTHORIZATION)]
        token_header: HeaderName,
        /// Optional callback invoked after each [`validate_request`](Self::validate_request) call.
        ///
        /// Use this to record metrics, emit log events, or trigger alerts.
        on_validate: Option<Arc<dyn OnValidate>>,
    ) -> Result<Self, Error> {
        let jws_verifier = jws_verifier_factory
            .build(jwks_uri.as_ref(), jws_verifier_platform.clone())
            .await?;

        let jwt_validator = JwtValidator::builder()
            .verifier(jws_verifier)
            .aud(rules.aud)
            .maybe_allowed_algorithms(allowed_signing_algorithms)
            .typ(rules.typ)
            .iss(rules.iss)
            .require_exp(rules.require_exp)
            .require_iat(rules.require_iat)
            .sub(rules.sub)
            .require_jti(rules.require_jti)
            .maybe_jti_checker(token_jti_checker)
            .build();

        Ok(Self {
            inner: ValidatorInner {
                jwt_validator,
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
                require_mtls,
            },
            authorization_server,
            on_validate,
            _phantom: PhantomData,
        })
    }
}

impl CustomValidator<()> {
    /// Creates a builder for [`CustomValidator`].
    ///
    /// Call [`.with_claims::<T>()`][CustomValidatorBuilder::with_claims] on the builder
    /// to specify a custom claims type. The default is `()` (no extra claims).
    pub fn builder() -> CustomValidatorBuilder<()> {
        CustomValidator::builder_internal()
    }

    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `jwks_uri` and `authorization_server` from the metadata. Issuer
    /// validation is configured via [`AccessTokenValidationRules`] rather than
    /// inferred from metadata, since non-RFC-9068 authorization servers may require
    /// different issuer handling. Call `.with_claims::<MyClaims>()` to use a custom
    /// claims type.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> CustomValidatorBuilder<(), SetJwksUri<SetAuthorizationServer>> {
        Self::builder()
            .authorization_server(metadata.issuer.clone())
            .maybe_jwks_uri(metadata.jwks_uri.clone())
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static, S: custom_validator_builder::State>
    CustomValidatorBuilder<Claims, S>
{
    /// Sets the claims type for the validator.
    pub fn with_claims<Claims1: for<'de> Deserialize<'de> + Clone + 'static>(
        self,
    ) -> CustomValidatorBuilder<Claims1, S> {
        self.with_claims_internal()
    }

    /// Replaces all validation rules at once.
    ///
    /// Overrides any individual rule setters called earlier on this builder.
    pub fn rules(mut self, rules: AccessTokenValidationRules) -> Self {
        self.rules = rules;
        self
    }

    /// Check the `typ` header. Defaults to no check.
    pub fn token_type(mut self, typ: ClaimCheck) -> Self {
        self.rules.typ = typ;
        self
    }

    /// Check on the `iss` claim. Defaults to requiring presence.
    pub fn issuer(mut self, iss: ClaimCheck) -> Self {
        self.rules.iss = iss;
        self
    }

    /// Check on the `aud` claim. Defaults to no check.
    pub fn audience(mut self, aud: ClaimCheck) -> Self {
        self.rules.aud = aud;
        self
    }

    /// Require the `exp` claim to be present. Defaults to `true`.
    pub fn require_exp(mut self, require_exp: bool) -> Self {
        self.rules.require_exp = require_exp;
        self
    }

    /// Require the `iat` claim to be present. Defaults to `true`.
    pub fn require_iat(mut self, require_iat: bool) -> Self {
        self.rules.require_iat = require_iat;
        self
    }

    /// Check on the `sub` claim. Defaults to requiring presence.
    pub fn subject(mut self, sub: ClaimCheck) -> Self {
        self.rules.sub = sub;
        self
    }

    /// Require the `jti` claim to be present. Defaults to `true`.
    pub fn require_jti(mut self, require_jti: bool) -> Self {
        self.rules.require_jti = require_jti;
        self
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static> AccessTokenValidator
    for CustomValidator<Claims>
{
    type Claims = Claims;
    type Error = ValidateHeadersError;

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

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> CustomValidator<Claims> {
    /// Returns metadata describing how this validator is configured.
    ///
    /// See [`ProvideValidatorMetadata`] for use in generic contexts.
    pub fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        ValidatorMetadata {
            realm: None,
            authorization_servers: self.authorization_server.as_ref().map(|s| vec![s.clone()]),
            dpop_signing_alg_values_supported: self
                .inner
                .dpop_binding_checker
                .proof_validator
                .allowed_signing_algorithms()
                .map(<[_]>::to_vec),
            dpop_bound_access_tokens_required: Some(self.inner.dpop_binding_checker.required),
            resource: resource.map(|r| r.to_owned()),
            bearer_methods_supported: Some(vec!["header"]),
        }
    }

    /// Validates the request headers, returning a [`super::ValidatedRequest`] if a valid token is found,
    /// or `None` if no authentication was provided.
    pub async fn validate_request(
        &self,
        headers: &http::HeaderMap,
        http_method: &http::Method,
        http_uri: &http::Uri,
        client_cert_der: Option<&[u8]>,
    ) -> ValidationResult<Claims, ValidateHeadersError> {
        let result = self
            .inner
            .validate_request(headers, http_method, http_uri, client_cert_der)
            .await;

        if let Some(cb) = &self.on_validate {
            let validation_outcome = match &result.outcome {
                Ok(Some(_)) => ValidationOutcome::Success,
                Ok(None) => ValidationOutcome::NoToken,
                Err(ValidateHeadersError::Extract { .. }) => ValidationOutcome::ExtractError,
                Err(ValidateHeadersError::InvalidJwt { .. }) => ValidationOutcome::InvalidToken,
                Err(ValidateHeadersError::Binding { .. }) => ValidationOutcome::BindingError,
            };
            cb.on_validate(validation_outcome);
        }

        result
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> ProvideValidatorMetadata
    for CustomValidator<Claims>
{
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.validator_metadata(resource)
    }
}

/// Validation rules for non-RFC-9068-compliant access tokens.
///
/// Used with [`CustomValidator`] to opt out of strict RFC 9068
/// validation. Boolean checks default to `true`; claim checks default to `NoCheck`.
///
/// When using [`CustomValidator::builder`] or [`CustomValidator::builder_from_metadata`],
/// all rules default to the values shown below. Use the individual rule setters on the
/// builder (e.g., `.require_jti(false)`, `.issuer(ClaimCheck::NoCheck)`) to customize, or
/// pass a complete `AccessTokenValidationRules` via `.rules(...)`.
#[derive(Debug, Clone, Builder)]
#[allow(clippy::should_implement_trait)]
pub struct AccessTokenValidationRules {
    /// Check the `typ` header. Defaults to no check.
    #[builder(default)]
    pub(super) typ: ClaimCheck,
    /// Check on the `iss` claim. Defaults to requiring presence.
    #[builder(default = ClaimCheck::Present)]
    pub(super) iss: ClaimCheck,
    /// Check on the `aud` claim. Defaults to no check.
    #[builder(default)]
    pub(super) aud: ClaimCheck,
    /// Require the `exp` claim to be present.
    #[builder(default = true)]
    pub(super) require_exp: bool,
    /// Require the `iat` claim to be present.
    #[builder(default = true)]
    pub(super) require_iat: bool,
    /// Check on the `sub` claim. Defaults to requiring presence.
    #[builder(default = ClaimCheck::Present)]
    pub(super) sub: ClaimCheck,
    /// Require the `jti` claim to be present.
    #[builder(default = true)]
    pub(super) require_jti: bool,
}

impl Default for AccessTokenValidationRules {
    fn default() -> Self {
        Self::builder().build()
    }
}
