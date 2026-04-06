//! Custom access token validator builder.

use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

use crate::core::{
    BoxedError, EndpointUrl,
    crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
    jwt::{
        BoxedJtiUniquenessChecker,
        validator::{ClaimCheck, JwtValidator},
    },
    platform::MaybeSendSync,
    server_metadata::AuthorizationServerMetadata,
};
use bon::Builder;
use http::HeaderName;
use serde::Deserialize;

use crate::{
    AccessTokenValidator,
    validator::{
        ValidationResult,
        binding::DPoPBindingChecker,
        common::ValidatorInner,
        custom::custom_validator_builder::{SetAuthorizationServer, SetJwksUri},
        dpop_nonce::DpopNonceChecker,
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
pub struct CustomValidator<N: DpopNonceChecker, Claims = HashMap<String, serde_json::Value>> {
    inner: ValidatorInner<N>,
    authorization_server: Option<String>,
    audience: Option<String>,
    on_validate: Option<Arc<dyn OnValidate>>,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<N: DpopNonceChecker, Claims: for<'de> Deserialize<'de> + Clone + 'static>
    CustomValidator<N, Claims>
{
    /// Creates a new [`CustomValidator`].
    #[builder(
        start_fn(vis = "", name = "builder_internal"),
        generics(setters(vis = "", name = "with_{}_internal"))
    )]
    pub async fn new(
        /// Validation rules for the access token.
        rules: AccessTokenValidationRules,
        /// The expected audience value.
        ///
        /// Per RFC 7519, the `aud` claim is optional. When set, tokens that include an `aud`
        /// claim must contain this value; tokens without `aud` are accepted.
        #[builder(into)]
        audience: Option<String>,
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
        #[builder(default = false)]
        require_dpop: bool,
        /// If `true`, tokens without a `cnf.x5t#S256` certificate binding are rejected.
        ///
        /// Advertised as `tls_client_certificate_bound_access_tokens` in RFC 9728 metadata.
        #[builder(default = false)]
        require_mtls: bool,
        /// The issuer URI of the authorization server, for RFC 9728 metadata.
        ///
        /// If provided, included in [`ValidatorMetadata::authorization_servers`].
        /// Independent of the `iss` check in [`AccessTokenValidationRules`].
        #[builder(into)]
        authorization_server: Option<String>,
        /// JWKS URI for fetching the authorization server's signing keys.
        jwks_uri: Option<EndpointUrl>,
        /// Factory for creating JWS verifiers for access token signature verification.
        jws_verifier_factory: Arc<dyn JwsVerifierFactory>,
        token_jti_checker: Option<BoxedJtiUniquenessChecker>,
        /// DPoP nonce checker.
        dpop_nonce_checker: N,
        /// DPoP JTI uniqueness checker.
        dpop_jti_checker: Option<BoxedJtiUniquenessChecker>,
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
        /// Receives the [`ValidationOutcome`] and the audience string identifying this validator.
        /// Use this to record metrics, emit log events, or trigger alerts.
        on_validate: Option<Arc<dyn OnValidate>>,
    ) -> Result<Self, BoxedError> {
        let jws_verifier = jws_verifier_factory
            .build(jwks_uri.as_ref(), jws_verifier_platform.clone())
            .await?;

        let token_validator = JwtValidator::builder()
            .verifier(jws_verifier)
            .aud(
                audience
                    .as_deref()
                    .map_or(ClaimCheck::NoCheck, ClaimCheck::if_present),
            )
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
                token_validator,
                dpop_binding_checker: DPoPBindingChecker {
                    dpop_nonce_checker,
                    dpop_jti_checker,
                    max_proof_age: max_dpop_proof_age,
                    jws_verifier_platform,
                    allowed_signing_algorithms: allowed_dpop_signing_algorithms,
                    required: require_dpop,
                },
                token_header,
                require_mtls,
            },
            authorization_server,
            audience,
            on_validate,
            _phantom: PhantomData,
        })
    }
}

impl<N: DpopNonceChecker> CustomValidator<N, ()> {
    /// Creates a builder for [`CustomValidator`].
    ///
    /// Call [`.with_claims::<T>()`][CustomValidatorBuilder::with_claims] on the builder
    /// to specify a custom claims type. The default is `()` (no extra claims).
    pub fn builder() -> CustomValidatorBuilder<N, ()> {
        CustomValidator::builder_internal()
    }
}

impl<
    N: DpopNonceChecker,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
    S: custom_validator_builder::State,
> CustomValidatorBuilder<N, Claims, S>
{
    /// Sets the claims type for the validator.
    pub fn with_claims<Claims1: for<'de> Deserialize<'de> + Clone + 'static>(
        self,
    ) -> CustomValidatorBuilder<N, Claims1, S> {
        self.with_claims_internal()
    }
}

impl<N: DpopNonceChecker> CustomValidator<N, ()> {
    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `jwks_uri` and `authorization_server` from the metadata. Issuer
    /// validation is configured via [`AccessTokenValidationRules`] rather than
    /// inferred from metadata, since non-RFC-9068 authorization servers may require
    /// different issuer handling. Call `.with_claims::<MyClaims>()` to use a custom
    /// claims type.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> CustomValidatorBuilder<N, (), SetJwksUri<SetAuthorizationServer>> {
        Self::builder()
            .authorization_server(metadata.issuer.clone())
            .maybe_jwks_uri(metadata.jwks_uri.clone())
    }
}

impl<N: DpopNonceChecker, Claims: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static>
    AccessTokenValidator for CustomValidator<N, Claims>
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

impl<N: DpopNonceChecker, Claims: for<'de> Deserialize<'de> + Clone + 'static>
    CustomValidator<N, Claims>
{
    /// Returns metadata describing how this validator is configured.
    ///
    /// See [`ProvideValidatorMetadata`] for use in generic contexts.
    pub fn validator_metadata(&self) -> ValidatorMetadata {
        ValidatorMetadata {
            realm: None,
            authorization_servers: self.authorization_server.as_ref().map(|s| vec![s.clone()]),
            dpop_signing_alg_values_supported: self
                .inner
                .dpop_binding_checker
                .allowed_signing_algorithms
                .clone(),
            dpop_bound_access_tokens_required: Some(self.inner.dpop_binding_checker.required),
            resource: self.audience.clone(),
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
            cb.on_validate(validation_outcome, self.audience.as_deref().unwrap_or(""));
        }

        result
    }
}

impl<N: DpopNonceChecker, Claims: for<'de> Deserialize<'de> + Clone + 'static>
    ProvideValidatorMetadata for CustomValidator<N, Claims>
{
    fn validator_metadata(&self) -> ValidatorMetadata {
        self.validator_metadata()
    }
}

/// Validation rules for non-RFC-9068-compliant access tokens.
///
/// Used with [`CustomValidator`] to opt out of strict RFC 9068
/// validation. Boolean checks default to `true`; claim checks default to `NoCheck`.
#[derive(Debug, Clone, Builder)]
#[allow(clippy::should_implement_trait)]
pub struct AccessTokenValidationRules {
    /// Check the `typ` header. Defaults to no check.
    #[builder(default)]
    pub(super) typ: ClaimCheck,
    /// Check on the `iss` claim. Defaults to requiring presence.
    #[builder(default = ClaimCheck::Present)]
    pub(super) iss: ClaimCheck,
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
