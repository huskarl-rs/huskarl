//! Custom access token validator for non-RFC-9068 authorization servers.
//!
//! Use [`CustomValidator`] when your authorization server issues JWT access
//! tokens that do not conform to RFC 9068. Validation rules are configured via
//! [`AccessTokenValidationRules`] or through individual builder methods such as
//! `.audience()`, `.issuer()`, and `.subject()`. For RFC 9068-compliant
//! authorization servers, use [`crate::validator::rfc9068::Rfc9068Validator`].
//!
//! For a step-by-step setup walkthrough see the [custom validator
//! guide](crate::_docs::guide::custom); for picking between the validators see
//! [choosing a validator](crate::_docs::explanation::choosing_a_validator).

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
        dpop_nonce::DPoPNonceChecker,
        dpop_proof::DPoPProofValidator,
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
    realm: Option<String>,
    resource_metadata: Option<String>,
    on_validate: Option<Arc<dyn OnValidate>>,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> CustomValidator<Claims> {
    /// Creates a new [`CustomValidator`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the [`JwsVerifierFactory`] fails to build a
    /// verifier — for example, when the JWKS cannot be fetched or parsed.
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
        /// Allowed algorithms for `DPoP` proof signature verification.
        ///
        /// If `None`, any algorithm supported by the verifier is accepted.
        #[builder(into)]
        allowed_dpop_signing_algorithms: Option<Vec<String>>,
        /// Maximum accepted age of a `DPoP` proof. Defaults to 1 minute.
        #[builder(default = Duration::from_mins(1))]
        max_dpop_proof_age: Duration,
        /// Clock-skew leeway for the temporal checks on access tokens and
        /// `DPoP` proofs (RFC 9449 §11.1). Defaults to
        /// [`DEFAULT_CLOCK_LEEWAY`](super::DEFAULT_CLOCK_LEEWAY).
        #[builder(default = super::DEFAULT_CLOCK_LEEWAY)]
        clock_leeway: Duration,
        /// If `true`, Bearer tokens are rejected — all tokens must be DPoP-bound.
        ///
        /// Advertised as `dpop_bound_access_tokens_required` in RFC 9728 metadata.
        #[builder(default)]
        require_dpop: bool,
        /// If `true`, tokens without a `cnf.x5t#S256` certificate binding are rejected.
        ///
        /// When `true`, advertised as `tls_client_certificate_bound_access_tokens`
        /// in RFC 9728 metadata.
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
        /// `DPoP` nonce checker.
        #[builder(with = |checker: impl DPoPNonceChecker + 'static| Arc::new(checker) as Arc<dyn DPoPNonceChecker>)]
        dpop_nonce_checker: Option<Arc<dyn DPoPNonceChecker>>,
        /// `DPoP` JTI uniqueness checker.
        dpop_jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
        /// Cryptographic platform for JWS verification.
        ///
        /// Used for both access token and `DPoP` proof verification. When the
        /// `default-jws-verifier-platform` feature is enabled, defaults to the platform default.
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        /// The HTTP header to extract the access token from.
        ///
        /// Defaults to `Authorization`.
        #[builder(default = http::header::AUTHORIZATION)]
        token_header: HeaderName,
        /// The realm identifying the protection space (RFC 6750 §3).
        ///
        /// Included as `realm="..."` in the `WWW-Authenticate` challenges built
        /// from this validator's [metadata](Self::validator_metadata).
        realm: Option<String>,
        /// URL of this resource's Protected Resource Metadata document (RFC 9728).
        ///
        /// Included as `resource_metadata="..."` in the `WWW-Authenticate`
        /// challenges built from this validator's
        /// [metadata](Self::validator_metadata), so clients can discover the
        /// document (RFC 9728 §5.1).
        resource_metadata: Option<String>,
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
            .clock_leeway(clock_leeway)
            .build();

        Ok(Self {
            inner: ValidatorInner {
                jwt_validator,
                dpop_binding_checker: DPoPBindingChecker {
                    dpop_nonce_checker,
                    proof_validator: DPoPProofValidator::builder()
                        .jws_verifier_platform(jws_verifier_platform)
                        .max_proof_age(max_dpop_proof_age)
                        .clock_leeway(clock_leeway)
                        .maybe_allowed_signing_algorithms(allowed_dpop_signing_algorithms)
                        .maybe_jti_checker(dpop_jti_checker)
                        .build(),
                    required: require_dpop,
                },
                token_header,
                require_mtls,
            },
            authorization_server,
            realm,
            resource_metadata,
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
    pub fn token_type(mut self, typ: impl Into<ClaimCheck>) -> Self {
        self.rules.typ = typ.into();
        self
    }

    /// Check on the `iss` claim. Defaults to requiring presence.
    pub fn issuer(mut self, iss: impl Into<ClaimCheck>) -> Self {
        self.rules.iss = iss.into();
        self
    }

    /// Check on the `aud` claim. Defaults to no check.
    pub fn audience(mut self, aud: impl Into<ClaimCheck>) -> Self {
        self.rules.aud = aud.into();
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
    pub fn subject(mut self, sub: impl Into<ClaimCheck>) -> Self {
        self.rules.sub = sub.into();
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

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> crate::core::platform::MaybeSendBoxFuture<'a, ValidationResult<Self::Claims, Self::Error>>
    {
        Box::pin(self.validate_request(headers, method, uri, client_cert_der))
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> CustomValidator<Claims> {
    /// Returns metadata describing how this validator is configured.
    ///
    /// See [`ProvideValidatorMetadata`] for use in generic contexts.
    pub fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        ValidatorMetadata {
            realm: self.realm.clone(),
            authorization_servers: self.authorization_server.as_ref().map(|s| vec![s.clone()]),
            dpop_supported: Some(true),
            dpop_signing_alg_values_supported: self
                .inner
                .dpop_binding_checker
                .proof_validator
                .allowed_signing_algorithms()
                .map(<[_]>::to_vec),
            dpop_bound_access_tokens_required: Some(self.inner.dpop_binding_checker.required),
            // Only a hard mTLS requirement proves support: whether TLS
            // termination presents client certificates is deployment knowledge.
            tls_client_certificate_bound_access_tokens: self.inner.require_mtls.then_some(true),
            resource: resource.map(std::borrow::ToOwned::to_owned),
            bearer_methods_supported: Some(vec!["header"]),
            resource_metadata: self.resource_metadata.clone(),
        }
    }

    /// Validates the request headers, returning a [`ValidationResult`] whose
    /// [`outcome`](super::ValidationResult::outcome) is `Ok(Some(_))` for a valid
    /// token, `Ok(None)` when no authentication was presented, or `Err(_)` when a
    /// token was present but invalid. Any configured `on_validate` callback fires
    /// before returning.
    ///
    /// `http_uri` must be the absolute external target URI the client
    /// addressed, not a framework request object's origin-form path — see
    /// [`AccessTokenValidator::validate_request`]
    /// for the `DPoP` `htu` contract.
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

/// Validation rules for non-RFC-9068-compliant access tokens, used with
/// [`CustomValidator`] to opt out of strict RFC 9068 validation.
///
/// Set rules through the individual builder setters (e.g. `.require_jti(false)`,
/// `.issuer(ClaimCheck::NoCheck)`) or pass a complete value via `.rules(...)`;
/// the per-field defaults are shown below.
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
