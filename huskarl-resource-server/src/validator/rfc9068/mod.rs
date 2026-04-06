//! RFC 9068 JWT profile for OAuth 2.0 access tokens.

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
use http::HeaderName;
use serde::Deserialize;

use crate::{
    AccessTokenValidator,
    validator::{
        ValidationResult,
        binding::DPoPBindingChecker,
        common::ValidatorInner,
        dpop_nonce::DpopNonceChecker,
        error::ValidateHeadersError,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        observe::{OnValidate, ValidationOutcome},
    },
};

/// A validator for RFC 9068 JWT access tokens.
///
/// Enforces all RFC 9068 §2.2 requirements: `typ`, `iss`, `exp`, `aud`,
/// `sub`, `iat`, `jti`, and `client_id` (via deserialization into
/// [`Rfc9068AccessTokenClaims`]). The `Extra` type parameter captures any
/// additional claims your authorization server includes beyond the standard set.
///
/// For authorization servers that do not issue RFC 9068-compliant tokens, use
/// [`crate::validator::custom::CustomValidator`] instead.
pub struct Rfc9068Validator<N: DpopNonceChecker, Extra = HashMap<String, serde_json::Value>> {
    inner: ValidatorInner<N>,
    issuer: String,
    audience: String,
    on_validate: Option<Arc<dyn OnValidate>>,
    _phantom: PhantomData<Extra>,
}

#[bon::bon]
impl<N: DpopNonceChecker, Extra: for<'de> Deserialize<'de> + Clone + 'static>
    Rfc9068Validator<N, Extra>
{
    /// Creates a new [`Rfc9068Validator`].
    ///
    /// For a more convenient constructor when you have authorization server metadata,
    /// see [`Rfc9068Validator::builder_from_metadata`].
    #[builder(
        start_fn(vis = "", name = "builder_internal"),
        generics(setters(vis = "", name = "with_{}_internal"))
    )]
    pub async fn new(
        /// The issuer URL of the authorization server.
        ///
        /// Required for exact issuer matching per RFC 9068 §4.
        #[builder(into)]
        issuer: String,
        /// The expected audience value.
        #[builder(into)]
        audience: String,
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
        /// JWKS URI for fetching the authorization server's signing keys.
        jwks_uri: Option<EndpointUrl>,
        /// Factory for creating JWS verifiers for access token signature verification.
        jws_verifier_factory: Arc<dyn JwsVerifierFactory>,
        /// Cryptographic platform for JWS verification.
        ///
        /// Used for both access token and DPoP proof verification. When the
        /// `default-jws-verifier-platform` feature is enabled, defaults to the platform default.
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        /// JTI uniqueness checker.
        jti_checker: Option<BoxedJtiUniquenessChecker>,
        /// DPoP nonce checker.
        dpop_nonce_checker: N,
        /// JTI uniqueness checker.
        dpop_jti_checker: Option<BoxedJtiUniquenessChecker>,
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
            .aud(ClaimCheck::required_value(&audience))
            .maybe_allowed_algorithms(allowed_signing_algorithms)
            .typ(ClaimCheck::required_value("at+jwt"))
            .iss(ClaimCheck::required_value(&issuer))
            .require_exp(true)
            .require_iat(true)
            .sub(ClaimCheck::present())
            .require_jti(jti_checker.is_some())
            .maybe_jti_checker(jti_checker)
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
            issuer,
            audience,
            on_validate,
            _phantom: PhantomData,
        })
    }
}

impl<N: DpopNonceChecker> Rfc9068Validator<N, ()> {
    /// Creates a builder for [`Rfc9068Validator`].
    ///
    /// Call [`.with_extra::<T>()`][Rfc9068ValidatorBuilder::with_extra] on the builder
    /// to specify a custom extra claims type. The default is `()` (no extra claims).
    pub fn builder() -> Rfc9068ValidatorBuilder<N, ()> {
        Rfc9068Validator::builder_internal()
    }
}

impl<
    N: DpopNonceChecker,
    Extra: for<'de> Deserialize<'de> + Clone + 'static,
    S: rfc9068_validator_builder::State,
> Rfc9068ValidatorBuilder<N, Extra, S>
{
    /// Sets the extra claims type for the validator.
    pub fn with_extra<Extra1: for<'de> Deserialize<'de> + Clone + 'static>(
        self,
    ) -> Rfc9068ValidatorBuilder<N, Extra1, S> {
        self.with_extra_internal()
    }
}

impl<N: DpopNonceChecker> Rfc9068Validator<N, ()> {
    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `issuer` and `jwks_uri` from the metadata.
    /// Call `.with_extra::<MyExtra>()` on the builder to use a custom extra claims type.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Rfc9068ValidatorBuilder<
        N,
        (),
        rfc9068_validator_builder::SetJwksUri<rfc9068_validator_builder::SetIssuer>,
    > {
        Self::builder()
            .issuer(metadata.issuer.clone())
            .maybe_jwks_uri(metadata.jwks_uri.clone())
    }
}

impl<N: DpopNonceChecker, Extra: for<'de> Deserialize<'de> + Clone + 'static>
    Rfc9068Validator<N, Extra>
{
    /// Returns metadata describing how this validator is configured.
    ///
    /// See [`ProvideValidatorMetadata`] for use in generic contexts.
    pub fn validator_metadata(&self) -> ValidatorMetadata {
        ValidatorMetadata {
            realm: None,
            authorization_servers: Some(vec![self.issuer.clone()]),
            dpop_signing_alg_values_supported: self
                .inner
                .dpop_binding_checker
                .allowed_signing_algorithms
                .clone(),
            dpop_bound_access_tokens_required: Some(self.inner.dpop_binding_checker.required),
            resource: Some(self.audience.clone()),
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
    ) -> ValidationResult<Rfc9068AccessTokenClaims<Extra>, ValidateHeadersError> {
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
            cb.on_validate(validation_outcome, &self.audience);
        }

        result
    }
}

impl<N: DpopNonceChecker, Extra: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static>
    AccessTokenValidator for Rfc9068Validator<N, Extra>
{
    type Claims = Rfc9068AccessTokenClaims<Extra>;
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

impl<N: DpopNonceChecker, Extra: for<'de> Deserialize<'de> + Clone + 'static>
    ProvideValidatorMetadata for Rfc9068Validator<N, Extra>
{
    fn validator_metadata(&self) -> ValidatorMetadata {
        self.validator_metadata()
    }
}

/// Claims for an RFC 9068 JWT access token.
///
/// RFC 9068 §2.2 requires the following claims to be present in the token:
/// `iss`, `exp`, `aud`, `sub`, `iat`, `jti`, and `client_id`. If your
/// authorization server does not include all of these — in particular `client_id`
/// — it is not issuing RFC 9068-compliant tokens. In that case, use
/// [`crate::validator::custom::CustomValidator`] with a claims type suited to your AS.
///
/// `Extra` captures any additional claims beyond the RFC 9068 standard set.
/// RFC 9068 §2.2.3.1 describes `groups`, `roles`, and `entitlements` claims and
/// recommends a specific encoding for them, but does not make it mandatory.
/// Therefore, you should use the `Extra` type parameter to capture these claims
/// in whatever shape your authorization server emits.
#[derive(Debug, Deserialize, Clone)]
#[serde(bound(deserialize = "Extra: for<'d> Deserialize<'d>"))]
pub struct Rfc9068AccessTokenClaims<Extra = HashMap<String, serde_json::Value>> {
    /// The client identifier for the OAuth 2.0 client that requested this token.
    ///
    /// Required by RFC 9068 §2.2. Deserialization of this claims type will fail
    /// if this field is absent — this is intentional, as its absence indicates
    /// the token was not issued by an RFC 9068-compliant authorization server.
    pub client_id: String,
    /// Time of the end-user authentication, as a Unix timestamp (RFC 9068 §2.2.1).
    pub auth_time: Option<u64>,
    /// Authentication context class reference (RFC 9068 §2.2.1).
    pub acr: Option<String>,
    /// Authentication methods references (RFC 9068 §2.2.1).
    #[serde(default)]
    pub amr: Vec<String>,
    /// Space-separated list of scopes associated with the token (RFC 9068 §2.2.3).
    pub scope: Option<String>,
    /// Additional claims beyond the RFC 9068 standard set.
    #[serde(flatten)]
    pub extra: Option<Extra>,
}
