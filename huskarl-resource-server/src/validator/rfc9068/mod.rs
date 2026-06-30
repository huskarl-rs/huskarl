//! RFC 9068 JWT profile for OAuth 2.0 access tokens.
//!
//! [`Rfc9068Validator`] verifies RFC 9068 JWT access tokens locally against the
//! authorization server's published signing keys. For authorization servers
//! that do not issue RFC 9068-compliant tokens, see [`crate::validator::custom`].
//!
//! For a step-by-step setup walkthrough see the [RFC 9068
//! guide](crate::_docs::guide::rfc9068); for picking between the validators see
//! [choosing a validator](crate::_docs::explanation::choosing_a_validator).

use std::{marker::PhantomData, sync::Arc, time::Duration};

use http::HeaderName;
use serde::{Deserialize, Serialize};

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
        dpop_nonce::DpopNonceChecker,
        dpop_proof::DpopProofValidator,
        error::ValidateHeadersError,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        observe::{OnValidate, ValidationOutcome},
    },
};

/// A validator for RFC 9068 JWT access tokens.
///
/// Enforces the RFC 9068 §2.2 requirements: `typ`, `iss`, `exp`, `aud`, `sub`,
/// `iat`, and `client_id` (the last via deserialization into
/// [`Rfc9068AccessTokenClaims`]). Presence of `jti` is enforced only when a
/// `jti_checker` is configured (for replay protection); without one, a token
/// missing `jti` still validates. The `Claims` type parameter captures any
/// additional claims your authorization server includes beyond the standard set.
///
/// For authorization servers that do not issue RFC 9068-compliant tokens, use
/// [`crate::validator::custom::CustomValidator`] instead.
pub struct Rfc9068Validator<Claims = ()> {
    inner: ValidatorInner,
    issuer: String,
    on_validate: Option<Arc<dyn OnValidate>>,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> Rfc9068Validator<Claims> {
    /// Creates a new [`Rfc9068Validator`].
    ///
    /// For a more convenient constructor when you have authorization server metadata,
    /// see [`Rfc9068Validator::builder_from_metadata`].
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
        /// The issuer URL of the authorization server.
        ///
        /// Required for exact issuer matching per RFC 9068 §4.
        issuer: String,
        /// The expected audience value.
        audience: String,
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
        /// JWKS URI for fetching the authorization server's signing keys.
        jwks_uri: Option<EndpointUrl>,
        /// Factory for creating JWS verifiers for access token signature verification.
        jws_verifier_factory: Arc<dyn JwsVerifierFactory>,
        /// Cryptographic platform for JWS verification.
        ///
        /// Used for both access token and `DPoP` proof verification. When the
        /// `default-jws-verifier-platform` feature is enabled, defaults to the platform default.
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        /// Access token JTI uniqueness checker.
        jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
        /// Optional server-side `DPoP` nonce enforcement (RFC 9449 §8). When set,
        /// proofs must carry a nonce this checker accepts; omitting it disables
        /// nonce enforcement.
        #[builder(with = |checker: impl DpopNonceChecker + 'static| Arc::new(checker) as Arc<dyn DpopNonceChecker>)]
        dpop_nonce_checker: Option<Arc<dyn DpopNonceChecker>>,
        /// Uniqueness checker for the `jti` of `DPoP` proofs (replay protection) —
        /// the proof-level counterpart to `jti_checker`.
        dpop_jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
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
            issuer,
            on_validate,
            _phantom: PhantomData,
        })
    }
}

impl Rfc9068Validator<()> {
    /// Creates a builder for [`Rfc9068Validator`].
    ///
    /// Call [`.with_claims::<T>()`][Rfc9068ValidatorBuilder::with_claims] on the builder
    /// to specify a custom claims type. The default is `()` (no extra claims).
    pub fn builder() -> Rfc9068ValidatorBuilder<()> {
        Rfc9068Validator::builder_internal()
    }

    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `issuer` and `jwks_uri` from the metadata.
    /// Call `.with_claims::<MyClaims>()` on the builder to use a custom claims type.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Rfc9068ValidatorBuilder<
        (),
        rfc9068_validator_builder::SetJwksUri<rfc9068_validator_builder::SetIssuer>,
    > {
        Self::builder()
            .issuer(metadata.issuer.clone())
            .maybe_jwks_uri(metadata.jwks_uri.clone())
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static, S: rfc9068_validator_builder::State>
    Rfc9068ValidatorBuilder<Claims, S>
{
    /// Captures access-token claims beyond the RFC 9068 set into a custom type,
    /// surfaced on the validated request. The default is `()` (no extra claims);
    /// see [`Rfc9068AccessTokenClaims`].
    pub fn with_claims<Claims1: for<'de> Deserialize<'de> + Clone + 'static>(
        self,
    ) -> Rfc9068ValidatorBuilder<Claims1, S> {
        self.with_claims_internal()
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> Rfc9068Validator<Claims> {
    /// Returns metadata describing how this validator is configured.
    ///
    /// The resource is the URL of the protected resource.
    ///
    /// See [`ProvideValidatorMetadata`] for use in generic contexts.
    pub fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        ValidatorMetadata {
            realm: None,
            authorization_servers: Some(vec![self.issuer.clone()]),
            dpop_signing_alg_values_supported: self
                .inner
                .dpop_binding_checker
                .proof_validator
                .allowed_signing_algorithms()
                .map(<[_]>::to_vec),
            dpop_bound_access_tokens_required: Some(self.inner.dpop_binding_checker.required),
            resource: resource.map(std::borrow::ToOwned::to_owned),
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
    ) -> ValidationResult<Rfc9068AccessTokenClaims<Claims>, ValidateHeadersError> {
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

impl<ExtraClaims: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static> AccessTokenValidator
    for Rfc9068Validator<ExtraClaims>
{
    type Claims = Rfc9068AccessTokenClaims<ExtraClaims>;
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

impl<ExtraClaims: for<'de> Deserialize<'de> + Clone + 'static> ProvideValidatorMetadata
    for Rfc9068Validator<ExtraClaims>
{
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.validator_metadata(resource)
    }
}

/// Claims for an RFC 9068 JWT access token (RFC 9068 §2.2).
///
/// `ExtraClaims` captures any claims beyond the standard set — including
/// `groups`/`roles`/`entitlements` (§2.2.3.1) — in whatever shape your
/// authorization server emits. If a server omits required claims such as
/// `client_id`, it is not RFC 9068-compliant; use
/// [`crate::validator::custom::CustomValidator`] instead.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "ExtraClaims: for<'d> Deserialize<'d>"))]
pub struct Rfc9068AccessTokenClaims<ExtraClaims = ()> {
    /// The client that requested this token. Required by RFC 9068 §2.2;
    /// deserialization fails if absent, since its absence means the token is not
    /// RFC 9068-compliant.
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
    /// Claims beyond the RFC 9068 standard set (e.g. RFC 9396
    /// `authorization_details`), captured via the caller-supplied `ExtraClaims`.
    #[serde(flatten)]
    pub extra_claims: ExtraClaims,
}
