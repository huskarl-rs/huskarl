//! RFC 9068 JWT profile for OAuth 2.0 access tokens.
//!
//! Validates RFC 9068 JWT access tokens using the authorization server's public keys.
//! For authorization servers that do not issue RFC 9068-compliant tokens, see
//! [`crate::validator::custom`] instead.
//!
//! # Usage
//!
//! ## 1. Set up your HTTP client
//!
//! A HTTP client needs to be configured. Using the `huskarl_reqwest` crate:
//!
//! ```rust
//! use huskarl_reqwest::ReqwestClient;
//! use huskarl_reqwest::mtls::NoMtls;
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder()
//!     .mtls(NoMtls)
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 2a. Build the validator from authorization server metadata
//!
//! ```rust
//! use std::sync::Arc;
//! use huskarl_resource_server::core::{
//!     jwk::JwksSource,
//!     server_metadata::AuthorizationServerMetadata,
//! };
//! use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().mtls(NoMtls).build().await?;
//!
//! let metadata = AuthorizationServerMetadata::builder()
//!     .issuer("https://my-issuer")
//!     .http_client(&http_client)
//!     .build()
//!     .await?;
//!
//! let validator = Rfc9068Validator::builder_from_metadata(&metadata)
//!     .audience("api://my-resource")
//!     .jws_verifier_factory(Arc::new(
//!         JwksSource::builder().http_client(http_client.clone()).build(),
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
//! use huskarl_resource_server::core::{IntoEndpointUrl as _, jwk::JwksSource};
//! use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().mtls(NoMtls).build().await?;
//!
//! let validator = Rfc9068Validator::builder()
//!     .issuer("https://my-issuer")
//!     .audience("api://my-resource")
//!     .jwks_uri("https://my-issuer/.well-known/jwks.json".into_endpoint_url()?)
//!     .jws_verifier_factory(Arc::new(
//!         JwksSource::builder().http_client(http_client.clone()).build(),
//!     ))
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 3. Validate a request
//!
//! Call [`Rfc9068Validator::validate_request`] with the HTTP request headers, method, and URI.
//! The [`outcome`][crate::validator::ValidationResult::outcome] field of the result is:
//! - `Ok(None)` — no authentication header was present
//! - `Ok(Some(_))` — a valid token was found; the request is authenticated
//! - `Err(_)` — a token was present but invalid
//!
//! ```rust
//! # use std::sync::Arc;
//! # use huskarl_resource_server::core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata};
//! # use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;
//! # use huskarl_reqwest::mtls::NoMtls;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().mtls(NoMtls).build().await?;
//! # let metadata = AuthorizationServerMetadata::builder().issuer("https://my-issuer").http_client(&http_client).build().await?;
//! # let validator = Rfc9068Validator::builder_from_metadata(&metadata).audience("api://my-resource").jws_verifier_factory(Arc::new(JwksSource::builder().http_client(http_client.clone()).build())).build().await?;
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
//!     Ok(Some(validated)) => println!(
//!         "Authenticated: subject={:?}, scope={:?}",
//!         validated.subject,
//!         validated.claims.scope,
//!     ),
//!     Ok(None) => println!("No authentication provided"),
//!     Err(e) => println!("Validation failed: {e}"),
//! }
//! # Ok(())
//! # }
//! ```

use std::{marker::PhantomData, sync::Arc, time::Duration};

use crate::{
    core::{
        BoxedError, EndpointUrl,
        crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
        jwt::{
            BoxedJtiUniquenessChecker,
            validator::{ClaimCheck, JwtValidator},
        },
        platform::MaybeSendSync,
        server_metadata::AuthorizationServerMetadata,
    },
    validator::{
        dpop_nonce::NoNonceCheck, rfc9068::rfc9068_validator_builder::SetDpopNonceChecker,
    },
};
use http::HeaderName;
use serde::{Deserialize, Serialize};

use crate::{
    AccessTokenValidator,
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
/// Enforces all RFC 9068 §2.2 requirements: `typ`, `iss`, `exp`, `aud`,
/// `sub`, `iat`, `jti`, and `client_id` (via deserialization into
/// [`Rfc9068AccessTokenClaims`]). The `Claims` type parameter captures any
/// additional claims your authorization server includes beyond the standard set.
///
/// For authorization servers that do not issue RFC 9068-compliant tokens, use
/// [`crate::validator::custom::CustomValidator`] instead.
pub struct Rfc9068Validator<N: DpopNonceChecker, Claims = ()> {
    inner: ValidatorInner<N>,
    issuer: String,
    on_validate: Option<Arc<dyn OnValidate>>,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<N: DpopNonceChecker, Claims: for<'de> Deserialize<'de> + Clone + 'static>
    Rfc9068Validator<N, Claims>
{
    /// Creates a new [`Rfc9068Validator`].
    ///
    /// For a more convenient constructor when you have authorization server metadata,
    /// see [`Rfc9068Validator::builder_from_metadata`].
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
        /// Access token JTI uniqueness checker.
        jti_checker: Option<BoxedJtiUniquenessChecker>,
        /// DPoP nonce checker.
        #[builder(setters(vis = "", name = "dpop_nonce_checker_internal"))]
        dpop_nonce_checker: Option<N>,
        /// JTI uniqueness checker.
        dpop_jti_checker: Option<BoxedJtiUniquenessChecker>,
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

impl Rfc9068Validator<NoNonceCheck, ()> {
    /// Creates a builder for [`Rfc9068Validator`].
    ///
    /// Call [`.with_claims::<T>()`][Rfc9068ValidatorBuilder::with_claims] on the builder
    /// to specify a custom claims type. The default is `()` (no extra claims).
    pub fn builder() -> Rfc9068ValidatorBuilder<NoNonceCheck, ()> {
        Rfc9068Validator::builder_internal()
    }

    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `issuer` and `jwks_uri` from the metadata.
    /// Call `.with_claims::<MyClaims>()` on the builder to use a custom claims type.
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Rfc9068ValidatorBuilder<
        NoNonceCheck,
        (),
        rfc9068_validator_builder::SetJwksUri<rfc9068_validator_builder::SetIssuer>,
    > {
        Self::builder()
            .issuer(metadata.issuer.clone())
            .maybe_jwks_uri(metadata.jwks_uri.clone())
    }
}

impl<
    N: DpopNonceChecker,
    Claims: for<'de> Deserialize<'de> + Clone + 'static,
    S: rfc9068_validator_builder::State,
> Rfc9068ValidatorBuilder<N, Claims, S>
{
    /// Sets the claims type for the validator.
    pub fn with_claims<Claims1: for<'de> Deserialize<'de> + Clone + 'static>(
        self,
    ) -> Rfc9068ValidatorBuilder<N, Claims1, S> {
        self.with_claims_internal()
    }

    /// Sets the DPoP nonce checker for the validator.
    pub fn dpop_nonce_checker<N1: DpopNonceChecker>(
        self,
        dpop_nonce_checker: N1,
    ) -> Rfc9068ValidatorBuilder<N1, Claims, SetDpopNonceChecker<S>>
    where
        S::DpopNonceChecker: rfc9068_validator_builder::IsUnset,
    {
        self.with_n_internal()
            .dpop_nonce_checker_internal(dpop_nonce_checker)
    }
}

impl<N: DpopNonceChecker, Claims: for<'de> Deserialize<'de> + Clone + 'static>
    Rfc9068Validator<N, Claims>
{
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

impl<N: DpopNonceChecker, ExtraClaims: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static>
    AccessTokenValidator for Rfc9068Validator<N, ExtraClaims>
{
    type Claims = Rfc9068AccessTokenClaims<ExtraClaims>;
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

impl<N: DpopNonceChecker, ExtraClaims: for<'de> Deserialize<'de> + Clone + 'static>
    ProvideValidatorMetadata for Rfc9068Validator<N, ExtraClaims>
{
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.validator_metadata(resource)
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
/// `ExtraClaims` captures any additional claims beyond the RFC 9068 standard set.
/// RFC 9068 §2.2.3.1 describes `groups`, `roles`, and `entitlements` claims and
/// recommends a specific encoding for them, but does not make it mandatory.
/// Therefore, you should use the `ExtraClaims` type parameter to capture these claims
/// in whatever shape your authorization server emits.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "ExtraClaims: for<'d> Deserialize<'d>"))]
pub struct Rfc9068AccessTokenClaims<ExtraClaims = ()> {
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
    pub extra_claims: ExtraClaims,
}
