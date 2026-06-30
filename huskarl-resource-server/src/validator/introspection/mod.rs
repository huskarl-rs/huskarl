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
//! use huskarl_reqwest::ReqwestClient;
//!
//! # async fn setup_client() -> Result<(), Box<dyn std::error::Error>> {
//! let client: ReqwestClient = ReqwestClient::builder().build().await?;
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
//! let client_auth: ClientSecret = ClientSecret::new(client_secret);
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
//! use huskarl_resource_server::{
//!     core::{
//!         client_auth::ClientSecret,
//!         jwt::validator::ClaimCheck,
//!         secrets::{EnvVarSecret, encodings::StringEncoding},
//!         server_metadata::AuthorizationServerMetadata,
//!     },
//!     validator::introspection::IntrospectionValidator,
//! };
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//! # let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//!
//! let metadata = AuthorizationServerMetadata::fetch()
//!     .http_client(&http_client)
//!     .issuer("https://my-issuer")
//!     .call()
//!     .await?;
//!
//! let validator = IntrospectionValidator::builder_from_metadata(&metadata)
//!     .expect("authorization server does not support token introspection")
//!     .client_id("my-resource-server")
//!     .audience(ClaimCheck::required_value("api://my-resource"))
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
//! use huskarl_resource_server::{
//!     core::{
//!         client_auth::ClientSecret,
//!         jwt::validator::ClaimCheck,
//!         secrets::{EnvVarSecret, encodings::StringEncoding},
//!     },
//!     validator::introspection::IntrospectionValidator,
//! };
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//! # let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//!
//! let validator = IntrospectionValidator::builder()
//!     .client_id("my-resource-server")
//!     .issuer("https://my-issuer")
//!     .introspection_endpoint("https://my-issuer/oauth/introspect".parse()?)
//!     .audience(ClaimCheck::required_value("api://my-resource"))
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
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let http_client = huskarl_reqwest::ReqwestClient::builder().build().await?;
//! # let client_secret = EnvVarSecret::new("CLIENT_SECRET", &StringEncoding)?;
//! # let metadata = AuthorizationServerMetadata::fetch().http_client(&http_client).issuer("https://my-issuer").call().await?;
//! # let validator = IntrospectionValidator::builder_from_metadata(&metadata).expect("").client_id("my-resource-server").audience(huskarl_resource_server::core::jwt::validator::ClaimCheck::required_value("api://my-resource")).client_auth(ClientSecret::new(client_secret)).http_client(http_client.clone()).build().await?;
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
        EndpointUrl, Error,
        client_auth::ClientAuthentication,
        crypto::verifier::{JwsVerifierFactory, JwsVerifierPlatform},
        http::HttpClient,
        jwk::JwksSource,
        jwt::{JtiUniquenessChecker, validator::ClaimCheck},
        platform::{Duration, MaybeSendSync},
        server_metadata::AuthorizationServerMetadata,
    },
    introspection::TokenIntrospection,
    validator::{
        AccessTokenValidator, ValidatedRequest, ValidationResult,
        binding::{DPoPBindingChecker, check_token_binding},
        dpop_nonce::DpopNonceChecker,
        dpop_proof::DpopProofValidator,
        extract::extract_token,
        introspection::{
            error::{AudienceSnafu, BindingSnafu, CallSnafu, ExtractSnafu},
            introspection_validator_builder::{
                SetIntrospectionEndpoint, SetIssuer, SetJwksUri, SetTokenEndpoint, State,
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
/// Supports `DPoP` token binding validation when configured with a `jws_verifier_platform`.
///
/// Use [`IntrospectionValidator::builder`] to construct an instance.
pub struct IntrospectionValidator<Claims = ()> {
    token_introspection: TokenIntrospection,
    http_client: Arc<dyn HttpClient>,
    dpop_binding_checker: DPoPBindingChecker,
    token_header: HeaderName,
    on_validate: Option<Arc<dyn OnValidate>>,
    issuer: Option<String>,
    audience: ClaimCheck,
    require_mtls: bool,
    _phantom: PhantomData<Claims>,
}

#[bon::bon]
impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> IntrospectionValidator<Claims> {
    /// Creates a new [`IntrospectionValidator`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the underlying [`TokenIntrospection`] cannot be
    /// built — for example, when its JWS verifier factory fails to construct a
    /// verifier.
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
        /// The authorization server's token endpoint, as published in metadata.
        ///
        /// Used only as the audience for client assertions configured with
        /// `Audience::TokenEndpoint`. Pre-filled by
        /// [`builder_from_metadata`](Self::builder_from_metadata); leave unset
        /// to make that audience policy fail closed.
        token_endpoint: Option<EndpointUrl>,
        /// Check applied against the audience (`aud`) of introspected tokens.
        ///
        /// RFC 7662 §4 directs resource servers to verify that an introspected
        /// token was intended for them: when one authorization server serves
        /// multiple resources, a token minted for another resource still
        /// introspects as `active`. Use [`ClaimCheck::required_value`] with
        /// this resource's identifier (or [`ClaimCheck::require_any`] for
        /// several), or opt out explicitly with [`ClaimCheck::NoCheck`] when
        /// the authorization server scopes tokens to a single resource or
        /// omits `aud` from its introspection responses.
        audience: ClaimCheck,
        /// The client authentication strategy.
        #[builder(with = |auth: impl ClientAuthentication + 'static| Arc::new(auth) as Arc<dyn ClientAuthentication>)]
        client_auth: Arc<dyn ClientAuthentication>,
        /// If `true`, adds `Accept: application/token-introspection+jwt` to introspection
        /// requests, requesting an RFC 9701 JWT response.
        ///
        /// The AS may still respond with JSON even when this is `true`.
        #[builder(default)]
        request_jwt_response: bool,
        /// HTTP client for calling the introspection endpoint (also used by default to get JWKS keys).
        #[builder(with = |client: impl HttpClient + 'static| Arc::new(client) as Arc<dyn HttpClient>)]
        http_client: Arc<dyn HttpClient>,
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
        /// JWKS URI for RFC 9701 JWT response validation.
        ///
        /// Must be provided together with `jws_verifier_factory` to enable JWT response
        /// validation.
        jwks_uri: Option<EndpointUrl>,
        /// Cryptographic platform for JWS verification.
        ///
        /// Used for JWT response (RFC 9701) and `DPoP` proof verification. When the
        /// `default-jws-verifier-platform` feature is enabled, defaults to the platform default.
        #[cfg_attr(feature = "default-jws-verifier-platform", builder(default = crate::DefaultJwsVerifierPlatform::default().into()))]
        jws_verifier_platform: Arc<dyn JwsVerifierPlatform>,
        /// Optional server-side `DPoP` nonce enforcement (RFC 9449 §8). When set,
        /// proofs must carry a nonce this checker accepts; omitting it disables
        /// nonce enforcement.
        #[builder(with = |checker: impl DpopNonceChecker + 'static| Arc::new(checker) as Arc<dyn DpopNonceChecker>)]
        dpop_nonce_checker: Option<Arc<dyn DpopNonceChecker>>,
        /// `DPoP` JTI uniqueness checker.
        dpop_jti_checker: Option<Arc<dyn JtiUniquenessChecker>>,
        /// JWS verifier factory for RFC 9701 JWT response validation.
        ///
        /// When provided (along with `jwks_uri`), a [`JwtValidator`] is built that validates
        /// the outer JWT of introspection responses with content type
        /// `application/token-introspection+jwt`. If the AS returns a JWT response without a
        /// validator configured,
        /// [`IntrospectionCallError::UnexpectedJwtResponse`](crate::introspection::IntrospectionCallError::UnexpectedJwtResponse)
        /// is returned.
        ///
        /// [`JwtValidator`]: crate::core::jwt::validator::JwtValidator
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
    ) -> Result<Self, Error> {
        let token_introspection = TokenIntrospection::builder()
            .client_id(client_id.clone())
            .maybe_issuer(issuer.clone())
            .introspection_endpoint(introspection_endpoint)
            .maybe_token_endpoint(token_endpoint)
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
            audience,
            require_mtls,
            _phantom: PhantomData,
        })
    }
}

impl IntrospectionValidator<()> {
    /// Creates a builder for [`IntrospectionValidator`].
    ///
    /// Call [`.with_claims::<T>()`][IntrospectionValidatorBuilder::with_claims] on the builder
    /// to specify a custom claims type. The default is `()` (no extra claims).
    pub fn builder() -> IntrospectionValidatorBuilder<()> {
        IntrospectionValidator::builder_internal()
    }

    /// Configure the validator from authorization server metadata.
    ///
    /// Pre-fills `issuer`, `introspection_endpoint`, `jwks_uri`, and
    /// `token_endpoint` from the metadata. Call `.with_claims::<MyClaims>()` to
    /// use a custom claims type.
    #[allow(clippy::type_complexity)]
    pub fn builder_from_metadata(
        metadata: &AuthorizationServerMetadata,
    ) -> Option<
        IntrospectionValidatorBuilder<
            (),
            SetTokenEndpoint<SetJwksUri<SetIntrospectionEndpoint<SetIssuer>>>,
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
                    .token_endpoint(metadata.token_endpoint.clone())
            })
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static, S: State>
    IntrospectionValidatorBuilder<Claims, S>
{
    /// Sets the claims type for the validator.
    pub fn with_claims<Claims1: for<'de> Deserialize<'de> + Clone + 'static>(
        self,
    ) -> IntrospectionValidatorBuilder<Claims1, S> {
        self.with_claims_internal()
    }
}

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> IntrospectionValidator<Claims> {
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
            resource: resource.map(std::borrow::ToOwned::to_owned),
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
    ) -> ValidationResult<Claims, IntrospectionValidateError> {
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
                Err(IntrospectionValidateError::Audience { .. }) => ValidationOutcome::InvalidToken,
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
        Result<Option<ValidatedRequest<Claims>>, IntrospectionValidateError>,
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

        // 3. Audience check (RFC 7662 §4): an active token may still have been
        // minted for a different resource served by the same authorization server.
        if let Err(expected) = check_audience(&self.audience, &validated.audience) {
            return (
                None,
                Err(AudienceSnafu {
                    token_type,
                    expected,
                    actual: validated.audience.clone(),
                }
                .build()),
            );
        }

        // 4. Binding check
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

impl<Claims: for<'de> Deserialize<'de> + Clone + 'static> ProvideValidatorMetadata
    for IntrospectionValidator<Claims>
{
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.validator_metadata(resource)
    }
}

/// Checks the introspected token's audience values against the configured
/// [`ClaimCheck`], returning a description of the expected audience on mismatch.
///
/// Mirrors the `aud` semantics of [`JwtValidator`](crate::core::jwt::validator::JwtValidator):
/// a token with no `aud` fails `Present`/`RequiredValue`/`RequireAny` but
/// passes `IfPresent`. Unrecognized future check variants fail closed.
fn check_audience(check: &ClaimCheck, aud: &[String]) -> Result<(), String> {
    let ok = match check {
        ClaimCheck::NoCheck => true,
        ClaimCheck::Present => !aud.is_empty(),
        ClaimCheck::RequiredValue(v) => aud.contains(v),
        ClaimCheck::RequireAny(vs) => vs.iter().any(|v| aud.contains(v)),
        ClaimCheck::IfPresent(v) => aud.is_empty() || aud.contains(v),
        _ => false,
    };
    if ok {
        return Ok(());
    }
    Err(match check {
        ClaimCheck::Present => "any audience".to_owned(),
        ClaimCheck::RequiredValue(v) | ClaimCheck::IfPresent(v) => v.clone(),
        ClaimCheck::RequireAny(vs) => vs.join(" or "),
        _ => "a supported audience check".to_owned(),
    })
}

impl<Claims: for<'de> Deserialize<'de> + Clone + MaybeSendSync + 'static> AccessTokenValidator
    for IntrospectionValidator<Claims>
{
    type Claims = Claims;
    type Error = IntrospectionValidateError;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn auds(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn audience_no_check_accepts_anything() {
        assert!(check_audience(&ClaimCheck::NoCheck, &[]).is_ok());
        assert!(check_audience(&ClaimCheck::NoCheck, &auds(&["other"])).is_ok());
    }

    #[test]
    fn audience_required_value() {
        let check = ClaimCheck::required_value("api://rs1");
        assert!(check_audience(&check, &auds(&["api://rs1"])).is_ok());
        assert!(check_audience(&check, &auds(&["api://rs2", "api://rs1"])).is_ok());
        // A token for a different resource — or with no audience at all —
        // must be rejected.
        assert!(check_audience(&check, &auds(&["api://rs2"])).is_err());
        assert!(check_audience(&check, &[]).is_err());
    }

    #[test]
    fn audience_require_any() {
        let check = ClaimCheck::require_any(["api://a", "api://b"]);
        assert!(check_audience(&check, &auds(&["api://b"])).is_ok());
        assert!(check_audience(&check, &auds(&["api://c"])).is_err());
        assert!(check_audience(&check, &[]).is_err());
    }

    #[test]
    fn audience_if_present() {
        let check = ClaimCheck::if_present("api://rs1");
        assert!(check_audience(&check, &[]).is_ok());
        assert!(check_audience(&check, &auds(&["api://rs1"])).is_ok());
        assert!(check_audience(&check, &auds(&["api://rs2"])).is_err());
    }

    #[test]
    fn audience_present() {
        assert!(check_audience(&ClaimCheck::present(), &auds(&["anything"])).is_ok());
        assert!(check_audience(&ClaimCheck::present(), &[]).is_err());
    }
}
