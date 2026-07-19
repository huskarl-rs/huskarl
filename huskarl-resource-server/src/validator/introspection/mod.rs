//! RFC 7662 Token Introspection support.
//!
//! [`IntrospectionValidator`] validates access tokens by calling an authorization server's
//! token introspection endpoint, rather than validating JWT signatures locally.
//! This enables validation of opaque tokens and authoritative revocation status checks.
//!
//! Optionally supports RFC 9701 (JWT Response for Introspection) when a
//! `jwks_uri` is configured (together with a `jws_verifier_factory`, which has
//! a default).
//!
//! For a step-by-step setup walkthrough (including client authentication) see
//! the [introspection guide](crate::_docs::guide::introspection); for picking
//! between the validators see [choosing a
//! validator](crate::_docs::explanation::choosing_a_validator).

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
        dpop::DPoPNonceChecker,
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
        dpop_proof::DPoPProofValidator,
        extract::extract_token,
        introspection::{
            error::{AudienceSnafu, BindingSnafu, CallSnafu, ExtractSnafu},
            introspection_validator_builder::{
                SetIntrospectionEndpoint, SetIssuer, SetJwksUri, SetTokenEndpoint, State,
            },
        },
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};

/// Validates access tokens by calling an authorization server's RFC 7662 token introspection
/// endpoint.
///
/// Supports both opaque tokens and JWT tokens. Optionally supports RFC 9701
/// (JWT Response for Introspection) when configured with a `jwks_uri` (together
/// with a `jws_verifier_factory`, which has a default).
///
/// Supports `DPoP` token binding validation when configured with a `jws_verifier_platform`.
///
/// Use [`IntrospectionValidator::builder`] to construct an instance.
pub struct IntrospectionValidator<Claims = ()> {
    token_introspection: TokenIntrospection,
    http_client: Arc<dyn HttpClient>,
    dpop_binding_checker: DPoPBindingChecker,
    token_header: HeaderName,
    issuer: Option<String>,
    realm: Option<String>,
    resource_metadata: Option<String>,
    aud: ClaimCheck,
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
        /// introspects as `active`. Pass this resource's identifier as a
        /// plain string (equivalent to [`ClaimCheck::required_value`]; use
        /// [`ClaimCheck::require_any`] for several), or opt out explicitly
        /// with [`ClaimCheck::NoCheck`] when the authorization server scopes
        /// tokens to a single resource or omits `aud` from its introspection
        /// responses.
        #[builder(into)]
        aud: ClaimCheck,
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
        /// Clock-skew leeway for the temporal checks on `DPoP` proofs and the
        /// RFC 9701 introspection-response JWT (RFC 9449 §11.1). Defaults to
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
        #[builder(with = |checker: impl DPoPNonceChecker + 'static| Arc::new(checker) as Arc<dyn DPoPNonceChecker>)]
        dpop_nonce_checker: Option<Arc<dyn DPoPNonceChecker>>,
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
            .clock_leeway(clock_leeway)
            .build()
            .await?;

        Ok(Self {
            token_introspection,
            http_client,
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
            issuer,
            realm,
            resource_metadata,
            aud,
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
            realm: self.realm.clone(),
            authorization_servers: self.issuer.as_ref().map(|s| vec![s.clone()]),
            dpop_supported: Some(true),
            dpop_signing_alg_values_supported: self
                .dpop_binding_checker
                .proof_validator
                .allowed_signing_algorithms()
                .map(<[_]>::to_vec),
            dpop_bound_access_tokens_required: Some(self.dpop_binding_checker.required),
            // Only a hard mTLS requirement proves support: whether TLS
            // termination presents client certificates is deployment knowledge.
            tls_client_certificate_bound_access_tokens: self.require_mtls.then_some(true),
            resource: resource.map(std::borrow::ToOwned::to_owned),
            bearer_methods_supported: Some(vec!["header"]),
            resource_metadata: self.resource_metadata.clone(),
        }
    }

    /// Validates an access token by calling the introspection endpoint.
    ///
    /// Returns `Ok(None)` if no token was present in the request headers,
    /// `Ok(Some(_))` if the token was successfully validated, or `Err(_)` if
    /// a token was present but invalid.
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
    ) -> ValidationResult<Claims, IntrospectionValidateError> {
        let (dpop_nonce, outcome) = self
            .validate_inner(headers, http_method, http_uri, client_cert_der)
            .await;

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
        if let Err(expected) = check_audience(&self.aud, &validated.aud) {
            return (
                None,
                Err(AudienceSnafu {
                    token_type,
                    expected,
                    actual: validated.aud.clone(),
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
