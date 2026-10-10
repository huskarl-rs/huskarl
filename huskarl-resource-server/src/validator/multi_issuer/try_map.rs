//! Fallible claim normalization.

use crate::{
    AccessTokenValidator, TokenType, ValidatedRequest,
    core::platform::{MaybeSendBoxFuture, MaybeSendSync},
    error::{Challenge, ToRfc6750Error},
    validator::{
        ValidationResult,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        observe::ValidationOutcome,
    },
};

/// Wraps a validator, normalizing its extra claims with a fallible function.
///
/// The mapper runs only after successful validation of a present token. Its
/// user-chosen error implements [`ToRfc6750Error`] to determine the rejection's
/// challenge and observation outcome. Universal token fields, the raw
/// introspection JWT, and validator metadata pass through unchanged. The `DPoP`
/// nonce is preserved even when mapping fails.
///
/// Like [`MapClaims`](super::MapClaims), this can give per-issuer validators a
/// common claims type for [`MultiIssuerValidator`](super::MultiIssuerValidator).
///
/// ```
/// use huskarl_resource_server::{
///     error::{Challenge, ToRfc6750Error, TokenErrorCode, TokenValidationError},
///     validator::{AccessTokenValidator, extract::TokenType, multi_issuer::TryMapClaims},
/// };
///
/// struct SourceClaims {
///     tenant_id: String,
/// }
/// struct Principal {
///     tenant_id: u64,
/// }
///
/// #[derive(Debug)]
/// struct InvalidTenant;
/// impl std::fmt::Display for InvalidTenant {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("invalid tenant ID")
///     }
/// }
/// impl std::error::Error for InvalidTenant {}
/// impl ToRfc6750Error for InvalidTenant {
///     fn attempted_scheme(&self) -> Option<TokenType> {
///         None
///     }
///     fn challenge(&self) -> Challenge {
///         Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
///     }
/// }
///
/// fn normalize<V>(validator: V) -> impl AccessTokenValidator<Claims = Principal>
/// where
///     V: AccessTokenValidator<Claims = SourceClaims>,
///     V::Error: 'static,
/// {
///     TryMapClaims::new(validator, |claims: SourceClaims| {
///         let tenant_id = claims.tenant_id.parse().map_err(|_| InvalidTenant)?;
///         Ok::<_, InvalidTenant>(Principal { tenant_id })
///     })
/// }
/// ```
pub struct TryMapClaims<V, F> {
    inner: V,
    f: F,
}

impl<V, F> TryMapClaims<V, F> {
    /// Wraps `inner`, applying `f` to the claims of every validated request.
    pub fn new(inner: V, f: F) -> Self {
        Self { inner, f }
    }

    /// Returns a reference to the wrapped validator.
    pub fn inner(&self) -> &V {
        &self.inner
    }
}

impl<V, F, C, E> AccessTokenValidator for TryMapClaims<V, F>
where
    V: AccessTokenValidator,
    V::Error: 'static,
    F: Fn(V::Claims) -> Result<C, E> + MaybeSendSync,
    C: MaybeSendSync,
    E: ToRfc6750Error + 'static,
{
    type Claims = C;
    type Error = TryMapError<V::Error, E>;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<C, Self::Error>> {
        Box::pin(async move {
            let result = self
                .inner
                .validate_request(headers, method, uri, client_cert_der)
                .await;
            try_map_result(result, |request| request.try_map_claims(&self.f))
        })
    }
}

impl<V: ProvideValidatorMetadata, F> ProvideValidatorMetadata for TryMapClaims<V, F> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.inner.validator_metadata(resource)
    }
}

/// Wraps a validator, mapping each whole validated request with a fallible function.
///
/// The fallible counterpart of [`MapRequest`](super::MapRequest), behaving
/// like [`TryMapClaims`] on failure. The mapper can, for example, reject a
/// token by `sub`.
///
/// Rewritten fields are not revalidated; see [subjects and other token
/// fields](crate::_docs::explanation::multi_issuer_routing#subjects-and-other-token-fields).
///
/// ```
/// use huskarl_resource_server::{
///     error::{Challenge, ToRfc6750Error, TokenErrorCode, TokenValidationError},
///     validator::{
///         AccessTokenValidator, ValidatedRequest, extract::TokenType, multi_issuer::TryMapRequest,
///     },
/// };
///
/// struct Principal {
///     tenant: String,
/// }
///
/// #[derive(Debug)]
/// struct BlockedSubject;
/// impl std::fmt::Display for BlockedSubject {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("subject is not permitted")
///     }
/// }
/// impl std::error::Error for BlockedSubject {}
/// impl ToRfc6750Error for BlockedSubject {
///     fn attempted_scheme(&self) -> Option<TokenType> {
///         None
///     }
///     fn challenge(&self) -> Challenge {
///         Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
///     }
/// }
///
/// fn restrict<V>(validator: V) -> impl AccessTokenValidator<Claims = Principal>
/// where
///     V: AccessTokenValidator<Claims = String>,
///     V::Error: 'static,
/// {
///     TryMapRequest::new(validator, |request: ValidatedRequest<String>| {
///         if request.sub.as_deref() == Some("service-account") {
///             return Err(BlockedSubject);
///         }
///         Ok(request.map_claims(|tenant| Principal { tenant }))
///     })
/// }
/// ```
pub struct TryMapRequest<V, F> {
    inner: V,
    f: F,
}

impl<V, F> TryMapRequest<V, F> {
    /// Wraps `inner`, applying `f` to every validated request.
    pub fn new(inner: V, f: F) -> Self {
        Self { inner, f }
    }

    /// Returns a reference to the wrapped validator.
    pub fn inner(&self) -> &V {
        &self.inner
    }
}

impl<V, F, C, E> AccessTokenValidator for TryMapRequest<V, F>
where
    V: AccessTokenValidator,
    V::Error: 'static,
    F: Fn(ValidatedRequest<V::Claims>) -> Result<ValidatedRequest<C>, E> + MaybeSendSync,
    C: MaybeSendSync,
    E: ToRfc6750Error + 'static,
{
    type Claims = C;
    type Error = TryMapError<V::Error, E>;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<C, Self::Error>> {
        Box::pin(async move {
            let result = self
                .inner
                .validate_request(headers, method, uri, client_cert_der)
                .await;
            try_map_result(result, &self.f)
        })
    }
}

impl<V: ProvideValidatorMetadata, F> ProvideValidatorMetadata for TryMapRequest<V, F> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.inner.validator_metadata(resource)
    }
}

/// Applies `f` to a present validated request, keeping the `DPoP` nonce either way.
fn try_map_result<C0, C, V, E>(
    result: ValidationResult<C0, V>,
    f: impl FnOnce(ValidatedRequest<C0>) -> Result<ValidatedRequest<C>, E>,
) -> ValidationResult<C, TryMapError<V, E>> {
    ValidationResult {
        outcome: result
            .outcome
            .map_err(TryMapError::Validation)
            .and_then(|request| request.map(f).transpose().map_err(TryMapError::Mapping)),
        dpop_nonce: result.dpop_nonce,
    }
}

/// The former name of [`TryMapError`].
#[deprecated(since = "0.11.7", note = "renamed to `TryMapError`")]
pub type TryMapClaimsError<V, E> = TryMapError<V, E>;

/// Distinguishes validation failures from user-defined mapping failures in
/// [`TryMapClaims`] and [`TryMapRequest`].
///
/// Both variants preserve the underlying error's challenge, attempted scheme,
/// observation outcome, issuer attribution, and error source chain.
#[derive(Debug)]
#[non_exhaustive]
pub enum TryMapError<V, E> {
    /// The wrapped validator rejected the request.
    Validation(V),
    /// Validation succeeded, but the mapper rejected the request.
    Mapping(E),
}

impl<V, E> std::fmt::Display for TryMapError<V, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Validation(_) => "token validation error",
            Self::Mapping(_) => "request mapping error",
        })
    }
}

impl<V: std::error::Error + 'static, E: std::error::Error + 'static> std::error::Error
    for TryMapError<V, E>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Validation(error) => error,
            Self::Mapping(error) => error,
        })
    }
}

impl<V: ToRfc6750Error, E: ToRfc6750Error> TryMapError<V, E> {
    fn error(&self) -> &dyn ToRfc6750Error {
        match self {
            Self::Validation(error) => error,
            Self::Mapping(error) => error,
        }
    }
}

impl<V: ToRfc6750Error + 'static, E: ToRfc6750Error + 'static> ToRfc6750Error
    for TryMapError<V, E>
{
    fn challenge(&self) -> Challenge {
        self.error().challenge()
    }

    fn attempted_scheme(&self) -> Option<TokenType> {
        self.error().attempted_scheme()
    }

    fn validation_outcome(&self, challenge: &Challenge) -> ValidationOutcome {
        self.error().validation_outcome(challenge)
    }

    fn issuer(&self) -> Option<&str> {
        self.error().issuer()
    }

    fn branch_label(&self) -> Option<&str> {
        self.error().branch_label()
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
#[allow(clippy::expect_used)] // Test helpers use fixed, valid fixtures.
mod tests {
    use super::*;
    use crate::{
        core::{jwt::ConfirmationClaim, platform::SystemTime},
        error::InsufficientScope,
        validator::multi_issuer::{MapClaims, MapRequest},
    };

    enum Stub {
        Present,
        Absent,
        Invalid,
    }

    fn request() -> ValidatedRequest<String> {
        ValidatedRequest {
            iss: Some("issuer".into()),
            sub: Some("subject".into()),
            aud: vec!["audience".into()],
            jti: Some("token-id".into()),
            iat: Some(SystemTime::UNIX_EPOCH),
            exp: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100)),
            cnf: Some(
                serde_json::from_str::<ConfirmationClaim>(r#"{"jkt":"thumbprint"}"#)
                    .expect("valid confirmation claim"),
            ),
            claims: "42".into(),
            introspection_jwt: Some("raw-jwt".into()),
        }
    }

    impl AccessTokenValidator for Stub {
        type Claims = String;
        type Error = InsufficientScope;

        fn validate_request<'a>(
            &'a self,
            _: &'a http::HeaderMap,
            _: &'a http::Method,
            _: &'a http::Uri,
            _: Option<&'a [u8]>,
        ) -> MaybeSendBoxFuture<'a, ValidationResult<String, Self::Error>> {
            Box::pin(async move {
                ValidationResult {
                    outcome: match self {
                        Self::Present => Ok(Some(request())),
                        Self::Absent => Ok(None),
                        Self::Invalid => Err(InsufficientScope::new("read")),
                    },
                    dpop_nonce: Some("nonce".into()),
                }
            })
        }
    }

    impl ProvideValidatorMetadata for Stub {
        fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
            ValidatorMetadata::builder()
                .realm("test")
                .maybe_resource(resource.map(str::to_owned))
                .build()
        }
    }

    async fn validate<V: AccessTokenValidator>(
        validator: &V,
    ) -> ValidationResult<V::Claims, V::Error> {
        validator
            .validate_request(
                &http::HeaderMap::new(),
                &http::Method::GET,
                &"https://api.example/".parse().expect("valid URI"),
                None,
            )
            .await
    }

    fn assert_fields(mapped: &ValidatedRequest<usize>) {
        let original = request();
        assert_eq!(mapped.claims, 42);
        assert_eq!(mapped.iss, original.iss);
        assert_eq!(mapped.sub, original.sub);
        assert_eq!(mapped.aud, original.aud);
        assert_eq!(mapped.jti, original.jti);
        assert_eq!(mapped.iat, original.iat);
        assert_eq!(mapped.exp, original.exp);
        assert_eq!(
            serde_json::to_value(&mapped.cnf).expect("serializable confirmation"),
            serde_json::to_value(&original.cnf).expect("serializable confirmation")
        );
        assert_eq!(mapped.introspection_jwt, original.introspection_jwt);
    }

    #[tokio::test]
    async fn success_preserves_token_fields_nonce_and_metadata() {
        let validator = TryMapClaims::new(
            Stub::Present,
            |c: String| -> Result<usize, InsufficientScope> { Ok(c.parse().unwrap()) },
        );
        assert!(matches!(validator.inner(), Stub::Present));
        let result = validate(&validator).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        assert_fields(&result.outcome.unwrap().unwrap());
        let metadata = validator.validator_metadata(Some("https://api.example/"));
        assert_eq!(metadata.realm.as_deref(), Some("test"));
        assert_eq!(metadata.resource.as_deref(), Some("https://api.example/"));
    }

    #[tokio::test]
    async fn infallible_mapping_preserves_token_fields() {
        let result = validate(&MapClaims::new(Stub::Present, |c: String| {
            c.parse::<usize>().unwrap()
        }))
        .await;
        assert_fields(&result.outcome.unwrap().unwrap());
    }

    #[tokio::test]
    async fn infallible_request_mapping_rewrites_token_fields() {
        let validator = MapRequest::new(Stub::Present, |request: ValidatedRequest<String>| {
            let mut mapped = request.map_claims(|c| c.parse::<usize>().unwrap());
            mapped.sub = mapped.sub.map(|sub| format!("ns|{sub}"));
            mapped
        });
        assert!(matches!(validator.inner(), Stub::Present));
        let result = validate(&validator).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        let mut mapped = result.outcome.unwrap().unwrap();
        assert_eq!(mapped.sub.as_deref(), Some("ns|subject"));
        mapped.sub = request().sub;
        assert_fields(&mapped);
        let metadata = validator.validator_metadata(None);
        assert_eq!(metadata.realm.as_deref(), Some("test"));
    }

    #[tokio::test]
    async fn infallible_request_mapping_passes_errors_through() {
        fn never(_: ValidatedRequest<String>) -> ValidatedRequest<()> {
            panic!("mapper must not run")
        }
        let result = validate(&MapRequest::new(Stub::Absent, never)).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        assert!(matches!(result.outcome, Ok(None)));
        let result = validate(&MapRequest::new(Stub::Invalid, never)).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        let error: InsufficientScope = result.outcome.unwrap_err();
        assert_eq!(error.challenge().scope.as_deref(), Some("read"));
    }

    #[tokio::test]
    async fn mapping_failure_rejects_and_preserves_nonce_and_source() {
        let validator = TryMapClaims::new(
            Stub::Present,
            |_: String| -> Result<(), InsufficientScope> { Err(InsufficientScope::new("admin")) },
        );
        let result = validate(&validator).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        let error = result.outcome.unwrap_err();
        assert!(matches!(error, TryMapError::Mapping(_)));
        assert_eq!(error.challenge().scope.as_deref(), Some("admin"));
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .is::<InsufficientScope>()
        );
    }

    #[tokio::test]
    async fn absent_requests_skip_mapping() {
        let validator =
            TryMapClaims::new(Stub::Absent, |_: String| -> Result<(), InsufficientScope> {
                panic!("mapper must not run")
            });
        let result = validate(&validator).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        assert!(matches!(result.outcome, Ok(None)));
    }

    #[tokio::test]
    async fn invalid_requests_skip_mapping() {
        let validator = TryMapClaims::new(
            Stub::Invalid,
            |_: String| -> Result<(), InsufficientScope> { panic!("mapper must not run") },
        );
        let result = validate(&validator).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        let error = result.outcome.unwrap_err();
        assert!(matches!(error, TryMapError::Validation(_)));
        assert_eq!(error.challenge().scope.as_deref(), Some("read"));
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .is::<InsufficientScope>()
        );
    }

    #[tokio::test]
    async fn request_mapper_sees_and_rewrites_token_fields() {
        let validator = TryMapRequest::new(
            Stub::Present,
            |request: ValidatedRequest<String>| -> Result<_, InsufficientScope> {
                let sub = format!(
                    "{}|{}",
                    request.iss.as_deref().unwrap(),
                    request.sub.as_deref().unwrap()
                );
                let mut mapped = request.map_claims(|c| c.parse::<usize>().unwrap());
                mapped.sub = Some(sub);
                Ok(mapped)
            },
        );
        assert!(matches!(validator.inner(), Stub::Present));
        let result = validate(&validator).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        let mut mapped = result.outcome.unwrap().unwrap();
        assert_eq!(mapped.sub.as_deref(), Some("issuer|subject"));
        mapped.sub = request().sub;
        assert_fields(&mapped);
        let metadata = validator.validator_metadata(None);
        assert_eq!(metadata.realm.as_deref(), Some("test"));
    }

    #[tokio::test]
    async fn request_mapper_can_reject_by_subject() {
        let validator = TryMapRequest::new(
            Stub::Present,
            |request: ValidatedRequest<String>| -> Result<ValidatedRequest<String>, _> {
                if request.sub.as_deref() == Some("subject") {
                    Err(InsufficientScope::new("admin"))
                } else {
                    Ok(request)
                }
            },
        );
        let result = validate(&validator).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        let error = result.outcome.unwrap_err();
        assert!(matches!(error, TryMapError::Mapping(_)));
        assert_eq!(error.challenge().scope.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn request_mapper_skips_absent_and_invalid_requests() {
        fn never(_: ValidatedRequest<String>) -> Result<ValidatedRequest<()>, InsufficientScope> {
            panic!("mapper must not run")
        }
        let result = validate(&TryMapRequest::new(Stub::Absent, never)).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        assert!(matches!(result.outcome, Ok(None)));
        let result = validate(&TryMapRequest::new(Stub::Invalid, never)).await;
        assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
        assert!(matches!(result.outcome, Err(TryMapError::Validation(_))));
    }

    #[test]
    fn request_mapping_accepts_fn_once_and_arbitrary_errors() {
        let captured = String::from("owned");
        assert_eq!(request().map_claims(|_| captured).claims, "owned");
        assert_eq!(
            request().try_map_claims(|_| Err::<(), _>(123)).unwrap_err(),
            123
        );
    }

    #[test]
    fn both_variants_forward_error_context() {
        use crate::{
            core::jwt::validator::JwtValidationError,
            validator::{error::ValidateHeadersError, multi_issuer::MultiIssuerError},
        };

        let make = || MultiIssuerError::Validation {
            issuer: "configured-issuer".into(),
            error: Box::new(ValidateHeadersError::InvalidJwt {
                token_type: TokenType::DPoP,
                source: JwtValidationError::UnsignedToken,
            }),
        };
        for error in [
            TryMapError::<MultiIssuerError, MultiIssuerError>::Validation(make()),
            TryMapError::Mapping(make()),
        ] {
            assert_eq!(error.attempted_scheme(), Some(TokenType::DPoP));
            assert_eq!(error.issuer(), Some("configured-issuer"));
            assert_eq!(
                error.validation_outcome(&error.challenge()),
                ValidationOutcome::InvalidToken
            );
            assert!(
                std::error::Error::source(&error)
                    .unwrap()
                    .is::<MultiIssuerError>()
            );
        }
    }

    crate::forwarding_table! {
        challenges_are_preserved {
            || InsufficientScope::new("admin") => |e| TryMapError::<InsufficientScope, _>::Mapping(e),
            || InsufficientScope::new("read") => |e| TryMapError::<_, InsufficientScope>::Validation(e),
        }
    }
}
