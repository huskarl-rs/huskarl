//! Token validation observation hooks.
//!
//! Wrap any [`AccessTokenValidator`] in an [`ObservedValidator`] to record
//! metrics, emit structured log events, or trigger alerts on each validation
//! attempt without touching the validator itself.

use std::sync::Arc;

use crate::{
    core::platform::{MaybeSendBoxFuture, MaybeSendSync},
    error::ToRfc6750Error,
    validator::{
        AccessTokenValidator, ValidationResult,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};

/// The outcome of a token validation attempt, as a low-cardinality label
/// suitable for a metrics tag.
///
/// Carried on the [`ValidationEvent`] passed to an [`ObservedValidator`]'s
/// callback, alongside the underlying rejection for detail beyond the label.
/// Which variants can occur depends on the wrapped validator — e.g. `Expired`
/// arises only from local JWT validation, and `UnrecognizedIssuer` only from
/// multi-issuer routing.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr, strum::AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum ValidationOutcome {
    /// Token was valid.
    Success,
    /// No authentication was present in the request headers.
    NoToken,
    /// Token could not be extracted or parsed from the request headers.
    ExtractError,
    /// Token was invalid — bad signature, wrong issuer or audience, or inactive.
    InvalidToken,
    /// Token was expired (`exp` in the past).
    ///
    /// Split from [`InvalidToken`](Self::InvalidToken) because late-refreshing
    /// clients make expiry the highest-volume benign rejection; folding it in
    /// would mask signature-failure spikes (the classic broken-key-rotation
    /// signal). Local JWT validation only — introspection reports inactive
    /// tokens as `InvalidToken` (RFC 7662 `active` does not say why).
    Expired,
    /// Sender-constraint binding check failed (`DPoP` or mTLS) — the
    /// possible-stolen-token bucket (RFC 9449 §7.1).
    BindingError,
    /// A `DPoP` nonce is required; the client retries with the supplied nonce
    /// (RFC 9449 §8).
    ///
    /// Routine protocol churn under server-side nonce enforcement, not a
    /// failure — kept out of [`BindingError`](Self::BindingError) so that
    /// bucket stays an alertable security signal.
    NonceRequired,
    /// The resource server itself failed — a backing call broke (introspection
    /// endpoint, replay store, nonce checker) or the deployment is
    /// misintegrated. The token was never judged; mirrors the 5xx response.
    CallError,
    /// A token was presented but its `iss` claim was missing, unparseable, or
    /// not registered with the
    /// [`MultiIssuerValidator`](crate::validator::multi_issuer::MultiIssuerValidator)
    /// (a misconfigured client, or probing).
    UnrecognizedIssuer,
}

impl ValidationOutcome {
    /// Returns a short static string label suitable for use as a metrics tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// A single observed validation attempt, passed to [`OnValidate`].
///
/// Marked non-exhaustive so future observation dimensions are additive.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct ValidationEvent<'a> {
    /// The outcome label.
    pub outcome: ValidationOutcome,
    /// The validator's rejection, when a token was presented but refused — its
    /// [`error_description`](ToRfc6750Error::error_description),
    /// [`token_error`](ToRfc6750Error::token_error), and `Debug` output give
    /// more detail than the outcome label alone.
    pub error: Option<&'a dyn ToRfc6750Error>,
    /// The token's issuer, when known and trustworthy as a metrics label: the
    /// validated `iss` claim on success, or the registered issuer a
    /// [multi-issuer validator](crate::validator::multi_issuer) routed to on
    /// failure ([`ToRfc6750Error::issuer`]). A multi-issuer success whose
    /// source dropped the optional `iss` falls back to the routed issuer.
    ///
    /// `None` when the rejection carries no trusted issuer — including
    /// unrecognized-issuer rejections, whose unverified `iss` would let
    /// clients mint arbitrary label values.
    pub iss: Option<&'a str>,
}

/// A callback invoked after each token validation attempt.
///
/// Implement this trait (or use a closure) and wrap a validator in an
/// [`ObservedValidator`] to observe validation outcomes — for example to
/// record metrics, emit structured log events, or trigger alerts.
///
/// Any context needed to identify the validator (resource name, machine ID, etc.)
/// should be captured by the implementation itself.
pub trait OnValidate: MaybeSendSync {
    /// Called after each call to `validate_request`.
    fn on_validate(&self, event: &ValidationEvent<'_>);
}

impl<F: Fn(&ValidationEvent<'_>) + MaybeSendSync> OnValidate for F {
    fn on_validate(&self, event: &ValidationEvent<'_>) {
        self(event);
    }
}

/// An [`AccessTokenValidator`] wrapper that reports each validation attempt to
/// an [`OnValidate`] callback as a [`ValidationEvent`].
///
/// Works with any validator. One wrapper around a
/// [`MultiIssuerValidator`](crate::validator::multi_issuer::MultiIssuerValidator)
/// observes the whole deployment: routing failures surface as
/// [`UnrecognizedIssuer`](ValidationOutcome::UnrecognizedIssuer), and both
/// successes and delegated failures carry the routed issuer in
/// [`ValidationEvent::iss`] — no need to wrap each source validator.
///
/// # Example
///
/// ```rust,no_run
/// # use huskarl_resource_server::validator::observe::{ObservedValidator, ValidationEvent};
/// # fn wrap(validator: impl huskarl_resource_server::validator::AccessTokenValidator) {
/// let resource = "my-api";
/// let observed = ObservedValidator::builder()
///     .inner(validator)
///     .on_validate(move |event: &ValidationEvent<'_>| {
///         metrics::counter!(
///             "my.token.validate",
///             "resource" => resource,
///             "issuer" => event.iss.unwrap_or("unknown").to_owned(),
///             "outcome" => event.outcome.as_str(),
///         )
///         .increment(1);
///         if let Some(error) = event.error {
///             eprintln!("token rejected: {error:?}");
///         }
///     })
///     .build();
/// # let _ = observed;
/// # }
/// ```
pub struct ObservedValidator<V> {
    inner: V,
    on_validate: Arc<dyn OnValidate>,
}

#[bon::bon]
impl<V> ObservedValidator<V> {
    /// Creates a new [`ObservedValidator`].
    #[builder]
    pub fn new(
        /// The validator whose outcomes are observed.
        inner: V,
        /// Callback invoked after each `validate_request` call.
        #[builder(with = |cb: impl OnValidate + 'static| Arc::new(cb) as Arc<dyn OnValidate>)]
        on_validate: Arc<dyn OnValidate>,
    ) -> Self {
        Self { inner, on_validate }
    }
}

impl<V> ObservedValidator<V> {
    /// Returns a reference to the inner validator.
    pub fn inner(&self) -> &V {
        &self.inner
    }

    /// Unwraps the inner validator.
    pub fn into_inner(self) -> V {
        self.inner
    }
}

impl<V: AccessTokenValidator> AccessTokenValidator for ObservedValidator<V> {
    type Claims = V::Claims;
    type Error = V::Error;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<Self::Claims, Self::Error>> {
        Box::pin(async move {
            let result = self
                .inner
                .validate_request(headers, method, uri, client_cert_der)
                .await;

            let event = match &result.outcome {
                Ok(Some(validated)) => ValidationEvent {
                    outcome: ValidationOutcome::Success,
                    error: None,
                    iss: validated.iss.as_deref(),
                },
                Ok(None) => ValidationEvent {
                    outcome: ValidationOutcome::NoToken,
                    error: None,
                    iss: None,
                },
                Err(e) => ValidationEvent {
                    outcome: e.validation_outcome(),
                    error: Some(e),
                    iss: e.issuer(),
                },
            };
            self.on_validate.on_validate(&event);

            result
        })
    }
}

impl<V: ProvideValidatorMetadata> ProvideValidatorMetadata for ObservedValidator<V> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.inner.validator_metadata(resource)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use rstest::rstest;

    use super::*;
    use crate::{
        core::{
            jwt::validator::JwtValidationError,
            platform::{Duration, SystemTime},
        },
        validator::{
            ValidatedRequest,
            binding::DPoPBindingError,
            error::{TokenBindingError, ValidateHeadersError},
            introspection::IntrospectionValidateError,
            multi_issuer::MultiIssuerError,
        },
    };

    /// A validator double that returns a fixed outcome on every request.
    struct StubValidator {
        result: fn() -> Result<Option<ValidatedRequest<()>>, ValidateHeadersError>,
    }

    impl AccessTokenValidator for StubValidator {
        type Claims = ();
        type Error = ValidateHeadersError;

        fn validate_request<'a>(
            &'a self,
            _headers: &'a http::HeaderMap,
            _method: &'a http::Method,
            _uri: &'a http::Uri,
            _client_cert_der: Option<&'a [u8]>,
        ) -> MaybeSendBoxFuture<'a, ValidationResult<(), ValidateHeadersError>> {
            Box::pin(async {
                ValidationResult {
                    outcome: (self.result)(),
                    dpop_nonce: None,
                }
            })
        }
    }

    impl ProvideValidatorMetadata for StubValidator {
        fn validator_metadata(&self, _resource: Option<&str>) -> ValidatorMetadata {
            ValidatorMetadata::builder().build()
        }
    }

    fn validated(iss: Option<&str>) -> ValidatedRequest<()> {
        ValidatedRequest {
            iss: iss.map(str::to_owned),
            sub: None,
            aud: Vec::new(),
            jti: None,
            iat: None,
            exp: None,
            cnf: None,
            claims: (),
            introspection_jwt: None,
        }
    }

    fn binding_error() -> ValidateHeadersError {
        ValidateHeadersError::Binding {
            token_type: crate::TokenType::DPoP,
            source: TokenBindingError::MissingDPoPHeader,
        }
    }

    fn dpop_binding(source: DPoPBindingError) -> ValidateHeadersError {
        ValidateHeadersError::Binding {
            token_type: crate::TokenType::DPoP,
            source: TokenBindingError::DPoPBinding { source },
        }
    }

    #[rstest]
    #[case::success(
        || Ok(Some(validated(Some("https://as.example")))),
        ValidationOutcome::Success,
        Some("https://as.example")
    )]
    #[case::no_token(|| Ok(None), ValidationOutcome::NoToken, None)]
    #[case::error(|| Err(binding_error()), ValidationOutcome::BindingError, None)]
    #[tokio::test]
    async fn observes_each_validation(
        #[case] result: fn() -> Result<Option<ValidatedRequest<()>>, ValidateHeadersError>,
        #[case] expected: ValidationOutcome,
        #[case] expected_iss: Option<&str>,
    ) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let observed = ObservedValidator::builder()
            .inner(StubValidator { result })
            .on_validate(move |event: &ValidationEvent<'_>| {
                sink.lock().unwrap().push((
                    event.outcome,
                    event.error.is_some(),
                    event.iss.map(str::to_owned),
                ));
            })
            .build();

        let outcome = observed
            .validate_request(
                &http::HeaderMap::new(),
                &http::Method::GET,
                &http::Uri::from_static("https://api.example/resource"),
                None,
            )
            .await
            .outcome;

        // The observed result passes through unchanged; a rejection carries
        // its error detail on the event.
        let expect_error = expected == ValidationOutcome::BindingError;
        assert_eq!(outcome.is_err(), expect_error);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(expected, expect_error, expected_iss.map(str::to_owned))]
        );
    }

    #[rstest]
    // Expired splits out of the invalid-token bucket; other JWT failures stay.
    #[case::expired(
        ValidateHeadersError::InvalidJwt {
            token_type: crate::TokenType::Bearer,
            source: JwtValidationError::Expired {
                expiration: SystemTime::UNIX_EPOCH,
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            },
        },
        ValidationOutcome::Expired
    )]
    #[case::bad_signature(
        ValidateHeadersError::InvalidJwt {
            token_type: crate::TokenType::Bearer,
            source: JwtValidationError::UnsignedToken,
        },
        ValidationOutcome::InvalidToken
    )]
    // A nonce challenge is routine churn, not a binding failure.
    #[case::nonce_required(
        dpop_binding(DPoPBindingError::NonceRequired { nonce: "n".into() }),
        ValidationOutcome::NonceRequired
    )]
    #[case::thumbprint_mismatch(
        dpop_binding(DPoPBindingError::ThumbprintMismatch),
        ValidationOutcome::BindingError
    )]
    // Wire-5xx rejections are our failure, not the client's, whichever
    // check tripped them.
    #[case::server_fault(
        dpop_binding(DPoPBindingError::RequestUriNotAbsolute { uri: "/x".into() }),
        ValidationOutcome::CallError
    )]
    fn validate_headers_errors_classify(
        #[case] error: ValidateHeadersError,
        #[case] expected: ValidationOutcome,
    ) {
        assert_eq!(error.validation_outcome(), expected);
    }

    #[test]
    fn introspection_inactive_token_is_invalid_not_call_error() {
        let error = IntrospectionValidateError::Call {
            token_type: crate::TokenType::Bearer,
            source: crate::introspection::IntrospectionCallError::TokenInactive,
        };
        assert_eq!(error.validation_outcome(), ValidationOutcome::InvalidToken);
    }

    /// Multi-issuer failures classify through the boxed inner error and carry
    /// the routed issuer, so one wrapper around a `MultiIssuerValidator`
    /// yields per-issuer labels for routing and delegated failures alike.
    #[rstest]
    #[case::routing(
        MultiIssuerError::UnrecognizedIssuer { iss: Some("https://rogue.example".into()) },
        ValidationOutcome::UnrecognizedIssuer,
        // Unverified `iss` values never become labels.
        None
    )]
    #[case::delegated(
        MultiIssuerError::Validation {
            issuer: "https://as.example".into(),
            error: Box::new(binding_error()),
        },
        ValidationOutcome::BindingError,
        Some("https://as.example")
    )]
    fn multi_issuer_errors_classify(
        #[case] error: MultiIssuerError,
        #[case] expected: ValidationOutcome,
        #[case] expected_iss: Option<&str>,
    ) {
        assert_eq!(error.validation_outcome(), expected);
        assert_eq!(error.issuer(), expected_iss);
    }

    /// One wrapper around the composite is enough: delegated failures carry the
    /// routed issuer, successes fall back to it when the source drops the
    /// `iss` claim, and foreign tokens surface as `UnrecognizedIssuer`.
    #[rstest]
    #[case::registered_failure(
        "https://as.example",
        || Err(binding_error()),
        ValidationOutcome::BindingError,
        Some("https://as.example")
    )]
    #[case::registered_success_source_drops_iss(
        "https://as.example",
        || Ok(Some(validated(None))),
        ValidationOutcome::Success,
        Some("https://as.example")
    )]
    #[case::foreign(
        "https://rogue.example",
        || Err(binding_error()),
        ValidationOutcome::UnrecognizedIssuer,
        None
    )]
    #[tokio::test]
    async fn one_decorator_over_multi_issuer_labels_per_issuer(
        #[case] token_iss: &str,
        #[case] result: fn() -> Result<Option<ValidatedRequest<()>>, ValidateHeadersError>,
        #[case] expected: ValidationOutcome,
        #[case] expected_iss: Option<&str>,
    ) {
        use base64::prelude::*;

        use crate::validator::multi_issuer::MultiIssuerValidator;

        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let observed = ObservedValidator::builder()
            .inner(
                MultiIssuerValidator::builder()
                    .source("https://as.example", StubValidator { result })
                    .build(),
            )
            .on_validate(move |event: &ValidationEvent<'_>| {
                sink.lock()
                    .unwrap()
                    .push((event.outcome, event.iss.map(str::to_owned)));
            })
            .build();

        let seg = |s: &str| BASE64_URL_SAFE_NO_PAD.encode(s);
        let token = format!(
            "{}.{}.{}",
            seg(r#"{"alg":"RS256"}"#),
            seg(&format!(r#"{{"iss":"{token_iss}"}}"#)),
            seg("sig"),
        );
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        observed
            .validate_request(
                &headers,
                &http::Method::GET,
                &http::Uri::from_static("https://api.example/resource"),
                None,
            )
            .await;

        assert_eq!(
            *seen.lock().unwrap(),
            vec![(expected, expected_iss.map(str::to_owned))]
        );
    }
}
