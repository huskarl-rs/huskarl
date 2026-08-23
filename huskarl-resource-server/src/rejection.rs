//! Turning a validation failure into an HTTP rejection response.
//!
//! A standards-compliant rejection has up to four ingredients:
//!
//! 1. an HTTP **status code** — 400/401/403 for client errors (RFC 6750 §3.1),
//!    a 5xx code for server-side failures;
//! 2. one or more **`WWW-Authenticate`** challenges, carrying the error code
//!    and description for client errors, and omitted entirely for server
//!    errors (re-authenticating would not help);
//! 3. a **`DPoP-Nonce`** header, when the validator issued a fresh nonce the
//!    client must echo in its next proof (RFC 9449 §8);
//! 4. a **`Retry-After`** header, when a server-side failure includes a retry
//!    interval (RFC 9110 §10.2.3).
//!
//! [`Rejection`] bundles all four. Build one directly from a validation
//! result:
//!
//! ```
//! # use huskarl_resource_server::validator::{ValidationResult, metadata::ValidatorMetadata};
//! # fn handle(
//! #     result: ValidationResult<(), huskarl_resource_server::validator::error::ValidateHeadersError>,
//! #     metadata: ValidatorMetadata,
//! # ) -> Result<(), http::Error> {
//! if let Some(rejection) = result.rejection(&metadata, Some("read")) {
//!     let response = rejection.apply(http::Response::builder()).body(())?;
//!     # let _ = response;
//!     // …return the response…
//! }
//! # Ok(())
//! # }
//! ```
//!
//! or from [`ValidatorMetadata`] and an application-level error such as
//! [`InsufficientScope`](crate::error::InsufficientScope) when a *valid* token
//! does not authorize the request.
//!
//! A `DPoP` nonce can also arrive with a **successful** validation (the
//! checker rotates nonces before they expire): echo
//! [`ValidationResult::dpop_nonce`] in a `DPoP-Nonce` header on success
//! responses too, or clients lose nonce freshness and pay a
//! `use_dpop_nonce` retry on a later request.

use crate::{
    error::ToRfc6750Error,
    validator::{ValidationResult, metadata::ValidatorMetadata},
};

/// The ingredients of an HTTP response rejecting an unauthenticated or
/// unauthorized request.
///
/// Built by [`ValidationResult::rejection`] (which carries the `DPoP` nonce
/// through) or [`ValidatorMetadata::rejection`] (for application-level
/// rejections such as [`InsufficientScope`](crate::error::InsufficientScope)).
/// Stamp it onto a response with [`apply`](Self::apply), or read the fields
/// and build the response in your framework's own vocabulary.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rejection {
    /// The HTTP status code to respond with.
    pub status: http::StatusCode,
    /// The `WWW-Authenticate` challenge values to include.
    ///
    /// Empty for server-side failures, which must not carry a challenge.
    /// Per RFC 9110 §§5.2 and 11.6.1, the values may be sent as separate
    /// `WWW-Authenticate` fields or combined into one comma-separated field.
    pub www_authenticate: Vec<String>,
    /// A nonce to include in the response `DPoP-Nonce` header, if any.
    pub dpop_nonce: Option<String>,
    /// How long the client should wait before re-attempting, for the
    /// `Retry-After` header (RFC 9110 §10.2.3).
    ///
    /// [`apply`](Self::apply) emits this as delta-seconds, rounding a non-zero
    /// fractional second up. `None` omits the header. Client errors always have
    /// no retry interval.
    pub retry_after: Option<crate::core::platform::Duration>,
}

impl Rejection {
    /// Applies this rejection's status and headers to a response builder.
    ///
    /// Every value this crate produces is a valid header value, so the
    /// builder cannot fail on account of this call.
    ///
    /// ```
    /// # use huskarl_resource_server::{error::InsufficientScope, validator::metadata::ValidatorMetadata};
    /// # fn example() -> Result<(), http::Error> {
    /// let metadata = ValidatorMetadata::builder().realm("api").build();
    /// let rejection = metadata.rejection(&InsufficientScope::new("read write"), None);
    ///
    /// let response = rejection.apply(http::Response::builder()).body(())?;
    ///
    /// assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    /// # Ok(())
    /// # }
    /// # example().unwrap();
    /// ```
    #[must_use]
    pub fn apply(&self, builder: http::response::Builder) -> http::response::Builder {
        let mut builder = builder.status(self.status);
        for challenge in &self.www_authenticate {
            builder = builder.header(http::header::WWW_AUTHENTICATE, challenge.as_str());
        }
        if let Some(nonce) = &self.dpop_nonce {
            builder = builder.header("DPoP-Nonce", nonce.as_str());
        }
        if let Some(after) = self.retry_after {
            // Delta-seconds avoids clock synchronization. Round fractions up
            // so a remaining cooldown never renders as `Retry-After: 0`.
            let seconds = after
                .as_secs()
                .saturating_add(u64::from(after.subsec_nanos() > 0));
            builder = builder.header(http::header::RETRY_AFTER, seconds);
        }
        builder
    }
}

impl ValidatorMetadata {
    /// Builds the [`Rejection`] for a validation or authorization error.
    ///
    /// The status code comes from the error's
    /// [`Challenge::error`](crate::error::Challenge::error), and the
    /// `WWW-Authenticate` challenges from [`challenges`](Self::challenges)
    /// (empty for server-side failures). The challenges' `scope` attribute
    /// comes from the error's own
    /// [`Challenge::scope`](crate::error::Challenge::scope) when set — e.g.
    /// [`InsufficientScope::new`](crate::error::InsufficientScope::new) —
    /// falling back to the `scope` argument.
    ///
    /// Server errors carry no `WWW-Authenticate` challenge and propagate their
    /// optional `Retry-After` interval. The returned rejection has no `DPoP`
    /// nonce; when rejecting after a
    /// [`ValidationResult`] that carried one, either use
    /// [`ValidationResult::rejection`] or copy
    /// [`dpop_nonce`](ValidationResult::dpop_nonce) over.
    #[must_use]
    pub fn rejection(&self, error: &dyn ToRfc6750Error, scope: Option<&str>) -> Rejection {
        let challenge = error.challenge();
        Rejection {
            status: challenge.error.suggested_status(),
            www_authenticate: self.challenges_from(
                error.attempted_scheme(),
                Some(&challenge),
                scope,
                None,
            ),
            dpop_nonce: None,
            retry_after: challenge.error.retry_after(),
        }
    }
}

impl<C, E: ToRfc6750Error> ValidationResult<C, E> {
    /// Builds the [`Rejection`] for this result, or `None` when a valid token
    /// was found.
    ///
    /// - `Ok(Some(_))` — authenticated; returns `None`. (Remember to echo
    ///   [`dpop_nonce`](Self::dpop_nonce) on the success response.)
    /// - `Ok(None)` — no credentials presented; a `401` with the
    ///   [unauthenticated challenges](ValidatorMetadata::unauthenticated_challenges).
    ///   Endpoints that also serve anonymous requests should consult
    ///   [`outcome`](Self::outcome) instead of rejecting unconditionally.
    /// - `Err(_)` — invalid token; status and challenges via
    ///   [`ValidatorMetadata::rejection`].
    ///
    /// Any `DPoP` nonce on this result is carried into the rejection, so the
    /// `DPoP-Nonce` header survives the error path — dropping it strands
    /// clients in a `use_dpop_nonce` retry loop.
    ///
    /// Get the metadata from the validator's
    /// [`validator_metadata`](crate::validator::metadata::ProvideValidatorMetadata::validator_metadata);
    /// `scope` is included as the challenges' `scope` parameter.
    #[must_use]
    pub fn rejection(
        &self,
        metadata: &ValidatorMetadata,
        scope: Option<&str>,
    ) -> Option<Rejection> {
        let mut rejection = match &self.outcome {
            Ok(Some(_)) => return None,
            Ok(None) => Rejection {
                status: http::StatusCode::UNAUTHORIZED,
                www_authenticate: metadata.unauthenticated_challenges(scope),
                dpop_nonce: None,
                // Nothing failed: no credentials were presented. There is no
                // interval to wait out, only a login to perform.
                retry_after: None,
            },
            Err(error) => metadata.rejection(error, scope),
        };
        rejection.dpop_nonce.clone_from(&self.dpop_nonce);
        Some(rejection)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::{
        TokenType,
        error::{Challenge, InsufficientScope, ServerStatus, TokenErrorCode, TokenValidationError},
        validator::ValidatedRequest,
    };

    /// A configurable [`ToRfc6750Error`] test double.
    #[derive(Debug)]
    struct TestError(TokenValidationError);

    impl TestError {
        fn client(code: TokenErrorCode) -> Self {
            Self(TokenValidationError::Client(code))
        }

        fn server() -> Self {
            Self(TokenValidationError::server(ServerStatus::BAD_GATEWAY))
        }

        /// A server-side failure that knows how long it will last.
        fn unavailable_for(after: crate::core::platform::Duration) -> Self {
            Self(TokenValidationError::Server {
                status: ServerStatus::SERVICE_UNAVAILABLE,
                retry_after: Some(after),
            })
        }
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("test error")
        }
    }

    impl std::error::Error for TestError {}

    impl ToRfc6750Error for TestError {
        fn attempted_scheme(&self) -> Option<TokenType> {
            None
        }

        fn challenge(&self) -> Challenge {
            Challenge::new(self.0.clone())
        }
    }

    fn meta() -> ValidatorMetadata {
        ValidatorMetadata::builder().realm("api").build()
    }

    fn validated() -> ValidatedRequest<()> {
        ValidatedRequest {
            iss: None,
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

    #[test]
    fn metadata_rejection_client_error() {
        let rejection = meta().rejection(&TestError::client(TokenErrorCode::InvalidToken), None);
        assert_eq!(rejection.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejection.www_authenticate,
            vec![r#"Bearer realm="api", error="invalid_token""#]
        );
        assert_eq!(rejection.dpop_nonce, None);
    }

    #[test]
    fn metadata_rejection_server_error_has_no_challenges() {
        let rejection = meta().rejection(&TestError::server(), None);
        assert_eq!(rejection.status, http::StatusCode::BAD_GATEWAY);
        assert!(rejection.www_authenticate.is_empty());
        // Nothing measured an interval, so nothing is claimed.
        assert_eq!(rejection.retry_after, None);
    }

    /// The interval a lower layer measured has to reach the wire, or the whole
    /// chain that carried it — a secret provider's cooldown, an upstream
    /// `Retry-After`, `RetryAdvice::Retry { after }` — ends in a 503 that tells
    /// the client to guess.
    #[test]
    fn a_server_error_that_named_an_interval_emits_retry_after() {
        let after = crate::core::platform::Duration::from_secs(30);
        let rejection = meta().rejection(&TestError::unavailable_for(after), None);

        assert_eq!(rejection.status, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejection.retry_after, Some(after));

        let response = rejection
            .apply(http::Response::builder())
            .body(())
            .expect("valid header values");
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER),
            Some(&http::HeaderValue::from_static("30")),
        );
    }

    /// A sub-second remainder rounds up. `Retry-After: 0` is "retry now",
    /// which is the one thing a source with time left on its cooldown does not
    /// mean — and truncation is how it would come to say it.
    #[test]
    fn a_part_second_interval_never_renders_as_retry_now() {
        let rejection = meta().rejection(
            &TestError::unavailable_for(crate::core::platform::Duration::from_millis(100)),
            None,
        );
        let response = rejection
            .apply(http::Response::builder())
            .body(())
            .expect("valid header values");
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER),
            Some(&http::HeaderValue::from_static("1")),
        );
    }

    #[test]
    fn retry_after_ceiling_saturates_for_duration_max() {
        let rejection = meta().rejection(
            &TestError::unavailable_for(crate::core::platform::Duration::MAX),
            None,
        );
        let response = rejection
            .apply(http::Response::builder())
            .body(())
            .expect("valid header values");
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER),
            Some(&http::HeaderValue::from_static("18446744073709551615")),
        );
    }

    #[test]
    fn metadata_rejection_reads_the_challenge_once() {
        #[derive(Debug)]
        struct CountingError(AtomicUsize);

        impl std::fmt::Display for CountingError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("counting error")
            }
        }

        impl std::error::Error for CountingError {}

        impl ToRfc6750Error for CountingError {
            fn attempted_scheme(&self) -> Option<TokenType> {
                Some(TokenType::Bearer)
            }

            fn challenge(&self) -> Challenge {
                self.0.fetch_add(1, Ordering::Relaxed);
                Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                    .with_description("bad token")
            }
        }

        let error = CountingError(AtomicUsize::new(0));
        let rejection = meta().rejection(&error, None);

        assert_eq!(error.0.load(Ordering::Relaxed), 1);
        assert_eq!(rejection.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejection.www_authenticate,
            vec![r#"Bearer realm="api", error="invalid_token", error_description="bad token""#],
        );
    }

    /// A client error is a verdict on the token, and no amount of waiting
    /// makes an invalid one valid — so no header, whatever the challenge says.
    #[test]
    fn a_client_error_never_carries_retry_after() {
        let rejection = meta().rejection(&TestError::client(TokenErrorCode::InvalidToken), None);
        assert_eq!(rejection.retry_after, None);

        let response = rejection
            .apply(http::Response::builder())
            .body(())
            .expect("valid header values");
        assert!(
            response.headers().get(http::header::RETRY_AFTER).is_none(),
            "an invalid token does not become valid by waiting"
        );
    }

    #[test]
    fn metadata_rejection_insufficient_scope_is_403_with_scope() {
        // The error carries the required scope itself; no positional scope needed.
        let rejection = meta().rejection(&InsufficientScope::new("read write"), None);
        assert_eq!(rejection.status, http::StatusCode::FORBIDDEN);
        assert_eq!(rejection.www_authenticate.len(), 1);
        assert!(rejection.www_authenticate[0].contains(r#"scope="read write""#));
        assert!(
            rejection.www_authenticate[0].contains(r#"error="insufficient_scope""#),
            "challenge: {}",
            rejection.www_authenticate[0]
        );
    }

    #[test]
    fn result_rejection_none_when_authenticated() {
        let result: ValidationResult<(), TestError> = ValidationResult {
            outcome: Ok(Some(validated())),
            dpop_nonce: Some("fresh".to_string()),
        };
        assert!(result.rejection(&meta(), None).is_none());
    }

    #[test]
    fn result_rejection_unauthenticated_is_401_without_error_details() {
        let result: ValidationResult<(), TestError> = ValidationResult {
            outcome: Ok(None),
            dpop_nonce: None,
        };
        let rejection = result.rejection(&meta(), Some("read")).unwrap();
        assert_eq!(rejection.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejection.www_authenticate,
            vec![r#"Bearer realm="api", scope="read""#]
        );
    }

    #[test]
    fn result_rejection_carries_dpop_nonce() {
        let result: ValidationResult<(), TestError> = ValidationResult {
            outcome: Err(TestError::client(TokenErrorCode::UseDPoPNonce)),
            dpop_nonce: Some("fresh".to_string()),
        };
        let rejection = result.rejection(&meta(), None).unwrap();
        assert_eq!(rejection.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(rejection.dpop_nonce.as_deref(), Some("fresh"));
    }

    #[test]
    fn apply_sets_status_all_challenges_and_nonce() {
        let mut metadata = meta();
        metadata.dpop_supported = Some(true);
        let result: ValidationResult<(), TestError> = ValidationResult {
            outcome: Err(TestError::client(TokenErrorCode::InvalidToken)),
            dpop_nonce: Some("fresh".to_string()),
        };
        let rejection = result.rejection(&metadata, None).unwrap();

        let response = rejection.apply(http::Response::builder()).body(()).unwrap();

        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        let challenges: Vec<_> = response
            .headers()
            .get_all(http::header::WWW_AUTHENTICATE)
            .iter()
            .collect();
        assert_eq!(challenges.len(), 2, "one Bearer and one DPoP challenge");
        assert_eq!(
            response.headers().get("DPoP-Nonce").unwrap(),
            &http::HeaderValue::from_static("fresh")
        );
    }
}
