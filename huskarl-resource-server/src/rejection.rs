//! Turning a validation failure into an HTTP rejection response.
//!
//! A standards-compliant rejection has up to three ingredients:
//!
//! 1. an HTTP **status code** — 400/401/403 for client errors (RFC 6750 §3.1),
//!    a 5xx code for server-side failures;
//! 2. one or more **`WWW-Authenticate`** challenges, carrying the error code
//!    and description for client errors, and omitted entirely for server
//!    errors (re-authenticating would not help);
//! 3. a **`DPoP-Nonce`** header, when the validator issued a fresh nonce the
//!    client must echo in its next proof (RFC 9449 §8).
//!
//! [`Rejection`] bundles all three. Build one directly from a validation
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
    /// Per RFC 7235 the values may be sent as separate `WWW-Authenticate`
    /// headers or joined with `, ` on a single header — both are equivalent.
    pub www_authenticate: Vec<String>,
    /// A nonce to include in the response `DPoP-Nonce` header, if any.
    pub dpop_nonce: Option<String>,
}

impl Rejection {
    /// Applies the status code, `WWW-Authenticate` challenges, and
    /// `DPoP-Nonce` header to a response builder.
    ///
    /// Every value this crate produces is a valid header value, so the
    /// builder cannot fail on account of this call.
    ///
    /// ```
    /// # use huskarl_resource_server::{error::InsufficientScope, validator::metadata::ValidatorMetadata};
    /// # fn example() -> Result<(), http::Error> {
    /// let metadata = ValidatorMetadata::builder().realm("api").build();
    /// let rejection = metadata.rejection(&InsufficientScope, Some("read write"));
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
        builder
    }
}

impl ValidatorMetadata {
    /// Builds the [`Rejection`] for a validation or authorization error.
    ///
    /// The status code comes from the error's
    /// [classification](ToRfc6750Error::token_error), and the
    /// `WWW-Authenticate` challenges from [`challenges`](Self::challenges)
    /// (empty for server-side failures). `scope` is included as the
    /// challenges' `scope` parameter — pass the scope the resource requires,
    /// particularly for [`InsufficientScope`](crate::error::InsufficientScope)
    /// rejections.
    ///
    /// The returned rejection has no `DPoP` nonce; when rejecting after a
    /// [`ValidationResult`] that carried one, either use
    /// [`ValidationResult::rejection`] or copy
    /// [`dpop_nonce`](ValidationResult::dpop_nonce) over.
    #[must_use]
    pub fn rejection(&self, error: &dyn ToRfc6750Error, scope: Option<&str>) -> Rejection {
        Rejection {
            status: error.token_error().suggested_status(),
            www_authenticate: self.challenges(Some(error), scope, None),
            dpop_nonce: None,
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
            },
            Err(error) => metadata.rejection(error, scope),
        };
        rejection.dpop_nonce.clone_from(&self.dpop_nonce);
        Some(rejection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TokenType,
        error::{InsufficientScope, TokenErrorCode, TokenValidationError},
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
            Self(TokenValidationError::Server(http::StatusCode::BAD_GATEWAY))
        }
    }

    impl ToRfc6750Error for TestError {
        fn attempted_scheme(&self) -> Option<TokenType> {
            None
        }

        fn token_error(&self) -> TokenValidationError {
            self.0.clone()
        }

        fn error_description(&self) -> Option<String> {
            None
        }
    }

    fn meta() -> ValidatorMetadata {
        ValidatorMetadata::builder().realm("api").build()
    }

    fn validated() -> ValidatedRequest<()> {
        ValidatedRequest {
            issuer: None,
            subject: None,
            audience: Vec::new(),
            jti: None,
            issued_at: None,
            expiration: None,
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
    }

    #[test]
    fn metadata_rejection_insufficient_scope_is_403_with_scope() {
        let rejection = meta().rejection(&InsufficientScope, Some("read write"));
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
