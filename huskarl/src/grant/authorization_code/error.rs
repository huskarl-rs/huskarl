use snafu::Snafu;

use crate::core::Error;

/// The cause of an authorization-code completion failure.
#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[cfg_attr(test, derive(strum::EnumCount))]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub(crate) enum CompleteError {
    /// The callback contained an OAuth error response (RFC 6749 §4.1.2.1).
    ///
    /// Only a response bound to the flow reaches this variant; an unsolicited
    /// one is [`StateMismatch`](Self::StateMismatch).
    ///
    /// The wrapping [`Error`] also exposes this value through
    /// [`Error::verdict`](crate::core::Error::verdict).
    #[snafu(display("the authorization endpoint returned {verdict}"))]
    #[non_exhaustive]
    #[classify(with = CompleteError::judged_at_the_authorization_endpoint)]
    OAuthError {
        /// The RFC 6749 §4.1.2.1 error response.
        verdict: crate::core::OAuthError,
    },
    /// There was a mismatch between the required and returned issuer values.
    #[snafu(display("issuer mismatch: original = {}, callback = {}", original, callback))]
    #[classify(no)]
    IssuerMismatch {
        /// The required issuer value.
        original: String,
        /// The issuer value returned to the callback.
        callback: String,
    },
    /// There was a mismatch between the required and returned state values.
    #[snafu(display("state mismatch between original request and callback"))]
    #[classify(no)]
    StateMismatch,
    /// The authorization server claimed to support issuer identification but no issuer was returned.
    #[snafu(display(
        "authorization server claims to support issuer identification but no issuer returned"
    ))]
    #[classify(no)]
    MissingIssuer,
    /// The token response included an ID token but the grant cannot validate it.
    #[snafu(display(
        "ID token received but the grant cannot validate it; \
         configure a 'jwks_uri' (via server metadata or the builder) or supply a \
         'jws_verifier_factory'"
    ))]
    #[classify(no)]
    IdTokenVerifierNotConfigured,
    /// The token response included an ID token but no issuer was configured on the grant.
    #[snafu(display(
        "ID token received but grant has no issuer configured; provide an issuer via server metadata or builder"
    ))]
    #[classify(no)]
    IdTokenIssuerNotConfigured,
    /// `openid` was granted but the token response carried no ID token.
    #[snafu(display(
        "openid scope granted but token response contained no ID token (OIDC Core 1.0 §3.1.3.3)"
    ))]
    #[classify(no)]
    MissingIdToken,
    /// A JARM response mode was requested but the callback carried plain
    /// parameters — a possible downgrade to an unsigned response.
    #[snafu(display(
        "a JWT-secured authorization response (JARM) was requested but the callback \
         carried plain parameters; refusing the unsigned response"
    ))]
    #[classify(no)]
    MissingJarmResponse,
    /// The callback carried a JARM `response` JWT but none was requested.
    #[snafu(display(
        "callback carried a JARM 'response' JWT but no JWT-secured response mode was requested"
    ))]
    #[classify(no)]
    UnexpectedJarmResponse,
    /// The JARM response JWT failed validation.
    #[snafu(display("JARM response JWT validation failed"))]
    #[classify(with = CompleteError::jarm_validation_origin)]
    JarmValidation {
        /// The underlying validation error.
        source: crate::core::jwt::validator::JwtValidationError,
    },
    /// A validated JARM response carried neither an error nor this parameter.
    #[snafu(display("JARM response is missing the '{param}' claim"))]
    #[classify(no)]
    JarmMissingParameter {
        /// The missing parameter name.
        param: &'static str,
    },
    /// A JARM response was received but the grant cannot validate it.
    #[snafu(display(
        "JARM response received but the grant cannot validate it; \
         configure a 'jwks_uri' (via server metadata or the builder) or supply a \
         'jws_verifier_factory'"
    ))]
    #[classify(no)]
    JarmVerifierNotConfigured,
    /// A JARM response was received but no issuer is configured on the grant.
    #[snafu(display(
        "JARM response received but grant has no issuer configured; \
         provide an issuer via server metadata or builder"
    ))]
    #[classify(no)]
    JarmIssuerNotConfigured,
}

impl CompleteError {
    /// Classifies an OAuth callback error as an authorization-endpoint verdict.
    /// A well-formed rejection, such as the user denying access, is not a
    /// protocol failure.
    fn judged_at_the_authorization_endpoint(
        verdict: &crate::core::OAuthError,
    ) -> crate::core::error::propagation::Origin<'static> {
        crate::core::error::propagation::Origin::Establishes(
            crate::core::error::propagation::Classification::judged(
                verdict.code().implied_retry_advice(),
                verdict.clone(),
            ),
        )
    }

    fn jarm_validation_origin(
        source: &crate::core::jwt::validator::JwtValidationError,
    ) -> crate::core::error::propagation::Origin<'_> {
        crate::core::error::propagation::Cause::origin(source)
    }
}

impl CompleteError {
    /// The outcome label for this failure.
    ///
    /// The exhaustive match requires every new variant to select a label.
    #[cfg(any(feature = "metrics", test))]
    pub(crate) fn outcome(&self) -> crate::grant::GrantOutcome {
        use crate::grant::GrantOutcome as O;
        match self {
            // Keep security signals separate from general protocol failures.
            Self::IssuerMismatch { .. } => O::IssuerMismatch,
            Self::StateMismatch => O::StateMismatch,
            Self::MissingJarmResponse | Self::UnexpectedJarmResponse => O::JarmDowngrade,
            Self::OAuthError { .. } => O::Rejected,
            Self::IdTokenVerifierNotConfigured
            | Self::IdTokenIssuerNotConfigured
            | Self::JarmVerifierNotConfigured
            | Self::JarmIssuerNotConfigured => O::NotConfigured,
            Self::MissingIssuer
            | Self::MissingIdToken
            | Self::JarmValidation { .. }
            | Self::JarmMissingParameter { .. } => O::Protocol,
        }
    }
}

/// The cause of a failure while starting or completing an authorization-code flow.
#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[cfg_attr(test, derive(strum::EnumCount))]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub(crate) enum FlowError {
    /// Building the JAR request object failed.
    #[snafu(display("creating JAR request object"))]
    CreatingRequestObject {
        /// The underlying error.
        source: Error,
    },
    /// The pushed authorization request failed.
    #[snafu(display("making PAR request"))]
    PushedAuthorizationRequest {
        /// The underlying error.
        source: Error,
    },
    /// The grant's `DPoP` key differs from the one bound at authorization time.
    #[snafu(display(
        "the grant's DPoP key does not match the key bound at authorization time \
         (dpop_jkt); bind the same session key used at start"
    ))]
    #[classify(no)]
    DPoPKeyMismatch,
    /// The ID token in the token response failed validation.
    #[snafu(display("validating ID token"))]
    #[classify(with = FlowError::id_token_validation_origin)]
    ValidatingIdToken {
        /// The underlying error.
        source: crate::token::id_token::IdTokenValidationError,
    },
    /// The authorization request parameters could not be form-encoded.
    #[snafu(display("encoding authorization request parameters"))]
    #[classify(no)]
    EncodingParameters {
        /// The underlying error.
        source: crate::core::oauth_form::FormError,
    },
    /// The assembled authorization URL is not a valid URI.
    #[snafu(display(
        "constructing authorization URL (oversized requests should be delivered via PAR)"
    ))]
    #[classify(no)]
    ConstructingAuthorizationUrl {
        /// The underlying error.
        source: http::uri::InvalidUri,
    },
}

impl FlowError {
    fn id_token_validation_origin(
        source: &crate::token::id_token::IdTokenValidationError,
    ) -> crate::core::error::propagation::Origin<'_> {
        crate::core::error::propagation::Cause::origin(source)
    }

    /// The outcome label for this failure.
    ///
    /// The exhaustive match requires every new variant to select a label.
    #[cfg(any(feature = "metrics", test))]
    pub(crate) fn outcome(&self) -> crate::grant::GrantOutcome {
        use crate::grant::GrantOutcome as O;
        match self {
            // A mismatched session key is not a server protocol failure.
            Self::DPoPKeyMismatch => O::DPoPKeyMismatch,
            Self::ValidatingIdToken { .. } => O::Protocol,
            // These failures do not establish that the server misbehaved.
            Self::CreatingRequestObject { .. }
            | Self::PushedAuthorizationRequest { .. }
            | Self::EncodingParameters { .. }
            | Self::ConstructingAuthorizationUrl { .. } => O::Other,
        }
    }
}

/// Returns the metrics outcome for a completion failure.
///
/// Grant-specific causes take precedence, followed by token-endpoint verdicts
/// and unusable responses. Failures that establish none of these are reported
/// as [`Other`](crate::grant::GrantOutcome::Other).
#[cfg(any(feature = "metrics", test))]
pub(crate) fn completion_outcome(err: &Error) -> crate::grant::GrantOutcome {
    use crate::grant::GrantOutcome as O;

    let cause = err.cause();
    if let Some(complete) = cause.downcast_ref::<CompleteError>() {
        return complete.outcome();
    }
    if let Some(flow) = cause.downcast_ref::<FlowError>() {
        return flow.outcome();
    }
    // A parsed OAuth body is a rejection only when its HTTP classification
    // established a verdict.
    if err.verdict().is_some() {
        return O::Rejected;
    }
    if cause
        .downcast_ref::<crate::grant::core::token_response::InvalidTokenResponse>()
        .is_some()
        || cause
            .downcast_ref::<crate::grant::core::form::HandleResponseError>()
            .is_some_and(crate::grant::core::form::HandleResponseError::is_unusable_response)
    {
        return O::Protocol;
    }
    O::Other
}

/// The cause of an authorization-code start failure.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub(crate) enum StartError {
    /// An OIDC flow was started but the grant cannot validate ID tokens.
    #[snafu(display(
        "OIDC flow started (scope contains 'openid') but no 'jwks_uri' is configured, \
         so the required ID token (OIDC Core 1.0 §3.1.3.3) could never be \
         validated; configure a 'jwks_uri' (via server metadata or the builder) or \
         supply a 'jws_verifier_factory', or set 'oidc(false)' if 'openid' is an \
         ordinary scope on this server"
    ))]
    OidcVerifierNotConfigured,
    /// An OIDC flow was started but the grant has no issuer configured.
    #[snafu(display(
        "OIDC flow started (scope contains 'openid') but the grant has no issuer \
         configured, so the required ID token (OIDC Core 1.0 §3.1.3.3) could never be \
         validated; provide an issuer via server metadata or builder, or '.oidc(false)' \
         if 'openid' is an ordinary scope on this server"
    ))]
    OidcIssuerNotConfigured,
}

/// An error parsing authorization-callback parameters into a
/// [`CompleteInput`](super::CompleteInput).
///
/// An OAuth error response is not a parse failure: it parses, and completion
/// surfaces it as a rejection carrying the server's
/// [`verdict`](crate::core::Error::verdict).
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum ParseCallbackError {
    /// The callback parameters could not be parsed (malformed query, or a
    /// single-valued parameter that appeared more than once — RFC 6749 §3.1).
    #[snafu(display("failed to parse callback parameters"))]
    InvalidParameters {
        /// The underlying parse error.
        source: crate::core::oauth_form::FormError,
    },
    /// A required parameter was missing from the callback.
    #[snafu(display("missing required parameter: {param}"))]
    MissingParameter {
        /// The missing parameter name.
        param: &'static str,
    },
}

/// An error that occurs when building an [`AuthorizationCodeGrant`](super::AuthorizationCodeGrant).
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub(crate) enum BuildError {
    /// A JWS verifier factory was provided but no verifier platform is available.
    #[snafu(display(
        "jws_verifier_factory was set but no JWS verifier platform is configured; \
         enable the 'default-jws-verifier-platform' feature or call \
         '.jws_verifier_platform(...)' on the builder"
    ))]
    MissingJwsVerifierPlatform,
    /// PAR is required but no PAR endpoint is configured.
    #[snafu(display(
        "require_pushed_authorization_requests is set but no \
         pushed_authorization_request_endpoint is configured; supply the endpoint \
         or unset the requirement — proceeding would silently downgrade required \
         PAR (RFC 9126 §5) to a plain authorization request"
    ))]
    RequiredParEndpointMissing,
    /// `oidc(true)` was set but the grant cannot validate ID tokens.
    #[snafu(display(
        "oidc(true) was set but no 'jwks_uri' is configured (via server \
         metadata or the builder) and no 'jws_verifier_factory' was supplied, so \
         the verifier has no key source and ID tokens could never be validated"
    ))]
    OidcRequiresVerifier,
    /// `oidc(true)` was set but no issuer is configured.
    #[snafu(display(
        "oidc(true) was set but no issuer is configured; \
         provide one via server metadata or builder"
    ))]
    OidcRequiresIssuer,
    /// A JWT-secured response mode was set but the grant cannot validate JARM responses.
    #[snafu(display(
        "a JWT-secured response_mode was set but no 'jwks_uri' is configured \
         (via server metadata or the builder) and no 'jws_verifier_factory' was \
         supplied, so JARM responses could never be validated"
    ))]
    JarmRequiresVerifier,
    /// A JWT-secured response mode was set but no issuer is configured.
    #[snafu(display(
        "a JWT-secured response_mode was set but no issuer is configured; \
         provide one via server metadata or builder"
    ))]
    JarmRequiresIssuer,
}

#[cfg(test)]
mod classification {
    use super::*;
    use crate::core::{RetryAdvice, jwt::validator::JwtValidationError};

    #[test]
    fn jwt_infrastructure_failures_reach_both_authorization_wrappers() {
        let source = Error::new(RetryAdvice::RETRY, "the JTI store");
        let jarm = Error::from(CompleteError::JarmValidation {
            source: JwtValidationError::JtiCheck { source },
        });
        assert_eq!(jarm.retry_advice(), RetryAdvice::RETRY);

        let source = Error::new(RetryAdvice::RETRY, "the JTI store");
        let id_token = Error::from(FlowError::ValidatingIdToken {
            source: crate::token::id_token::IdTokenValidationError::Jwt {
                source: JwtValidationError::JtiCheck { source },
            },
        });
        assert_eq!(id_token.retry_advice(), RetryAdvice::RETRY);
    }

    // Converting the cause must preserve the server's full verdict.
    #[test]
    fn a_callback_rejection_carries_the_servers_verdict() {
        let err = Error::from(CompleteError::OAuthError {
            verdict: crate::core::OAuthError::new("invalid_scope")
                .with_description(Some(String::from("scope 'admin' is not permitted")))
                .with_uri(Some(String::from("https://as.example.com/errors"))),
        });

        let verdict = err.verdict().expect("the conversion attaches it");
        assert_eq!(verdict.code(), &crate::core::OAuthErrorCode::InvalidScope);
        assert_eq!(
            verdict.description(),
            Some("scope 'admin' is not permitted")
        );
        assert_eq!(verdict.uri(), Some("https://as.example.com/errors"));
    }

    // Callers can inspect the verdict without downcasting the cause.
    #[test]
    fn a_callback_rejection_is_read_without_a_downcast() {
        let denied = Error::from(CompleteError::OAuthError {
            verdict: crate::core::OAuthError::new("access_denied"),
        });
        assert!(
            denied
                .verdict()
                .is_some_and(|v| v.code() == &crate::core::OAuthErrorCode::AccessDenied)
        );
        assert!(!denied.verdict().unwrap().code().parameters_at_fault());

        // Preserve extension codes verbatim.
        let bespoke = Error::from(CompleteError::OAuthError {
            verdict: crate::core::OAuthError::new("something_bespoke"),
        });
        assert_eq!(
            bespoke.verdict().map(|v| v.code().as_str()),
            Some("something_bespoke")
        );
    }

    // Server-condition callback errors are retryable even though redirects
    // cannot carry a 5xx status.
    #[test]
    fn a_callback_naming_a_server_condition_is_retryable() {
        for code in ["temporarily_unavailable", "server_error"] {
            let err = Error::from(CompleteError::OAuthError {
                verdict: crate::core::OAuthError::new(code),
            });

            assert_eq!(err.retry_advice(), RetryAdvice::RETRY, "{code}");
            // Redirect parameters cannot provide `Retry-After`.
            assert_eq!(
                err.retry_advice(),
                RetryAdvice::Retry { after: None },
                "{code}"
            );
        }

        // A user's denial remains terminal.
        let denied = Error::from(CompleteError::OAuthError {
            verdict: crate::core::OAuthError::new("access_denied"),
        });
        assert_eq!(denied.retry_advice(), RetryAdvice::No);
    }

    // The formatted error chain should not repeat the verdict.
    #[test]
    fn the_chain_says_the_code_once_and_the_gloss_once() {
        let err = Error::from(CompleteError::OAuthError {
            verdict: crate::core::OAuthError::new("access_denied")
                .with_description(Some(String::from("user denied")))
                .with_uri(Some(String::from("https://as.example.com/doc"))),
        });

        assert_eq!(
            format!("{err:#}"),
            "the authorization endpoint returned access_denied: user denied \
             (see https://as.example.com/doc)"
        );
        assert_eq!(
            format!("{err:#}").matches("access_denied").count(),
            1,
            "the code must appear once across the whole chain"
        );

        // Even a bare verdict identifies the endpoint that returned it.
        let bare = Error::from(CompleteError::OAuthError {
            verdict: crate::core::OAuthError::new("access_denied"),
        });
        assert_eq!(
            format!("{bare:#}"),
            "the authorization endpoint returned access_denied"
        );
    }

    // `EnumCount` makes this fail when a new variant lacks an outcome case.
    #[test]
    fn every_completion_failure_has_a_distinct_outcome() {
        use strum::EnumCount as _;

        use crate::grant::GrantOutcome as O;

        let cases = [
            (
                CompleteError::IssuerMismatch {
                    original: String::new(),
                    callback: String::new(),
                },
                O::IssuerMismatch,
            ),
            (CompleteError::StateMismatch, O::StateMismatch),
            (CompleteError::MissingJarmResponse, O::JarmDowngrade),
            (CompleteError::UnexpectedJarmResponse, O::JarmDowngrade),
            (
                CompleteError::OAuthError {
                    verdict: crate::core::OAuthError::new("access_denied"),
                },
                O::Rejected,
            ),
            (
                CompleteError::IdTokenVerifierNotConfigured,
                O::NotConfigured,
            ),
            (CompleteError::IdTokenIssuerNotConfigured, O::NotConfigured),
            (CompleteError::JarmVerifierNotConfigured, O::NotConfigured),
            (CompleteError::JarmIssuerNotConfigured, O::NotConfigured),
            (CompleteError::MissingIssuer, O::Protocol),
            (CompleteError::MissingIdToken, O::Protocol),
            (
                CompleteError::JarmValidation {
                    source: crate::core::jwt::validator::JwtValidationError::UnsignedToken,
                },
                O::Protocol,
            ),
            (
                CompleteError::JarmMissingParameter { param: "code" },
                O::Protocol,
            ),
        ];
        assert_eq!(
            cases.len(),
            CompleteError::COUNT,
            "a variant was added without an outcome label",
        );
        for (cause, expected) in cases {
            assert_eq!(cause.outcome(), expected, "{cause}");
        }

        // Keep security signals distinct from protocol failures and rejections.
        for signal in [O::IssuerMismatch, O::StateMismatch, O::JarmDowngrade] {
            assert_ne!(signal.as_str(), O::Protocol.as_str());
            assert_ne!(signal.as_str(), O::Rejected.as_str());
        }
    }

    // Every flow failure must have an outcome, including completion-side checks.
    #[test]
    fn every_flow_failure_has_an_outcome() {
        use strum::EnumCount as _;

        use crate::grant::GrantOutcome as O;

        let cases = [
            (FlowError::DPoPKeyMismatch, O::DPoPKeyMismatch),
            (
                FlowError::ValidatingIdToken {
                    source: crate::token::id_token::IdTokenValidationError::SubjectMissing,
                },
                O::Protocol,
            ),
            (
                FlowError::CreatingRequestObject {
                    source: Error::new(RetryAdvice::No, "the inner failure"),
                },
                O::Other,
            ),
            (
                FlowError::PushedAuthorizationRequest {
                    source: Error::new(RetryAdvice::No, "the inner failure"),
                },
                O::Other,
            ),
            (
                FlowError::EncodingParameters {
                    source: crate::core::oauth_form::FormError::Other {
                        message: String::from("bad shape"),
                    },
                },
                O::Other,
            ),
            (
                FlowError::ConstructingAuthorizationUrl {
                    source: "::".parse::<http::Uri>().unwrap_err(),
                },
                O::Other,
            ),
        ];
        assert_eq!(
            cases.len(),
            FlowError::COUNT,
            "a variant was added without an outcome label",
        );
        for (cause, expected) in cases {
            assert_eq!(cause.outcome(), expected, "{cause}");
        }
    }

    // Exercise every source used to resolve a completion outcome.
    #[test]
    fn completion_outcome_covers_every_route() {
        use crate::grant::GrantOutcome as O;

        assert_eq!(
            completion_outcome(&Error::from(CompleteError::StateMismatch)),
            O::StateMismatch
        );

        assert_eq!(
            completion_outcome(&Error::from(FlowError::DPoPKeyMismatch)),
            O::DPoPKeyMismatch
        );

        // Shared token-response causes are identified by their verdict.
        let rejected = Error::propagate(
            crate::core::error::propagation::Classification::judged(
                RetryAdvice::No,
                crate::core::OAuthError::new("invalid_grant"),
            ),
            "the token endpoint returned invalid_grant",
        );
        assert_eq!(completion_outcome(&rejected), O::Rejected);

        let unusable = Error::from(
            crate::grant::core::token_response::InvalidTokenResponse::InvalidTokenType {
                token_type: String::from("mac"),
            },
        );
        assert_eq!(completion_outcome(&unusable), O::Protocol);

        // A transport failure does not establish a protocol failure.
        assert_eq!(
            completion_outcome(&Error::new(RetryAdvice::RETRY, "connection reset")),
            O::Other
        );
    }

    // An OAuth code echoed in a 5xx response is not a server verdict.
    #[test]
    fn an_echoed_code_is_not_counted_as_a_rejection() {
        let echoed = crate::core::http::FailedResponse::new(
            http::StatusCode::SERVICE_UNAVAILABLE,
            &http::HeaderMap::new(),
        )
        .expect("not a success")
        .into_error(
            Some(crate::core::OAuthError::new("invalid_grant")),
            "the token endpoint returned invalid_grant",
        );

        assert!(echoed.verdict().is_none());
        assert_eq!(
            completion_outcome(&echoed),
            crate::grant::GrantOutcome::Other
        );
    }
}
