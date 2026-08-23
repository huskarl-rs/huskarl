//! Errors for OAuth 2.0 Dynamic Client Registration (RFC 7591 §3.2.2).

use http::{StatusCode, header::InvalidHeaderValue};
use snafu::Snafu;

use crate::core::{Error, http::TruncatedBody};

impl RegistrationError {
    /// Returns the server verdict carried by this cause, if any.
    pub(super) fn verdict(&self) -> Option<crate::core::OAuthError> {
        match self {
            Self::OAuthError { verdict } => Some(verdict.clone()),
            // These failures do not establish that the server rejected the request.
            Self::JwksConflict
            | Self::Serialize { .. }
            | Self::AuthHeader { .. }
            | Self::RequestFailed { .. }
            | Self::MissingContentType
            | Self::UnexpectedContentType { .. }
            | Self::Deserialize { .. }
            | Self::BadStatus { .. } => None,
        }
    }
}

/// The cause of a client registration failure.
#[derive(Debug, Snafu, huskarl_macros::Classify)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub(crate) enum RegistrationError {
    /// The client metadata set both `jwks` and `jwks_uri` (RFC 7591 §2 forbids
    /// sending both in the same request).
    #[snafu(display("client metadata may not set both jwks and jwks_uri (RFC 7591 §2)"))]
    #[classify(no)]
    JwksConflict,

    /// The client metadata could not be serialized to JSON.
    #[snafu(display("failed to serialize client metadata"))]
    #[classify(no)]
    Serialize {
        /// The underlying error.
        source: serde_json::Error,
    },

    /// The initial access token could not be set as an `Authorization` header.
    #[snafu(display("initial access token is not a valid HTTP header value"))]
    #[classify(no)]
    AuthHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },

    /// The registration endpoint rejected the submitted metadata (RFC 7591 §3.2.2).
    ///
    /// The wrapping [`Error`] exposes the same value through
    /// [`Error::verdict`](crate::core::Error::verdict).
    #[snafu(display("the registration endpoint returned {verdict}"))]
    #[non_exhaustive]
    #[classify(with = RegistrationError::judged_by_the_server)]
    OAuthError {
        /// The RFC 7591 §3.2.2 error response.
        verdict: crate::core::OAuthError,
    },

    /// The HTTP request itself failed.
    #[snafu(display("client registration request failed"))]
    RequestFailed {
        /// The underlying error.
        source: Error,
    },

    /// The registration response is missing the `Content-Type` header.
    ///
    /// Per RFC 7591 §3.2.1, a successful response uses `application/json`.
    #[snafu(display("registration response is missing the Content-Type header"))]
    #[classify(no)]
    MissingContentType,

    /// The registration endpoint returned an unexpected `Content-Type`.
    ///
    /// Per RFC 7591 §3.2.1, a successful response uses `application/json`.
    #[snafu(display("registration endpoint returned unexpected Content-Type: {content_type}"))]
    #[classify(no)]
    UnexpectedContentType {
        /// The Content-Type value received.
        content_type: String,
    },

    /// The client information response could not be deserialized.
    #[snafu(display("failed to deserialize the client information response"))]
    #[classify(no)]
    Deserialize {
        /// The underlying error.
        source: serde_json::Error,
    },

    /// The server returned a non-success status without a recognizable
    /// RFC 7591 error body.
    #[snafu(display("registration endpoint returned HTTP {status}: {body}"))]
    #[classify(no)]
    BadStatus {
        /// The HTTP status code.
        status: StatusCode,
        /// The response body, rendered as a bounded prefix.
        body: TruncatedBody,
    },
}

impl RegistrationError {
    /// Classifies the response as the server's verdict on the metadata.
    fn judged_by_the_server(
        verdict: &crate::core::OAuthError,
    ) -> crate::core::error::propagation::Origin<'static> {
        use crate::core::error::propagation::Origin;

        Origin::Establishes(crate::core::error::propagation::Classification::judged(
            verdict.code().implied_retry_advice(),
            verdict.clone(),
        ))
    }
}

#[cfg(test)]
mod classification {
    use super::*;

    // Every rejection must preserve its server verdict.
    #[test]
    fn every_rejection_carries_the_servers_verdict() {
        for code in [
            "invalid_redirect_uri",
            "invalid_client_metadata",
            "invalid_software_statement",
            "unapproved_software_statement",
            // A code outside RFC 7591 §3.2.2 takes the same route and survives
            // verbatim rather than being flattened into "some rejection".
            "something_bespoke",
        ] {
            let err = Error::from(RegistrationError::OAuthError {
                verdict: crate::core::OAuthError::new(code),
            });
            assert_eq!(
                err.verdict().map(|v| v.code().as_str()),
                Some(code),
                "{code}"
            );
            assert!(err.verdict().is_some(), "{code}");
        }

        // The description travels with its code, as one response object.
        let described = Error::from(RegistrationError::OAuthError {
            verdict: crate::core::OAuthError::new("invalid_redirect_uri")
                .with_description(Some(String::from("loopback only"))),
        });
        assert_eq!(
            described
                .verdict()
                .and_then(crate::core::OAuthError::description),
            Some("loopback only")
        );
    }

    // Recovery is derived from the verdict code rather than the error variant.
    #[test]
    fn what_to_do_falls_out_of_the_code_not_the_variant() {
        for code in [
            "invalid_redirect_uri",
            "invalid_client_metadata",
            "invalid_software_statement",
            "unapproved_software_statement",
        ] {
            let err = Error::from(RegistrationError::OAuthError {
                verdict: crate::core::OAuthError::new(code),
            });
            assert_eq!(
                crate::cache::Recovery::implied_by(&err),
                crate::cache::Recovery::AdjustRequest,
                "{code}"
            );
        }

        let bespoke = Error::from(RegistrationError::OAuthError {
            verdict: crate::core::OAuthError::new("something_bespoke"),
        });
        assert_eq!(
            crate::cache::Recovery::implied_by(&bespoke),
            crate::cache::Recovery::Fail
        );
    }

    // Local failures must not invent a server verdict.
    #[test]
    fn a_local_failure_carries_no_verdict() {
        for cause in [
            RegistrationError::JwksConflict,
            RegistrationError::MissingContentType,
            RegistrationError::BadStatus {
                status: StatusCode::IM_A_TEAPOT,
                body: TruncatedBody::new(""),
            },
        ] {
            let err = Error::from(cause);
            assert_eq!(err.verdict().map(|v| v.code().as_str()), None, "{err:?}");
        }
    }

    // The formatted error chain should not repeat the verdict.
    #[test]
    fn the_chain_says_the_code_once_and_the_gloss_once() {
        let err = Error::from(RegistrationError::OAuthError {
            verdict: crate::core::OAuthError::new("invalid_client_metadata").with_description(
                Some(String::from("token_endpoint_auth_method is unsupported")),
            ),
        });

        assert_eq!(
            format!("{err:#}"),
            "the registration endpoint returned invalid_client_metadata: \
             token_endpoint_auth_method is unsupported"
        );
        assert_eq!(
            format!("{err:#}")
                .matches("invalid_client_metadata")
                .count(),
            1,
            "the code must appear once across the whole chain"
        );

        // With no gloss to add, the cause still names which request was judged.
        let bare = Error::from(RegistrationError::OAuthError {
            verdict: crate::core::OAuthError::new("something_bespoke"),
        });
        assert_eq!(
            format!("{bare:#}"),
            "the registration endpoint returned something_bespoke"
        );
    }
}
