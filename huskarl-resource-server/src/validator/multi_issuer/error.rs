//! Error type for [`MultiIssuerValidator`](super::MultiIssuerValidator).

use snafu::{IntoError as _, Snafu};

use crate::{
    TokenType,
    core::jwt::JwsParseError,
    error::{Challenge, ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{extract::TokenExtractError, observe::ValidationOutcome},
};

/// A failure of a [`MultiIssuerValidator`](super::MultiIssuerValidator).
///
/// Distinct from the inner validators' errors because routing has a failure mode
/// they do not: a token whose issuer cannot be determined or is not registered.
/// Inner-validator failures are wrapped in [`MultiIssuerError::Validation`] and
/// preserve their [`Challenge`], observation outcome, attempted scheme, and
/// [`std::error::Error::source`] chain.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum MultiIssuerError {
    /// The access token could not be extracted from the request headers.
    #[snafu(display("token presentation error"))]
    Extract {
        /// The underlying extraction error.
        source: TokenExtractError,
    },
    /// A token was present, but its `iss` claim was missing or did not match
    /// any registered issuer. Treated as `invalid_token`.
    // Debug-quote the unverified issuer so control characters are escaped.
    #[snafu(display("unrecognized token issuer{}", iss.as_ref().map(|iss| format!(": {iss:?}")).unwrap_or_default()))]
    UnrecognizedIssuer {
        /// The token's `iss` claim as peeked from the **unverified** payload,
        /// when one could be read. Diagnostic only — an attacker controls it,
        /// so never use it as a metrics label.
        iss: Option<String>,
    },
    /// The validator selected for the token's issuer rejected it.
    ///
    /// The inner error supplies the challenge and remains available through
    /// [`std::error::Error::source`]. The registered `issuer` is returned by
    /// [`ToRfc6750Error::issuer`] and is safe to use as a bounded metrics label.
    #[snafu(display("token validation error (issuer {issuer})"))]
    Validation {
        /// The registered issuer the token routed to.
        issuer: String,
        /// The inner validator's error.
        #[snafu(source)]
        error: Box<dyn ToRfc6750Error>,
    },
    // Append new variants so existing discriminants stay stable for
    // cargo-semver-checks.
    /// The token could not be parsed as compact JWS for issuer routing.
    #[snafu(display("malformed access token"))]
    Parse {
        /// The underlying parsing error.
        source: JwsParseError,
    },
    /// No decryption path is configured for issuer routing.
    ///
    /// Currently returned for any five-segment token, without validating it as
    /// JWE. Treated as `invalid_token`.
    #[snafu(display("unsupported five-segment (possibly JWE) token"))]
    UnsupportedEncryptedToken,
}

impl From<TokenExtractError> for MultiIssuerError {
    fn from(source: TokenExtractError) -> Self {
        ExtractSnafu.into_error(source)
    }
}

impl ToRfc6750Error for MultiIssuerError {
    fn challenge(&self) -> Challenge {
        match self {
            Self::Extract { source } => source.challenge(),
            Self::Parse { .. } => {
                Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                    .with_description("The access token is malformed")
            }
            Self::UnsupportedEncryptedToken => {
                Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                    .with_description("The access token format is not supported")
            }
            Self::Validation { error, .. } => error.challenge(),
            Self::UnrecognizedIssuer { .. } => {
                Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
                    .with_description("The access token issuer is not recognized")
            }
        }
    }
    fn attempted_scheme(&self) -> Option<TokenType> {
        match self {
            Self::Extract { source } => source.attempted_scheme(),
            Self::Parse { .. }
            | Self::UnsupportedEncryptedToken
            | Self::UnrecognizedIssuer { .. } => None,
            Self::Validation { error, .. } => error.attempted_scheme(),
        }
    }

    fn validation_outcome(&self, challenge: &Challenge) -> ValidationOutcome {
        match self {
            Self::Extract { .. } => ValidationOutcome::ExtractError,
            Self::Parse { .. } | Self::UnsupportedEncryptedToken => ValidationOutcome::InvalidToken,
            Self::UnrecognizedIssuer { .. } => ValidationOutcome::UnrecognizedIssuer,
            Self::Validation { error, .. } => error.validation_outcome(challenge),
        }
    }

    fn branch_label(&self) -> Option<&str> {
        match self {
            Self::Validation { error, .. } => error.branch_label(),
            _ => None,
        }
    }

    fn issuer(&self) -> Option<&str> {
        match self {
            // Only the registered issuer is a trusted, bounded label; the
            // peeked `iss` of an unrecognized issuer is attacker-controlled.
            Self::Validation { issuer, .. } => Some(issuer),
            Self::Extract { .. }
            | Self::Parse { .. }
            | Self::UnsupportedEncryptedToken
            | Self::UnrecognizedIssuer { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::jwt::validator::JwtValidationError, error::InsufficientScope};

    // Collects an error's display chain.
    fn chain(err: &dyn std::error::Error) -> Vec<String> {
        std::iter::successors(Some(err), |e| e.source())
            .map(ToString::to_string)
            .collect()
    }

    // Routing must preserve access to the inner validator's error.
    #[test]
    fn the_inner_validators_error_is_reachable_through_the_boundary() {
        let err = MultiIssuerError::Validation {
            issuer: String::from("https://as.example.com"),
            error: Box::new(JwtValidationError::UnsignedToken),
        };

        let recovered = std::iter::successors(Some(&err as &dyn std::error::Error), |e| e.source())
            .find_map(<dyn std::error::Error>::downcast_ref::<JwtValidationError>);

        assert!(
            matches!(recovered, Some(JwtValidationError::UnsignedToken)),
            "the inner error must survive being routed"
        );
    }

    // Each source-chain layer should describe itself once.
    #[test]
    fn the_chain_reads_without_repetition() {
        let err = MultiIssuerError::Validation {
            issuer: String::from("https://as.example.com"),
            error: Box::new(JwtValidationError::UnsignedToken),
        };

        let rendered = chain(&err);
        assert_eq!(rendered.len(), 2, "got {rendered:?}");
        assert_eq!(
            rendered[0],
            "token validation error (issuer https://as.example.com)"
        );
        assert_ne!(rendered[0], rendered[1], "a layer restated its own source");
    }

    // Each variant exposes exactly the source it carries.
    #[test]
    fn every_variant_reports_the_source_it_has() {
        let extract = MultiIssuerError::from(TokenExtractError::InvalidTokenHeaderFormat);
        assert_eq!(chain(&extract).len(), 2, "extraction has a cause");

        let unrecognized = MultiIssuerError::UnrecognizedIssuer {
            iss: Some(String::from("https://evil.example.com")),
        };
        assert!(
            std::error::Error::source(&unrecognized).is_none(),
            "nothing failed below the routing decision"
        );
    }

    // Escape attacker-controlled issuer values in diagnostics.
    #[test]
    fn a_peeked_issuer_is_escaped_when_rendered() {
        let err = MultiIssuerError::UnrecognizedIssuer {
            iss: Some(String::from("https://evil.example\r\nInjected: yes")),
        };
        let rendered = err.to_string();
        assert!(!rendered.contains('\n'), "got {rendered}");
        assert!(rendered.contains("\\r\\n"), "got {rendered}");
    }

    // Application-defined validation errors also remain in the source chain.
    #[test]
    fn an_application_rejection_chains_as_well() {
        let err = MultiIssuerError::Validation {
            issuer: String::from("https://as.example.com"),
            error: Box::new(InsufficientScope::new("admin")),
        };
        assert_eq!(chain(&err).len(), 2);
        assert_eq!(err.challenge().scope.as_deref(), Some("admin"));
    }

    crate::forwarding_table! {
        /// Preserve arbitrary inner challenge fields through issuer routing.
        multi_issuer_error_forwards {
            || TokenExtractError::InvalidTokenHeaderFormat
                => |source| MultiIssuerError::Extract { source },
            || InsufficientScope::new("admin") => |error| MultiIssuerError::Validation {
                issuer: String::from("https://as.example.com"),
                error: Box::new(error),
            },
            || crate::error::InsufficientUserAuthentication {
                acr_values: Some(String::from("phrh")),
                max_age: Some(60),
            } => |error| MultiIssuerError::Validation {
                issuer: String::from("https://as.example.com"),
                error: Box::new(error),
            },
        }
    }

    // The wrapper adds the trusted routed issuer as its own context.
    #[test]
    fn a_wrapper_keeps_the_members_that_are_its_own() {
        let wrapped = MultiIssuerError::Validation {
            issuer: String::from("https://as.example.com"),
            error: Box::new(InsufficientScope::new("admin")),
        };
        assert_eq!(InsufficientScope::new("admin").issuer(), None);
        assert_eq!(wrapped.issuer(), Some("https://as.example.com"));
    }
}
