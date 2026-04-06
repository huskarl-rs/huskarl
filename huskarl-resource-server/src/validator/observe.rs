//! Token validation observation hooks.

use crate::core::platform::MaybeSendSync;

/// The outcome of a token validation attempt.
///
/// Passed to the [`OnValidate`] callback registered on a validator.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Token was valid.
    Success,
    /// No authentication was present in the request headers.
    NoToken,
    /// Token could not be extracted or parsed from the request headers.
    ExtractError,
    /// Token was invalid — bad signature, expired, wrong issuer, or inactive.
    InvalidToken,
    /// Sender-constraint binding check failed (DPoP or mTLS).
    BindingError,
    /// Introspection endpoint call failed (infrastructure error, not a bad token).
    CallError,
}

impl ValidationOutcome {
    /// Returns a short static string label suitable for use as a metrics tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NoToken => "no_token",
            Self::ExtractError => "extract_error",
            Self::InvalidToken => "invalid_token",
            Self::BindingError => "binding_error",
            Self::CallError => "call_error",
        }
    }
}

/// A callback invoked after each token validation attempt.
///
/// Implement this trait (or use a closure) to observe validation outcomes — for
/// example to record metrics, emit structured log events, or trigger alerts.
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use huskarl_resource_server::validator::observe::{OnValidate, ValidationOutcome};
/// let observer: Arc<dyn OnValidate> = Arc::new(|outcome: ValidationOutcome, resource: &str| {
///     metrics::counter!(
///         "my.token.validate",
///         "resource" => resource.to_owned(),
///         "outcome" => outcome.as_str(),
///     ).increment(1);
/// });
/// ```
pub trait OnValidate: MaybeSendSync {
    /// Called after each call to `validate_request`.
    ///
    /// `resource` identifies the validator instance — typically the audience or client ID.
    fn on_validate(&self, outcome: ValidationOutcome, resource: &str);
}

impl<F: Fn(ValidationOutcome, &str) + MaybeSendSync> OnValidate for F {
    fn on_validate(&self, outcome: ValidationOutcome, resource: &str) {
        self(outcome, resource)
    }
}
