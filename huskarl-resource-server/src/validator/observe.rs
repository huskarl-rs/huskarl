//! Token validation observation hooks.

use crate::core::platform::MaybeSendSync;

/// The outcome of a token validation attempt.
///
/// Passed to the [`OnValidate`] callback registered on a validator. Which
/// variants can occur depends on the validator — e.g. `CallError` arises only
/// from introspection, never from the self-contained RFC 9068 path.
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
    /// Token was invalid — bad signature, expired, wrong issuer, or inactive.
    InvalidToken,
    /// Sender-constraint binding check failed (`DPoP` or mTLS).
    BindingError,
    /// Introspection endpoint call failed (infrastructure error, not a bad token).
    CallError,
}

impl ValidationOutcome {
    /// Returns a short static string label suitable for use as a metrics tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// A callback invoked after each token validation attempt.
///
/// Implement this trait (or use a closure) to observe validation outcomes — for
/// example to record metrics, emit structured log events, or trigger alerts.
///
/// Any context needed to identify the validator (resource name, machine ID, etc.)
/// should be captured by the implementation itself.
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use huskarl_resource_server::validator::observe::{OnValidate, ValidationOutcome};
/// let resource = "my-api";
/// let observer: Arc<dyn OnValidate> = Arc::new(move |outcome: ValidationOutcome| {
///     metrics::counter!(
///         "my.token.validate",
///         "resource" => resource,
///         "outcome" => outcome.as_str(),
///     ).increment(1);
/// });
/// ```
pub trait OnValidate: MaybeSendSync {
    /// Called after each call to `validate_request`.
    fn on_validate(&self, outcome: ValidationOutcome);
}

impl<F: Fn(ValidationOutcome) + MaybeSendSync> OnValidate for F {
    fn on_validate(&self, outcome: ValidationOutcome) {
        self(outcome);
    }
}
