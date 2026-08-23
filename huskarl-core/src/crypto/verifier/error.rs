use snafu::Snafu;

use crate::error::{BoxedSource, Error, RetryAdvice};

/// Errors that could occur during verification.
///
/// The variants provide control flow between verifier layers:
/// [`NoMatchingKey`](Self::NoMatchingKey) drives the refresh-and-retry loop
/// in [`RetryingVerifier`](super::RetryingVerifier) and candidate dispatch in
/// [`MultiKeyVerifier`](super::MultiKeyVerifier). [`Other`](Self::Other) carries
/// a concrete [`Error`] for failures that do not affect key selection.
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum VerifyError {
    /// No key matched the requested algorithm/kid pair.
    #[snafu(display("no matching key"))]
    NoMatchingKey,
    /// No keyset has loaded since startup.
    ///
    /// This is distinct from [`NoMatchingKey`](Self::NoMatchingKey): an
    /// unreachable upstream is an infrastructure failure, not a bad token.
    #[snafu(display("no keys available: JWKS has not loaded since startup"))]
    KeysUnavailable,
    /// Multiple keys matched but the token has no `kid` to disambiguate.
    #[snafu(display("ambiguous key: multiple keys match but token has no kid"))]
    AmbiguousKeyMatch,
    /// The signature bytes are not well-formed for this algorithm — the wrong
    /// length, or an invalid encoding.
    ///
    /// Unlike [`SignatureMismatch`](Self::SignatureMismatch), this fails before
    /// the cryptographic check. The distinction is diagnostic.
    #[snafu(display("malformed signature"))]
    MalformedSignature {
        /// The erased backend error.
        source: BoxedSource,
    },
    /// Signature mismatch, verification failed.
    #[snafu(display("signature mismatch"))]
    SignatureMismatch,
    /// Other kinds of errors that could occur during verification.
    #[snafu(transparent)]
    Other {
        /// The underlying error.
        source: Error,
    },
}

impl VerifyError {
    /// Returns whether and when retrying may help.
    ///
    /// This is the single retry-classification table used by
    /// [`is_retryable`](Self::is_retryable) and conversion to [`Error`].
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            VerifyError::NoMatchingKey
            | VerifyError::AmbiguousKeyMatch
            | VerifyError::MalformedSignature { .. }
            | VerifyError::SignatureMismatch => RetryAdvice::No,
            // A cold source may become ready once the upstream is reachable again.
            VerifyError::KeysUnavailable => RetryAdvice::RETRY,
            // Preserve the complete advice from the underlying layer.
            VerifyError::Other { source } => source.retry_advice(),
        }
    }

    /// If true, a failed verification may succeed if retried.
    ///
    /// This discards any retry delay. Use [`retry_advice`](Self::retry_advice)
    /// when scheduling another attempt. Candidate selection uses this method
    /// only to partition failures.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.retry_advice(), RetryAdvice::Retry { .. })
    }
}

/// Classifies a [`VerifyError`] and wraps it as the source of an [`Error`].
///
/// Classification comes from [`VerifyError::retry_advice`].
impl From<VerifyError> for Error {
    #[track_caller]
    fn from(source: VerifyError) -> Self {
        match source {
            // Return an existing `Error` directly to preserve its classification.
            VerifyError::Other { source } => source,
            // Each variant's display already provides the diagnostic message.
            other => Self::new(other.retry_advice(), other),
        }
    }
}

#[cfg(test)]
mod retryability_tests {
    use super::*;

    // Keep this exhaustive so new variants require an expected classification.
    fn every_variant() -> Vec<VerifyError> {
        vec![
            VerifyError::NoMatchingKey,
            VerifyError::KeysUnavailable,
            VerifyError::AmbiguousKeyMatch,
            VerifyError::MalformedSignature {
                source: "signature is 63 bytes, expected 64".into(),
            },
            VerifyError::SignatureMismatch,
            VerifyError::Other {
                source: Error::new(RetryAdvice::RETRY, "upstream failure"),
            },
            VerifyError::Other {
                source: Error::new(RetryAdvice::No, "crypto failure"),
            },
        ]
    }

    // Conversion to `Error` must preserve retryability.
    #[test]
    fn retryability_survives_conversion() {
        for variant in every_variant() {
            let expected = variant.is_retryable();
            let debug = format!("{variant:?}");
            let converted = Error::from(variant);
            assert_eq!(
                matches!(converted.retry_advice(), RetryAdvice::Retry { .. }),
                expected,
                "{debug} reports is_retryable() = {expected} but converts to {:?}",
                converted.retry_advice(),
            );
        }
    }

    // Conversion must preserve the complete advice, including its delay.
    #[test]
    fn the_whole_advice_survives_conversion() {
        for variant in every_variant() {
            let expected = variant.retry_advice();
            let debug = format!("{variant:?}");
            assert_eq!(Error::from(variant).retry_advice(), expected, "{debug}");
        }
    }

    // `retry_advice` retains information that `is_retryable` cannot represent.
    #[test]
    fn retry_advice_keeps_the_delay_is_retryable_cannot_carry() {
        let after = crate::platform::Duration::from_secs(30);
        let cooling = VerifyError::Other {
            source: Error::new(RetryAdvice::retry_after(after), "cooling down"),
        };

        assert_eq!(
            cooling.retry_advice(),
            RetryAdvice::Retry { after: Some(after) }
        );
        assert!(cooling.is_retryable());
        assert_eq!(
            Error::from(cooling).retry_advice(),
            RetryAdvice::Retry { after: Some(after) },
            "the interval must reach the erased error too",
        );
    }

    // A cold JWKS is an upstream failure, not a bad token.
    #[test]
    fn keys_unavailable_converts_to_a_retryable_transport_failure() {
        let err = Error::from(VerifyError::KeysUnavailable);
        assert_eq!(err.retry_advice(), RetryAdvice::RETRY);
    }

    // A transparent SNAFU variant must preserve every classification field.
    #[test]
    fn other_preserves_the_complete_classification() {
        let source = Error::propagate(
            crate::error::propagation::Classification::judged(
                RetryAdvice::retry_after(crate::platform::Duration::from_secs(97)),
                crate::oauth_error::OAuthError::new("temporarily_unavailable"),
            ),
            "verifier backend failed",
        );
        let expected = source.classification();

        let err = Error::from(VerifyError::Other { source });

        assert_eq!(err.classification(), expected);
    }
}

/// Errors that could occur while trying to create a verifier.
#[derive(Debug, Snafu)]
pub enum CreateVerifierError {
    /// The key is unsupported.
    ///
    /// [`MultiKeyVerifier::from_jwks`](super::MultiKeyVerifier::from_jwks)
    /// silently skips keys that fail with this variant.
    #[snafu(display("the key cannot back a verifier"))]
    UnsupportedKey {
        /// Why the key cannot back a verifier.
        source: Error,
    },
    /// No JWKS URI was provided to the verifier factory.
    #[snafu(display("a JWKS URI is required to build a JWS verifier"))]
    MissingJwksUri,
    /// Other kinds of errors that may occur while creating a verifier.
    #[snafu(transparent)]
    Other {
        /// The underlying error.
        source: Error,
    },
}
