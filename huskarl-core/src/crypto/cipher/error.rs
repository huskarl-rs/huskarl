use snafu::Snafu;

use crate::error::{Error, RetryAdvice};

/// Errors that could occur during AEAD decryption.
///
/// The variants provide control flow between decryptor layers:
/// [`NoMatchingKey`](Self::NoMatchingKey) drives the refresh-and-retry loop
/// in [`RetryingDecryptor`](super::RetryingDecryptor) and candidate dispatch
/// in [`MultiKeyDecryptor`](super::MultiKeyDecryptor) — the cipher analogue
/// of [`VerifyError`](crate::crypto::verifier::VerifyError). [`Other`](Self::Other)
/// carries a concrete [`Error`].
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum DecryptError {
    /// No key matched the requested algorithm/kid criteria — decryption was
    /// not attempted.
    #[snafu(display("no matching key"))]
    NoMatchingKey,
    /// Other kinds of errors that could occur during decryption, including
    /// authentication failure.
    #[snafu(transparent)]
    Other {
        /// The underlying error.
        source: Error,
    },
}

impl DecryptError {
    /// Returns whether and when retrying may help.
    ///
    /// This is the single retry-classification table used by
    /// [`is_retryable`](Self::is_retryable) and conversion to [`Error`].
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        match self {
            DecryptError::NoMatchingKey => RetryAdvice::No,
            // Preserve the complete advice from the underlying layer.
            DecryptError::Other { source } => source.retry_advice(),
        }
    }

    /// If true, a failed decryption may succeed if retried.
    ///
    /// This discards any retry delay. Use [`retry_advice`](Self::retry_advice)
    /// when scheduling another attempt. Candidate selection uses this method
    /// only to partition failures.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.retry_advice(), RetryAdvice::Retry { .. })
    }
}

/// Classifies a [`DecryptError`] and wraps it as the source of an [`Error`].
///
/// Classification comes from [`DecryptError::retry_advice`].
impl From<DecryptError> for Error {
    #[track_caller]
    fn from(source: DecryptError) -> Self {
        match source {
            // Return an existing `Error` directly to preserve its classification.
            DecryptError::Other { source } => source,
            other => Self::new(other.retry_advice(), other),
        }
    }
}

#[cfg(test)]
mod retryability_tests {
    use super::*;

    // Keep this exhaustive so new variants require an expected classification.
    fn every_variant() -> Vec<DecryptError> {
        vec![
            DecryptError::NoMatchingKey,
            DecryptError::Other {
                source: Error::new(RetryAdvice::RETRY, "upstream failure"),
            },
            DecryptError::Other {
                source: Error::new(RetryAdvice::No, "crypto failure"),
            },
            DecryptError::Other {
                source: Error::new(
                    RetryAdvice::retry_after(crate::platform::Duration::from_secs(30)),
                    "cooling down",
                ),
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

    // A transparent SNAFU variant must preserve every classification field.
    #[test]
    fn other_preserves_the_complete_classification() {
        let source = Error::propagate(
            crate::error::propagation::Classification::judged(
                RetryAdvice::retry_after(crate::platform::Duration::from_secs(97)),
                crate::oauth_error::OAuthError::new("temporarily_unavailable"),
            ),
            "cipher backend failed",
        );
        let expected = source.classification();

        let err = Error::from(DecryptError::Other { source });

        assert_eq!(err.classification(), expected);
    }

    // `retry_advice` retains information that `is_retryable` cannot represent.
    #[test]
    fn retry_advice_keeps_the_delay_is_retryable_cannot_carry() {
        let after = crate::platform::Duration::from_secs(30);
        let cooling = DecryptError::Other {
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
}
