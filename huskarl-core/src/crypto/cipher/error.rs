use snafu::Snafu;

use crate::error::Error;

/// Errors that could occur during AEAD decryption.
///
/// The variants are load-bearing control flow between decryptor layers:
/// [`NoMatchingKey`](Self::NoMatchingKey) drives the refresh-and-retry loop
/// in [`RetryingDecryptor`](super::RetryingDecryptor) and candidate dispatch
/// in [`MultiKeyDecryptor`](super::MultiKeyDecryptor) — the cipher analogue
/// of [`VerifyError`](crate::crypto::verifier::VerifyError). Only its
/// `Other` source is the concrete [`Error`].
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
    /// If true, a failed decryption may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            DecryptError::NoMatchingKey => false,
            DecryptError::Other { source } => source.is_retryable(),
        }
    }
}
