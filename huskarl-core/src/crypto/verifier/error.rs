use snafu::Snafu;

use crate::error::Error;

/// Errors that could occur during verification.
///
/// The variants are load-bearing control flow between verifier layers:
/// [`NoMatchingKey`](Self::NoMatchingKey) drives the refresh-and-retry loop
/// in [`RetryingVerifier`](super::RetryingVerifier) and candidate dispatch in
/// [`MultiKeyVerifier`](super::MultiKeyVerifier), so this enum survives the
/// dyn-first error collapse — only its `Other` source is the concrete
/// [`Error`].
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum VerifyError {
    /// No key matched the requested algorithm/kid pair.
    #[snafu(display("no matching key"))]
    NoMatchingKey,
    /// Multiple keys matched but the token has no `kid` to disambiguate.
    #[snafu(display("ambiguous key: multiple keys match but token has no kid"))]
    AmbiguousKeyMatch,
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
    /// If true, a failed verification may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            VerifyError::NoMatchingKey
            | VerifyError::AmbiguousKeyMatch
            | VerifyError::SignatureMismatch => false,
            VerifyError::Other { source } => source.is_retryable(),
        }
    }
}

/// Errors that could occur while trying to create a verifier.
#[derive(Debug, Snafu)]
pub enum CreateVerifierError {
    /// The key is unsupported.
    ///
    /// [`MultiKeyVerifier::from_jwks`](super::MultiKeyVerifier::from_jwks)
    /// silently skips keys that fail with this variant.
    #[snafu(display("Unsupported key"))]
    UnsupportedKey {
        /// Why the key cannot back a verifier.
        source: Error,
    },
    /// No JWKS URI was provided to the verifier factory.
    #[snafu(display("A JWKS URI is required to build a JWS verifier"))]
    MissingJwksUri,
    /// Other kinds of errors that may occur while creating a verifier.
    #[snafu(transparent)]
    Other {
        /// The underlying error.
        source: Error,
    },
}
