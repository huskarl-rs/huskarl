use snafu::Snafu;

use crate::BoxedError;

/// Errors that could occur during verification.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum VerifyError<E: crate::Error> {
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
        source: E,
    },
}

impl<E: crate::Error> crate::Error for VerifyError<E> {
    fn is_retryable(&self) -> bool {
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
    #[snafu(display("Unsupported key"))]
    UnsupportedKey,
    /// No JWKS URI was provided to the verifier factory.
    #[snafu(display("A JWKS URI is required to build a JWS verifier"))]
    MissingJwksUri,
    /// Other kinds of errors that may occur while creating a verifier.
    #[snafu(transparent)]
    Other {
        /// The underlying error.
        source: BoxedError,
    },
}

impl crate::Error for CreateVerifierError {
    fn is_retryable(&self) -> bool {
        match self {
            CreateVerifierError::UnsupportedKey | CreateVerifierError::MissingJwksUri => false,
            CreateVerifierError::Other { source } => source.is_retryable(),
        }
    }
}
