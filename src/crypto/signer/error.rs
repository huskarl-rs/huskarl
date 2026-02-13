use snafu::Snafu;

/// The error type returned by signing key operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum JwsSignerError<E: crate::Error + 'static> {
    /// Key metadata is mismatched.
    ///
    /// The default `sign` implementation retries once if it sees this error.
    MismatchedKeyMetadata,
    /// The error from the underlying implementation.
    UnderlyingError {
        /// The underlying error.
        source: E,
    },
}

impl<E: crate::Error> crate::Error for JwsSignerError<E> {
    fn is_retryable(&self) -> bool {
        match self {
            // If this is received from `sign`, then one retry has already failed.
            JwsSignerError::MismatchedKeyMetadata => false,
            JwsSignerError::UnderlyingError { source } => source.is_retryable(),
        }
    }
}
