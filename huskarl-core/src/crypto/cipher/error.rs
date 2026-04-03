use snafu::Snafu;

/// Errors that could occur during AEAD unsealing.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum UnsealError<E: crate::Error> {
    /// The bundle is malformed or uses an unsupported version.
    #[snafu(display("invalid bundle"))]
    InvalidBundle,
    /// The authentication tag did not match — the data may have been tampered with.
    #[snafu(display("authentication failed"))]
    AuthenticationFailed,
    /// The underlying cipher operation failed.
    #[snafu(transparent)]
    Cipher {
        /// The underlying error.
        source: E,
    },
}

impl<E: crate::Error> crate::Error for UnsealError<E> {
    fn is_retryable(&self) -> bool {
        match self {
            UnsealError::InvalidBundle | UnsealError::AuthenticationFailed => false,
            UnsealError::Cipher { source } => source.is_retryable(),
        }
    }
}
