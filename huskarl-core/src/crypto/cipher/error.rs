use snafu::Snafu;

/// Errors that could occur during AEAD unsealing.
///
/// Used as the source of [`ErrorKind::Crypto`](crate::error::ErrorKind::Crypto)
/// errors — cipher implementations construct these to describe *why* an
/// unseal failed without expanding the kind-level vocabulary.
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum UnsealError {
    /// The bundle is malformed or uses an unsupported version.
    #[snafu(display("invalid bundle"))]
    InvalidBundle,
    /// The authentication tag did not match — the data may have been tampered with.
    #[snafu(display("authentication failed"))]
    AuthenticationFailed,
}
