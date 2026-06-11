//! The concrete [`Error`] type used across the huskarl ecosystem.
//!
//! This follows the [`std::io::Error`] model: one non-generic struct carrying
//! a matchable [`ErrorKind`], optional context, and a type-erased source.
//! Programmatic handling — retry decisions, "re-run the interactive flow",
//! surfacing the RFC 6749 error code — goes through [`ErrorKind`] and the
//! accessors on [`Error`]; they are the stable contract.
//!
//! # Source chains and downcasting
//!
//! [`Error::source`](std::error::Error::source) chains preserve the concrete
//! underlying error (for example a transport crate's error type) for
//! diagnostics, logging, and error-report rendering. Downcasting a source to
//! a concrete type is **not** supported API surface: the type behind
//! `source()` may change in any release. Match on [`ErrorKind`] instead.

use std::fmt;

/// A type-erased error source.
///
/// `Send + Sync` on platforms that require it (everything except wasm32).
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSource = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A type-erased error source.
///
/// `Send + Sync` on platforms that require it (everything except wasm32).
#[cfg(target_arch = "wasm32")]
pub type BoxedSource = Box<dyn std::error::Error + 'static>;

/// An error from a huskarl operation.
///
/// Carries a classification ([`kind`](Error::kind)), the raw RFC 6749 error
/// code when the authorization server returned one
/// ([`oauth_error_code`](Error::oauth_error_code)), and the underlying cause
/// ([`source`](std::error::Error::source)).
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    context: Option<String>,
    oauth_error_code: Option<String>,
    source: Option<BoxedSource>,
}

/// Classification of an [`Error`].
///
/// Marked `#[non_exhaustive]`: match with a wildcard arm. Variants are kept
/// coarse deliberately — additions are non-breaking, removals are not.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// RFC 6749 §5.2 `invalid_grant` — the grant itself is dead.
    InvalidGrant,
    /// Refresh failed or there is no token source: the interactive flow must
    /// re-run before another token can be obtained.
    ReauthRequired,
    /// Transport-level failure.
    Transport {
        /// If true, re-sending the request is known to be safe and may
        /// succeed: either the request never reached the server, or it was
        /// declared [`Idempotency::Idempotent`](crate::http::Idempotency)
        /// and the failure was transient. Requests of
        /// [unknown idempotency](crate::http::Idempotency::Unknown) are
        /// only retryable when they provably never reached the server.
        retryable: bool,
    },
    /// Malformed or invalid server response.
    Protocol,
    /// Client authentication could not be constructed.
    Auth,
    /// `DPoP` proof construction or handling failed.
    Dpop,
    /// Builder, URL, or other setup error.
    Config,
    /// Cryptographic operation failed.
    Crypto,
}

impl Error {
    /// Create an error of the given kind caused by `source`.
    pub fn new(kind: ErrorKind, source: impl Into<BoxedSource>) -> Self {
        Self {
            kind,
            context: None,
            oauth_error_code: None,
            source: Some(source.into()),
        }
    }

    /// Attach human-readable context about the failed operation (for example
    /// the endpoint being called). Shown as a prefix in the `Display` output.
    ///
    /// Layers: calling this on an error that already has context prefixes the
    /// existing context, so outer operations read first
    /// (`"fetching client secret: reading secret file /run/secret: ..."`).
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(match self.context {
            Some(existing) => format!("{}: {existing}", context.into()),
            None => context.into(),
        });
        self
    }

    /// Attach the raw RFC 6749 §5.2 error code returned by the server.
    #[must_use]
    pub fn with_oauth_error_code(mut self, code: impl Into<String>) -> Self {
        self.oauth_error_code = Some(code.into());
        self
    }

    /// The classification of this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The raw RFC 6749 §5.2 error code, if the server returned one.
    #[must_use]
    pub fn oauth_error_code(&self) -> Option<&str> {
        self.oauth_error_code.as_deref()
    }

    /// If true, a failed request may succeed if retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, ErrorKind::Transport { retryable: true })
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
            oauth_error_code: None,
            source: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(context) = &self.context {
            write!(f, "{context}: ")?;
        }
        self.kind.fmt(f)?;
        if let Some(code) = &self.oauth_error_code {
            write!(f, " (oauth error code: {code})")?;
        }
        Ok(())
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::InvalidGrant => "the grant is no longer valid",
            Self::ReauthRequired => "re-authorization is required",
            Self::Transport { retryable: true } => "transient transport failure",
            Self::Transport { retryable: false } => "transport failure",
            Self::Protocol => "invalid or malformed server response",
            Self::Auth => "client authentication construction failed",
            Self::Dpop => "DPoP proof handling failed",
            Self::Config => "invalid configuration",
            Self::Crypto => "cryptographic operation failed",
        };
        f.write_str(description)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Underlying;

    impl fmt::Display for Underlying {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("underlying")
        }
    }

    impl std::error::Error for Underlying {}

    #[test]
    fn kind_and_oauth_code_are_preserved() {
        let err =
            Error::new(ErrorKind::InvalidGrant, Underlying).with_oauth_error_code("invalid_grant");
        assert_eq!(err.kind(), ErrorKind::InvalidGrant);
        assert_eq!(err.oauth_error_code(), Some("invalid_grant"));
        assert!(!err.is_retryable());
    }

    #[test]
    fn retryable_follows_transport_classification() {
        assert!(Error::from(ErrorKind::Transport { retryable: true }).is_retryable());
        assert!(!Error::from(ErrorKind::Transport { retryable: false }).is_retryable());
        assert!(!Error::from(ErrorKind::Crypto).is_retryable());
    }

    #[test]
    fn source_chain_preserves_concrete_error() {
        let err = Error::new(ErrorKind::Transport { retryable: false }, Underlying);
        let source = std::error::Error::source(&err).expect("source set");
        assert!(source.downcast_ref::<Underlying>().is_some());

        let sourceless = Error::from(ErrorKind::Config);
        assert!(std::error::Error::source(&sourceless).is_none());
    }

    #[test]
    fn display_prefixes_context() {
        let err = Error::from(ErrorKind::Transport { retryable: false })
            .with_context("fetching https://as.example/jwks.json");
        assert_eq!(
            err.to_string(),
            "fetching https://as.example/jwks.json: transport failure"
        );
    }

    #[test]
    fn context_layers_outermost_first() {
        let err = Error::from(ErrorKind::Config)
            .with_context("reading secret file /run/secret")
            .with_context("fetching client secret");
        assert_eq!(
            err.to_string(),
            "fetching client secret: reading secret file /run/secret: invalid configuration"
        );
    }

    #[test]
    fn display_includes_oauth_code() {
        let err = Error::from(ErrorKind::InvalidGrant).with_oauth_error_code("invalid_grant");
        assert_eq!(
            err.to_string(),
            "the grant is no longer valid (oauth error code: invalid_grant)"
        );
    }
}
