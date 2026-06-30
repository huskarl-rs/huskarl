//! The concrete [`Error`] type used across the huskarl ecosystem.
//!
//! This follows the [`std::io::Error`] model: one non-generic struct carrying
//! a matchable [`ErrorKind`], optional context, and a type-erased source.
//! Programmatic handling — retry decisions, "re-run the interactive flow",
//! surfacing the RFC 6749 error code — goes through [`ErrorKind`] and the
//! accessors on [`Error`]; they are the stable contract.
//!
//! For the signal model applications follow (retry / back off / adjust /
//! re-authenticate / fail) and notes on source chains and downcasting, see
//! [the error model](crate::_docs::explanation::error_handling).

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
/// Carries a classification ([`kind`](Error::kind)), the raw OAuth error code
/// when the server returned one
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
///
/// Most application code does not need to match individual variants: the
/// three signals described in [the error
/// model](crate::_docs::explanation::error_handling) (retry / re-authenticate /
/// fail) are the intended consumption pattern.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// RFC 6749 §5.2 `invalid_grant` — the grant itself is dead.
    ///
    /// Seen when driving a grant directly. A token cache absorbs this kind:
    /// it discards the rejected refresh token and reports
    /// [`ReauthRequired`](Self::ReauthRequired) once no token source remains.
    InvalidGrant,
    /// No token can be obtained without re-running the interactive flow: the
    /// refresh token is missing or was definitively rejected, and no usable
    /// grant parameters remain.
    ///
    /// Transient failures are deliberately *not* classified as this kind —
    /// they keep their retryable classification (see
    /// [`Error::is_retryable`]), since a later call may succeed without user
    /// involvement.
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
    /// The request was rejected for its parameters, but the credential is
    /// intact (RFC 6749 §5.2 `invalid_scope`, RFC 8707 `invalid_target`).
    ///
    /// Recoverable by adjusting the request — narrowing the requested scope,
    /// fixing the resource indicator — and retrying with the *same* credential.
    /// Re-authentication does not help, and a token cache deliberately does
    /// **not** discard the parameter source for this kind.
    RequestRejected,
    /// No token can be obtained right now, but the source expects the condition
    /// to clear on its own: it is backing off after repeated non-recoverable
    /// failures from scratch (for example an assertion signer that keeps
    /// producing values the server rejects with `invalid_grant`).
    ///
    /// Distinct from its neighbours. Unlike [`ReauthRequired`](Self::ReauthRequired)
    /// it does **not** call for re-running the interactive flow: a later
    /// automatic call, after the source's cooldown, may succeed once the
    /// underlying cause is fixed (a rotated signing key, a corrected clock).
    /// Unlike a retryable [`Transport`](Self::Transport) failure, retrying
    /// *immediately* will not help — wait for the cooldown before re-attempting.
    /// In short: try again later, without user involvement.
    Backoff,
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

    /// Attach the raw OAuth error code returned by the server (see
    /// [`oauth_error_code`](Self::oauth_error_code) for the codes this covers).
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

    /// The raw error code from the server's OAuth error response, if it returned
    /// one.
    ///
    /// Most commonly an RFC 6749 §5.2 token-endpoint error code (e.g.
    /// `invalid_grant`, `invalid_scope`), but the same field carries the
    /// equivalent code from any OAuth error response, including extension
    /// responses that reuse the `error` member — for example
    /// [`use_dpop_nonce`](Self::is_dpop_nonce_required) (RFC 9449) or a dynamic
    /// client registration error (RFC 7591 §3.2.2, such as
    /// `invalid_redirect_uri`). It is the verbatim string from the server; match
    /// on it only against codes defined by the protocol that produced the error.
    #[must_use]
    pub fn oauth_error_code(&self) -> Option<&str> {
        self.oauth_error_code.as_deref()
    }

    /// If true, the failure is transient and the same call may succeed if
    /// re-attempted (with backoff). No user involvement is needed; in
    /// particular this is not a reason to re-run the interactive flow.
    ///
    /// See [the error model](crate::_docs::explanation::error_handling) for how
    /// this composes with [`ErrorKind::ReauthRequired`].
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, ErrorKind::Transport { retryable: true })
    }

    /// If true, the server requires a `DPoP` nonce (RFC 9449 §8) — the error
    /// carries the `use_dpop_nonce` OAuth error code.
    ///
    /// The nonce value itself has already been recorded from the `DPoP-Nonce`
    /// response header by the time this error propagates; retry the request
    /// with freshly generated authentication parameters.
    #[must_use]
    pub fn is_dpop_nonce_required(&self) -> bool {
        self.oauth_error_code.as_deref() == Some("use_dpop_nonce")
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
            Self::RequestRejected => "the request parameters were rejected",
            Self::ReauthRequired => "re-authorization is required",
            Self::Backoff => "backing off after repeated failures",
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
