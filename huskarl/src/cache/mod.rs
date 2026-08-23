//! Token sources and caching for `OAuth2` tokens.
//!
//! The usual wiring is a chain, built from the inside out: an
//! [`HttpAuthorizer`] holds an [`InMemoryTokenCache`], which wraps a
//! [`GrantTokenSource`], which runs a grant — drawing exchange parameters from a
//! [`GrantParametersSource`] and storing the refresh token in a
//! [`RefreshTokenStore`]. Most applications use the built-in at every link and
//! implement none of these traits themselves.
//!
//! # Key types
//!
//! - [`TokenSource`] — the trait that produces tokens, however they are
//!   obtained. Caching is itself a `TokenSource`, layered on top.
//! - [`TokenCache`] — a marker for a *memoizing* [`TokenSource`]. An
//!   [`HttpAuthorizer`] requires it, so a raw producer cannot be wired in by
//!   mistake and re-run on every request.
//! - [`GrantTokenSource`] — the built-in producer: refreshes a token or runs a
//!   grant exchange.
//! - [`InMemoryTokenCache`] — the built-in [`TokenCache`]: stores the last
//!   token, single-flights concurrent acquisitions, and refreshes near expiry.
//! - [`RefreshTokenStore`] — pluggable storage for the refresh token, with
//!   [`InMemoryRefreshTokenStore`] as the default.
//! - [`GrantParametersSource`] — supplies the parameters for a from-scratch
//!   exchange. Reusable parameter types implement it directly; otherwise use
//!   [`single_use`], [`reusable`], or [`from_fn`].
//!
//! # Further reading
//!
//! - [Caching tokens and wiring an authorizer](crate::_docs::guide::caching) —
//!   building the chain and implementing your own store, cache, or parameter
//!   source.
//! - [Sharing a refresh token store](crate::_docs::explanation::sharing_a_token_store)
//!   — when a [`RefreshTokenStore`] can be shared across sources or processes.
//! - [Refresh timing](crate::_docs::explanation::refresh_timing) — how
//!   refresh-ahead and jitter decide when the cache refreshes.
//!
//! [`HttpAuthorizer`]: crate::authorizer::HttpAuthorizer

mod grant_parameters;
mod grant_token_source;
mod in_memory;
mod token_source;

use std::sync::{Arc, PoisonError, RwLock};

pub use grant_parameters::{
    FromFn, GrantParametersSource, NoSource, Reusable, SingleUse, from_fn, reusable, single_use,
};
pub use grant_token_source::{GrantTokenSource, GrantTokenSourceBuilder};
pub use in_memory::{CacheState, InMemoryTokenCache, InMemoryTokenCacheBuilder};
use snafu::Snafu;
pub use token_source::TokenSource;

use crate::{
    core::{
        Error, RetryAdvice,
        platform::{Duration, MaybeSendBoxFuture, MaybeSendSync},
    },
    token::RefreshToken,
};

/// Marker for a [`TokenSource`] that memoizes and single-flights token
/// acquisition.
///
/// It adds no methods of its own. The built-in implementation is
/// [`InMemoryTokenCache`]. Implementing this trait promises that repeated calls
/// do not reproduce a token unnecessarily; this is why
/// [`HttpAuthorizer`](crate::authorizer::HttpAuthorizer) requires it. A raw
/// producer such as [`GrantTokenSource`] does not implement `TokenCache`.
///
/// Token *injection* is a source concern, not a cache one — see
/// [`GrantTokenSource::prime`].
pub trait TokenCache: TokenSource {}

impl<T: TokenCache + ?Sized> TokenCache for &T {}
impl<T: TokenCache + ?Sized> TokenCache for Box<T> {}
impl<T: TokenCache + ?Sized> TokenCache for Arc<T> {}

/// Which attempt supplies the source for [`GetTokenError::BothFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// The refresh of a stored credential.
    Refresh,
    /// A fresh exchange with the grant parameters.
    Exchange,
}

impl Attempt {
    /// Returns the name of the other attempt.
    pub(crate) fn other(self) -> &'static str {
        match self {
            Self::Refresh => "the exchange",
            Self::Exchange => "the refresh",
        }
    }
}

/// The cause of a token acquisition failure.
#[derive(Debug, Snafu)]
#[cfg_attr(test, derive(strum::EnumCount))]
#[non_exhaustive]
pub(crate) enum GetTokenError {
    /// Token refresh failed and no grant parameters were available to fall back to.
    #[snafu(display("token refresh failed and no grant parameters were available"))]
    RefreshFailed {
        /// The underlying refresh error.
        source: Error,
    },
    /// Token refresh failed and the subsequent fresh exchange also failed.
    ///
    /// The actionable attempt is the error-chain source. The other attempt is
    /// included in the display message because an error can have only one source.
    #[snafu(display(
        "token refresh failed and exchange also failed: {} also failed: {other:#}",
        reported_attempt.other(),
    ))]
    BothFailed {
        /// The actionable attempt, or the exchange when neither is actionable.
        #[snafu(source)]
        reported: Error,
        /// The other attempt, off the chain and rendered into the message.
        other: Error,
        /// Identifies the reported attempt so the message can name the other one.
        reported_attempt: Attempt,
    },
    /// A from-scratch exchange failed and no refresh token was available to
    /// fall back to.
    #[snafu(display("token exchange failed and no refresh token was available"))]
    ExchangeFailed {
        /// The underlying exchange error.
        source: Error,
    },
    /// No refresh token is stored and the source has no grant parameters
    /// ([`NoSource`]) — there is no way to obtain a token until one is
    /// supplied.
    #[snafu(display(
        "no refresh token is stored and the source has no grant parameters — hand an \
         interactive flow's token response to 'GrantTokenSource::prime()', or configure \
         'grant_parameters' on the source"
    ))]
    NoTokenSource,
    /// The source is backing off after repeated non-recoverable fresh exchanges.
    #[snafu(display("token source backed off after repeated failures; retry after cooldown"))]
    Backoff,
}

/// Outcome of token acquisition, suitable for a low-cardinality metrics label.
///
/// With the `metrics` feature, this is emitted as the `outcome` label on
/// `huskarl.token.acquire`. Token acquisition itself returns [`TokenError`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenOutcome {
    /// A token was acquired.
    Success,
    /// Refresh failed and no grant parameters were available to fall back to.
    RefreshFailed,
    /// Refresh failed and the subsequent fresh exchange also failed.
    BothFailed,
    /// A from-scratch exchange failed with no refresh token to fall back to.
    ExchangeFailed,
    /// Nothing could be attempted: no refresh token and no grant parameters.
    NoTokenSource,
    /// The source is in breaker cooldown and declined to try.
    Backoff,
}

impl TokenOutcome {
    /// Returns the value emitted in the `outcome` metrics label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::RefreshFailed => "refresh_failed",
            Self::BothFailed => "both_failed",
            Self::ExchangeFailed => "exchange_failed",
            Self::NoTokenSource => "no_token_source",
            Self::Backoff => "backoff",
        }
    }
}

impl GetTokenError {
    /// The outcome label for this failure.
    ///
    /// The exhaustive match requires every new failure variant to select a label.
    #[cfg(any(feature = "metrics", test))]
    #[must_use]
    pub(crate) fn outcome(&self) -> TokenOutcome {
        match self {
            Self::RefreshFailed { .. } => TokenOutcome::RefreshFailed,
            Self::BothFailed { .. } => TokenOutcome::BothFailed,
            Self::ExchangeFailed { .. } => TokenOutcome::ExchangeFailed,
            Self::NoTokenSource => TokenOutcome::NoTokenSource,
            Self::Backoff => TokenOutcome::Backoff,
        }
    }
}

/// Action a caller can take after token acquisition fails.
///
/// A [`TokenSource`] establishes this from the acquisition paths it owns. It
/// may therefore differ from the underlying [`Error::retry_advice`]: retrying
/// one failed operation can be futile while asking the source again can use a
/// different credential, or vice versa.
///
/// This enum is non-exhaustive. Treat unknown variants as [`Fail`](Self::Fail).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// Attempt token acquisition again later.
    ///
    /// The source may retry the failed operation or choose another acquisition
    /// path, such as generating new grant parameters.
    Retry {
        /// Minimum known delay before calling [`TokenSource::token`] on this
        /// source again, if one was provided.
        ///
        /// This applies to the next acquisition attempt as a whole. `None`
        /// means no lower bound is known.
        after: Option<Duration>,
    },
    /// Change the request before retrying; the credential remains usable.
    ///
    /// Examples include narrowing a scope or changing a resource indicator.
    AdjustRequest,
    /// Obtain new authorization through user interaction, or alert an operator
    /// for an unattended client.
    Reauthenticate,
    /// No automatic recovery is known.
    Fail,
}

impl Recovery {
    /// Derives the recovery implied by one generic error.
    ///
    /// Retry advice produces [`Retry`](Self::Retry), and request-parameter
    /// verdicts such as `invalid_scope` produce
    /// [`AdjustRequest`](Self::AdjustRequest). The `prompt=none` verdicts
    /// `login_required`, `interaction_required`, `consent_required`, and
    /// `account_selection_required` produce
    /// [`Reauthenticate`](Self::Reauthenticate). Other failures produce
    /// [`Fail`](Self::Fail). This method cannot account for alternative
    /// acquisition paths held by a [`TokenSource`].
    #[must_use]
    pub(crate) fn implied_by(error: &Error) -> Self {
        // An explicit interaction requirement takes precedence over retry advice.
        if let Some(code) = error.verdict().map(crate::core::OAuthError::code) {
            if code.requires_interaction() {
                return Self::Reauthenticate;
            }
            if code.parameters_at_fault() {
                return Self::AdjustRequest;
            }
        }
        match error.retry_advice() {
            RetryAdvice::Retry { after } => Self::Retry { after },
            _ => Self::Fail,
        }
    }

    /// Returns whether retrying or changing the request may succeed without
    /// user interaction.
    #[must_use]
    pub(crate) fn leaves_a_live_path(self) -> bool {
        matches!(self, Self::Retry { .. } | Self::AdjustRequest)
    }
}

/// A token-acquisition failure, and what can be done about it.
///
/// Use [`recovery`](Self::recovery) for control flow and
/// [`as_error`](Self::as_error) for diagnostics or a caller-supplied cause.
#[derive(Debug)]
pub struct TokenError {
    recovery: Recovery,
    source: Error,
}

impl TokenError {
    /// Creates a token-acquisition error with an explicit recovery action.
    ///
    /// Use this in a [`TokenSource`] that knows whether another acquisition
    /// path remains. The underlying [`Error`] retains the retry advice, OAuth
    /// verdict, and cause for the operation that failed; `recovery` describes
    /// the larger token-acquisition operation.
    ///
    /// For a source with no additional recovery knowledge, convert the error
    /// with [`TokenError::from`] instead.
    ///
    /// [`TokenSource`]: crate::cache::TokenSource
    #[must_use]
    pub fn new(recovery: Recovery, source: Error) -> Self {
        Self { recovery, source }
    }

    /// Returns the recommended recovery action.
    #[must_use]
    pub fn recovery(&self) -> Recovery {
        self.recovery
    }

    /// Returns the authorization server's OAuth error response, if the server
    /// judged the request.
    ///
    /// A code found in a `429` or `5xx` response is not treated as a verdict.
    #[must_use]
    pub fn verdict(&self) -> Option<&crate::core::OAuthError> {
        self.source.verdict()
    }

    /// Returns the underlying generic error.
    ///
    /// Use [`Error::cause`](crate::core::Error::cause) on the result to
    /// downcast to an error supplied by the application.
    #[must_use]
    pub fn as_error(&self) -> &Error {
        &self.source
    }

    /// Returns the underlying generic error, consuming this acquisition error.
    ///
    /// Use this when a composing [`TokenSource`] needs to establish a different
    /// recovery action while preserving the operation's classification, cause,
    /// and location unchanged.
    #[must_use]
    pub fn into_error(self) -> Error {
        self.source
    }
}

/// Converts a generic error using the recovery implied by that failure alone.
///
/// This preserves a retry interval supplied by a transport, KMS, signer, or
/// other backend. A token source that knows about alternative acquisition paths
/// should use [`TokenError::new`] instead.
impl From<Error> for TokenError {
    fn from(source: Error) -> Self {
        Self {
            recovery: Recovery::implied_by(&source),
            source,
        }
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.source)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cache::{
            GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, Recovery, TokenError,
        },
        core::{
            Error, OAuthError, OAuthErrorCode, RetryAdvice, client_auth::NoAuth, http::HttpClient,
        },
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    };

    // Interaction-required verdicts require a new interactive authorization.
    #[test]
    fn a_server_demanding_interaction_is_a_reauthentication() {
        for code in [
            "login_required",
            "interaction_required",
            "consent_required",
            "account_selection_required",
        ] {
            let err = Error::propagate(
                crate::core::error::propagation::Classification::judged(
                    RetryAdvice::No,
                    OAuthError::new(code),
                ),
                "the callback",
            );
            assert_eq!(
                Recovery::implied_by(&err),
                Recovery::Reauthenticate,
                "{code}"
            );
        }

        // A user's explicit denial is not an interaction requirement.
        let denied = Error::propagate(
            crate::core::error::propagation::Classification::judged(
                RetryAdvice::No,
                OAuthError::new("access_denied"),
            ),
            "the callback",
        );
        assert_eq!(Recovery::implied_by(&denied), Recovery::Fail);
    }

    // Request-shape verdicts leave the credential intact.
    #[test]
    fn a_request_shape_verdict_is_adjustable() {
        for code in ["invalid_scope", "invalid_target", "invalid_client_metadata"] {
            let err = Error::propagate(
                crate::core::error::propagation::Classification::judged(
                    RetryAdvice::No,
                    OAuthError::new(code),
                ),
                "the token endpoint",
            );
            assert_eq!(
                Recovery::implied_by(&err),
                Recovery::AdjustRequest,
                "{code}"
            );
        }
    }

    // Local failures derive recovery from retry advice alone.
    #[test]
    fn a_local_failure_is_read_off_the_advice() {
        assert_eq!(
            Recovery::implied_by(&Error::new(RetryAdvice::RETRY, "the store timed out")),
            Recovery::Retry { after: None }
        );
        assert_eq!(
            Recovery::implied_by(&Error::new(RetryAdvice::No, "the keychain is locked")),
            Recovery::Fail
        );
    }

    #[test]
    fn consuming_a_token_error_preserves_the_underlying_error() {
        let source = Error::propagate(
            crate::core::error::propagation::Classification::judged(
                RetryAdvice::RETRY,
                OAuthError::new("temporarily_unavailable"),
            ),
            "the token endpoint",
        );
        let location = source.location();

        let source = TokenError::new(Recovery::Fail, source).into_error();

        assert_eq!(source.retry_advice(), RetryAdvice::RETRY);
        assert_eq!(
            source.verdict().map(OAuthError::code),
            Some(&OAuthErrorCode::TemporarilyUnavailable),
        );
        assert_eq!(source.location(), location);
        assert_eq!(source.to_string(), "the token endpoint");
    }

    struct NoHttp;

    impl HttpClient for NoHttp {
        fn execute(
            &self,
            _request: http::Request<bytes::Bytes>,
            _idempotency: crate::core::http::Idempotency,
        ) -> crate::core::platform::MaybeSendBoxFuture<
            '_,
            Result<crate::core::http::HttpResponse, crate::core::Error>,
        > {
            panic!("test only builds the cache, no HTTP expected")
        }
    }

    #[test]
    fn test_setup() {
        let source = GrantTokenSource::builder()
            .grant(
                ClientCredentialsGrant::builder()
                    .client_id("client_id")
                    .client_auth(NoAuth)
                    .token_endpoint("https://blah".parse().unwrap())
                    .http_client(NoHttp)
                    .build(),
            )
            .grant_parameters(
                ClientCredentialsGrantParameters::builder()
                    .scope(bon::vec!["read", "write"])
                    .build(),
            )
            .refresh_store(InMemoryRefreshTokenStore::default())
            .build();
        let _cache = InMemoryTokenCache::builder().source(source).build();
    }
}

/// A store for refresh tokens — [`get`](Self::get) / [`set`](Self::set) /
/// [`clear`](Self::clear).
///
/// Dyn-capable: implement it on your own store type (for example a keychain- or
/// disk-backed store) and hand it to a cache builder. The built-in is
/// [`InMemoryRefreshTokenStore`].
///
/// A [`GrantTokenSource`] treats its store as singly owned. Sharing one store
/// across owners or processes is safe *except* for rotation-only public clients
/// — see [sharing a token store](crate::_docs::explanation::sharing_a_token_store)
/// before sharing.
pub trait RefreshTokenStore: MaybeSendSync {
    /// Returns the current refresh token, if one exists.
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>>;
    /// Sets the current refresh token.
    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>>;
    /// Clears the current refresh token.
    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>>;
}

macro_rules! forward_refresh_token_store {
    ($wrapper:ty) => {
        impl<T: RefreshTokenStore + ?Sized> RefreshTokenStore for $wrapper {
            fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
                (**self).get()
            }

            fn set<'a>(
                &'a self,
                token: &'a RefreshToken,
            ) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
                (**self).set(token)
            }

            fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
                (**self).clear()
            }
        }
    };
}

forward_refresh_token_store!(&T);
forward_refresh_token_store!(Box<T>);
forward_refresh_token_store!(std::sync::Arc<T>);

/// An in-memory store for refresh tokens.
#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenStore {
    refresh_token: RwLock<Option<RefreshToken>>,
}

impl RefreshTokenStore for InMemoryRefreshTokenStore {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        Box::pin(async {
            Ok(self
                .refresh_token
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone())
        })
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async {
            *self
                .refresh_token
                .write()
                .unwrap_or_else(PoisonError::into_inner) = Some(token.clone());
            Ok(())
        })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async {
            *self
                .refresh_token
                .write()
                .unwrap_or_else(PoisonError::into_inner) = None;
            Ok(())
        })
    }
}

#[cfg(test)]
mod outcomes {
    use super::*;
    use crate::core::{Error, RetryAdvice};

    // `EnumCount` makes this fail when a new variant lacks an outcome label.
    #[test]
    fn every_failure_has_a_distinct_outcome_label() {
        use strum::EnumCount as _;

        let cases = [
            (
                GetTokenError::RefreshFailed {
                    source: Error::new(RetryAdvice::No, "refresh"),
                },
                TokenOutcome::RefreshFailed,
            ),
            (
                GetTokenError::BothFailed {
                    reported: Error::new(RetryAdvice::No, "exchange"),
                    other: Error::new(RetryAdvice::No, "refresh"),
                    reported_attempt: Attempt::Exchange,
                },
                TokenOutcome::BothFailed,
            ),
            (
                GetTokenError::ExchangeFailed {
                    source: Error::new(RetryAdvice::No, "exchange"),
                },
                TokenOutcome::ExchangeFailed,
            ),
            (GetTokenError::NoTokenSource, TokenOutcome::NoTokenSource),
            (GetTokenError::Backoff, TokenOutcome::Backoff),
        ];

        assert_eq!(
            cases.len(),
            GetTokenError::COUNT,
            "a variant was added without an outcome label",
        );

        let mut labels = Vec::new();
        for (cause, expected) in cases {
            assert_eq!(cause.outcome(), expected, "{cause}");
            let label = expected.as_str();
            assert!(
                !labels.contains(&label),
                "duplicate label {label}: two failures would be indistinguishable"
            );
            labels.push(label);
        }
        // `Success` is the sixth label and shares the namespace, so it must not
        // collide with a failure.
        assert!(!labels.contains(&TokenOutcome::Success.as_str()));
    }
}
