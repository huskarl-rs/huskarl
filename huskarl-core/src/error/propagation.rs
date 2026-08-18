//! Propagating error classifications through wrapping layers.
//!
//! Backend and internal errors use [`Cause`] and [`Origin`] to distinguish new
//! classifications from wrappers that preserve an existing one. Applications
//! that only handle [`Error`] values normally do not need this module.

use super::{BoxedSource, Error, Inner, RetryAdvice};

/// Describes where an error variant gets its classification.
#[derive(Debug)]
pub enum Origin<'a> {
    /// Preserves the classification of a wrapped [`Error`].
    ///
    /// To change only the retry advice, return [`Establishes`](Self::Establishes)
    /// with the result of [`Error::classification`] modified by
    /// [`Classification::with_retry_advice`].
    Propagates(&'a Error),
    /// Establishes a new classification.
    Establishes(Classification),
}

/// An error type whose variants report how they are classified.
///
/// Implement this trait, usually via `#[derive(Classify)]`, when converting an
/// error enum with [`Error::from_cause`]. Each variant chooses independently
/// because an enum can contain both leaf failures and wrappers.
pub trait Cause: std::error::Error + crate::platform::MaybeSendSync + 'static + Sized {
    /// Returns the classification origin for this variant.
    fn origin(&self) -> Origin<'_>;
}

impl Error {
    /// Creates an [`Error`] from a classified cause.
    ///
    /// [`Origin::Propagates`] preserves a wrapped error's classification, while
    /// [`Origin::Establishes`] uses the supplied classification. The caller's
    /// location is available through [`Error::location`].
    ///
    /// # Panics
    ///
    /// With the `strict-propagation` feature, panics if the cause reports
    /// [`Origin::Establishes`] while its source chain already contains an
    /// [`Error`]. This check is also enabled in this crate's tests. A transparent
    /// wrapper can delegate `source()` past its `Error`, hiding it from this
    /// check; such a wrapper must report [`Origin::Propagates`] itself.
    #[track_caller]
    #[must_use]
    pub fn from_cause<C: Cause + Into<BoxedSource>>(cause: C) -> Self {
        let classification = match cause.origin() {
            Origin::Propagates(inner) => inner.classification(),
            Origin::Establishes(classification) => {
                // Check here because this branch calls `propagate`, bypassing
                // the equivalent guard in `Error::new`.
                super::assert_not_already_classified(&cause, super::Establishment::Origin);
                classification
            }
        };
        Self::propagate(classification, cause)
    }
}

/// The programmatic classification preserved when an [`Error`] is wrapped.
///
/// Obtain it with [`Error::classification`] and apply it to a wrapping cause
/// with [`Error::propagate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    retry_advice: RetryAdvice,
    verdict: Option<crate::oauth_error::OAuthError>,
}

impl Classification {
    /// Replaces the retry advice while preserving the rest of the classification.
    #[must_use]
    pub fn with_retry_advice(mut self, retry_advice: RetryAdvice) -> Self {
        self.retry_advice = retry_advice;
        self
    }

    /// Returns whether retrying the failed operation may help.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        self.retry_advice
    }

    /// Creates a classification for an authorization server rejection.
    ///
    /// Use this only when the authorization server judged the request. When a
    /// full HTTP response is available, use
    /// [`FailedResponse::classification`](crate::http::FailedResponse::classification)
    /// so it can also apply the status and `Retry-After` header.
    #[must_use]
    pub fn judged(retry_advice: RetryAdvice, verdict: crate::oauth_error::OAuthError) -> Self {
        Self {
            retry_advice,
            verdict: Some(verdict),
        }
    }

    /// Returns the OAuth error from an authorization server rejection.
    ///
    /// This has the same contract as [`Error::verdict`].
    #[must_use]
    pub fn verdict(&self) -> Option<&crate::oauth_error::OAuthError> {
        self.verdict.as_ref()
    }
}

/// Creates a classification with no OAuth verdict.
impl From<RetryAdvice> for Classification {
    fn from(retry_advice: RetryAdvice) -> Self {
        Self {
            retry_advice,
            verdict: None,
        }
    }
}

impl Error {
    /// Establishes a fresh classification around a cause.
    ///
    /// Unlike [`propagate`](Self::propagate), this checks that the cause does
    /// not already contain a classified [`Error`]. For crate-internal paths
    /// whose classification is computed as a value rather than by a [`Cause`]
    /// implementation.
    #[track_caller]
    pub(crate) fn establish(classification: Classification, cause: impl Into<BoxedSource>) -> Self {
        let cause = cause.into();
        super::assert_not_already_classified(&*cause, super::Establishment::New);
        Self::propagate(classification, cause)
    }

    /// Creates an error around `cause` with an existing classification.
    ///
    /// Obtain `classification` from [`Error::classification`] before moving the
    /// inner error into the wrapping cause. The caller's location is recorded
    /// and returned by [`location`](Self::location).
    #[track_caller]
    #[must_use]
    // Take ownership because the wrapping layer carries the classification
    // outward with the new error.
    pub fn propagate(classification: Classification, cause: impl Into<BoxedSource>) -> Self {
        // Destructure so adding a field forces this propagation path to handle it.
        let Classification {
            retry_advice,
            verdict,
        } = classification;
        Self(Box::new(Inner {
            retry_advice,
            verdict,
            location: std::panic::Location::caller(),
            cause: cause.into(),
        }))
    }

    /// Returns this error's classification for use with
    /// [`propagate`](Self::propagate).
    #[must_use]
    pub fn classification(&self) -> Classification {
        Classification {
            retry_advice: self.0.retry_advice,
            verdict: self.0.verdict.clone(),
        }
    }
}

// Outside wasm32, callers may move errors containing this value between
// threads. Keep that requirement checked at compile time.
#[cfg(not(target_arch = "wasm32"))]
const _: () = {
    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<Classification>();
};

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    #[derive(Debug)]
    struct FalseLeaf(Error);

    impl fmt::Display for FalseLeaf {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("wrapping the backend failure")
        }
    }

    impl std::error::Error for FalseLeaf {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    impl Cause for FalseLeaf {
        fn origin(&self) -> Origin<'_> {
            Origin::Establishes(RetryAdvice::No.into())
        }
    }

    #[test]
    #[should_panic(expected = "Return `Origin::Propagates` with the inner `Error`")]
    fn a_false_establishment_names_the_origin_fix() {
        let inner = Error::new(RetryAdvice::RETRY, "the backend failure");
        let _ = Error::from_cause(FalseLeaf(inner));
    }
}
