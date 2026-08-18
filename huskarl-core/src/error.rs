//! Error classification and reporting.
//!
//! [`Error`] combines retry advice, an optional OAuth server verdict, and an
//! erased cause. See [the error model](crate::_docs::explanation::error_handling)
//! for the design rationale.

use std::fmt;

use crate::platform::Duration;

pub mod propagation;

/// A type-erased error source. It is `Send + Sync` except on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSource = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A type-erased error source.
#[cfg(target_arch = "wasm32")]
pub type BoxedSource = Box<dyn std::error::Error + 'static>;

/// An error from a huskarl operation.
///
/// It stores an erased [`cause`](Self::cause), retry advice, and an optional
/// OAuth [`verdict`](Self::verdict). Its [`Display`](fmt::Display)
/// implementation delegates to the cause instead of adding another message.
pub struct Error(Box<Inner>);

/// Boxed to keep [`Error`] one pointer wide.
#[derive(Debug)]
struct Inner {
    retry_advice: RetryAdvice,
    verdict: Option<crate::oauth_error::OAuthError>,
    location: &'static std::panic::Location<'static>,
    cause: BoxedSource,
}

impl fmt::Debug for Error {
    // Show the fields of the conceptual error rather than the boxed `Inner`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("retry_advice", &self.0.retry_advice)
            .field("verdict", &self.0.verdict)
            .field("location", &self.0.location)
            .field("cause", &self.0.cause)
            .finish()
    }
}

/// Whether retrying the failed operation may help, and when.
///
/// This classifies only the failed operation. Callers should also apply their
/// own retry budget, deadline, and backoff policy.
///
/// This enum is non-exhaustive. Treat unknown variants conservatively, like
/// [`No`](Self::No).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAdvice {
    /// The same operation may succeed later.
    Retry {
        /// The minimum delay reported by the source, if known.
        ///
        /// `None` means the caller should choose a delay using its own backoff
        /// policy.
        after: Option<Duration>,
    },
    /// Retrying this operation is not expected to help.
    No,
}

impl RetryAdvice {
    /// Retry with no particular delay.
    pub const RETRY: Self = Self::Retry { after: None };

    /// Returns [`RETRY`](Self::RETRY) when re-sending is safe, or
    /// [`No`](Self::No) otherwise.
    ///
    /// This is useful in transport layers that determine retryability from the
    /// failure and the request's [idempotency](crate::http::Idempotency).
    #[must_use]
    pub const fn retry_if(retryable: bool) -> Self {
        if retryable { Self::RETRY } else { Self::No }
    }

    /// Returns advice to retry after at least `after` has elapsed.
    #[must_use]
    pub const fn retry_after(after: Duration) -> Self {
        Self::Retry { after: Some(after) }
    }
}

impl Error {
    /// Creates an error with the given retry advice and cause.
    ///
    /// Use [`propagate`](Self::propagate) instead when `cause` wraps an existing
    /// [`Error`], so its complete classification is preserved. The caller's
    /// location is recorded and returned by [`location`](Self::location).
    ///
    /// # Panics
    ///
    /// With the `strict-propagation` feature, panics if the cause chain already
    /// contains an [`Error`]. This check is also enabled in this crate's tests.
    ///
    /// # Examples
    ///
    /// ```
    /// use huskarl_core::{Error, RetryAdvice};
    ///
    /// let error = Error::new(RetryAdvice::No, "the breaker is open");
    /// assert_eq!(error.to_string(), "the breaker is open");
    /// ```
    #[track_caller]
    #[must_use]
    pub fn new(retry_advice: RetryAdvice, cause: impl Into<BoxedSource>) -> Self {
        let cause = cause.into();
        assert_not_already_classified(cause.as_ref(), Establishment::New);
        Self(Box::new(Inner {
            retry_advice,
            verdict: None,
            location: std::panic::Location::caller(),
            cause,
        }))
    }

    /// Returns the OAuth error from an authorization server rejection.
    ///
    /// Returns `None` when the failure is not a server rejection. This includes
    /// a `429` or `5xx` response whose body contains an OAuth error code: the
    /// response is a transient server failure, not a verdict on the request.
    #[must_use]
    pub fn verdict(&self) -> Option<&crate::oauth_error::OAuthError> {
        self.0.verdict.as_ref()
    }

    /// Returns whether retrying the failed operation may help.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        self.0.retry_advice
    }

    /// Returns the call site at which this error was constructed.
    #[must_use]
    pub fn location(&self) -> &'static std::panic::Location<'static> {
        self.0.location
    }

    /// Returns the erased cause supplied when this error was constructed.
    ///
    /// Use this to downcast to an error type supplied by your own
    /// [`HttpClient`](crate::http::HttpClient), signer, store, or other backend.
    /// Because [`Error`] displays this cause directly, the cause is not repeated
    /// in the [`source`](std::error::Error::source) chain.
    ///
    /// ```
    /// # use huskarl_core::{Error, RetryAdvice};
    /// # #[derive(Debug)] struct KeychainLocked;
    /// # impl std::fmt::Display for KeychainLocked {
    /// #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("locked") }
    /// # }
    /// # impl std::error::Error for KeychainLocked {}
    /// let err = Error::new(RetryAdvice::RETRY, KeychainLocked);
    /// assert!(err.cause().downcast_ref::<KeychainLocked>().is_some());
    /// ```
    #[must_use]
    pub fn cause(&self) -> &(dyn std::error::Error + 'static) {
        self.0.cause.as_ref()
    }

    /// Returns this error and its sources, outermost first.
    ///
    /// The erased [`cause`](Self::cause) is represented by this error's own
    /// display, so it is not repeated as the next item. Alternate display
    /// (`{error:#}`) joins the messages with `": "`.
    #[must_use]
    pub fn chain(&self) -> Chain<'_> {
        Chain { next: Some(self) }
    }
}

/// Returns an error and its sources, outermost first.
#[must_use]
#[cfg(any(test, feature = "strict-propagation"))]
fn chain<'a>(error: &'a (dyn std::error::Error + 'static)) -> Chain<'a> {
    Chain { next: Some(error) }
}

// Reject attempts to establish a new classification over an existing one.
//
// `Classify` catches most mistakes from field types, but aliases and nested
// cause enums can hide an `Error` from the derive. Inspect the entire observable
// source chain here, where every new classification is created.
//
// A transparent wrapper can delegate `source()` past its `Error`, making that
// value impossible to detect. Such wrappers must explicitly return
// `Origin::Propagates` and cover that path with a propagation test.
#[cfg(any(test, feature = "strict-propagation"))]
#[track_caller]
fn assert_not_already_classified(
    cause: &(dyn std::error::Error + 'static),
    establishment: Establishment,
) {
    let already_classified = chain(cause).any(<dyn std::error::Error + 'static>::is::<Error>);
    match establishment {
        Establishment::New => assert!(
            !already_classified,
            "`Error::new` was handed a cause wrapping an already-classified `Error`, \
             which discards its classification. Use `Error::propagate` with the inner \
             error's `classification()`, or `Classification::with_retry_advice` to \
             override one member of it."
        ),
        Establishment::Origin => assert!(
            !already_classified,
            "`Cause::origin` returned `Origin::Establishes` for a cause wrapping an \
             already-classified `Error`, which discards its classification. Return \
             `Origin::Propagates` with the inner `Error`; returning a copied \
             `Classification` still establishes rather than propagates."
        ),
    }
}

// This invariant belongs to this workspace, so do not impose the check on
// downstream users unless they enable it explicitly.
#[cfg(not(any(test, feature = "strict-propagation")))]
#[inline]
fn assert_not_already_classified(
    _cause: &(dyn std::error::Error + 'static),
    _establishment: Establishment,
) {
}

#[derive(Clone, Copy)]
pub(super) enum Establishment {
    New,
    Origin,
}

impl fmt::Display for Error {
    // The erased cause supplies this layer's message. `{:#}` appends the rest
    // of the source chain, separated by `": "`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not pass the alternate flag through: for `Error`, it means to walk
        // the source chain, not to format the cause in alternate form.
        write!(f, "{}", self.0.cause)?;
        if f.alternate() {
            for cause in self.chain().skip(1) {
                write!(f, ": {cause}")?;
            }
        }
        Ok(())
    }
}

/// An iterator over an error and its sources.
///
/// Items can be downcast with `downcast_ref`.
#[derive(Debug, Clone)]
pub struct Chain<'a> {
    next: Option<&'a (dyn std::error::Error + 'static)>,
}

impl<'a> Iterator for Chain<'a> {
    type Item = &'a (dyn std::error::Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        self.next = current.source();
        Some(current)
    }
}

impl std::iter::FusedIterator for Chain<'_> {}

impl fmt::Display for RetryAdvice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry { after: None } => f.write_str("retry"),
            // `Duration`'s `Debug` is the human-readable form ("30s", "1.5s");
            // its `Display` does not exist.
            Self::Retry { after: Some(after) } => write!(f, "retry after {after:?}"),
            Self::No => f.write_str("not retryable"),
        }
    }
}

impl std::error::Error for Error {
    // The cause is rendered as this layer, so its source is the next distinct
    // item in the chain.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.cause.source()
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

    // Adds depth to the source chain used by the display tests.
    #[derive(Debug)]
    struct Outer(Underlying);

    impl fmt::Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("outer")
        }
    }

    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    // A typical wrapper that propagates the classification of an inner `Error`.
    #[derive(Debug)]
    struct Wrapping(Error);

    impl fmt::Display for Wrapping {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("refreshing the access token")
        }
    }

    impl std::error::Error for Wrapping {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    // A reporter that walks `source` must render every message only once.
    #[test]
    fn the_erasure_is_transparent() {
        let err = Error::new(RetryAdvice::No, Outer(Underlying));

        // The error displays the cause, then skips to the cause's source.
        assert_eq!(err.to_string(), "outer");
        let next = std::error::Error::source(&err).expect("outer has a source");
        assert_eq!(next.to_string(), "underlying");
    }

    // Walking `source` renders every layer exactly once.
    #[test]
    fn a_reporter_sees_each_message_once() {
        let inner = Error::new(RetryAdvice::RETRY, Outer(Underlying));
        let outer = Error::propagate(inner.classification(), Wrapping(inner));

        let rendered: Vec<String> = chain(&outer).map(ToString::to_string).collect();
        assert_eq!(
            rendered,
            ["refreshing the access token", "outer", "underlying"]
        );

        // No message is repeated.
        let mut seen = rendered.clone();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), rendered.len(), "{rendered:?}");
    }

    // `{}` renders one layer; `{:#}` renders the complete chain.
    #[test]
    fn alternate_display_renders_the_whole_chain() {
        let err = Error::new(RetryAdvice::No, Outer(Underlying));
        assert_eq!(format!("{err}"), "outer");
        assert_eq!(format!("{err:#}"), "outer: underlying");
    }

    // The erased cause is omitted, but its sources remain available.
    #[test]
    fn a_supplied_error_is_still_recoverable() {
        let err = Error::new(RetryAdvice::No, Outer(Underlying));
        assert!(
            err.chain()
                .find_map(|e| e.downcast_ref::<Underlying>())
                .is_some(),
            "a cause below the erasure must stay downcastable"
        );
        // The erased layer itself is not yielded.
        assert!(
            err.chain()
                .find_map(|e| e.downcast_ref::<Outer>())
                .is_none()
        );
    }

    // The constructor preserves each form of retry advice.
    #[test]
    fn advice_is_whatever_the_site_established() {
        assert_eq!(
            Error::new(RetryAdvice::RETRY, Underlying).retry_advice(),
            RetryAdvice::RETRY
        );
        assert_eq!(
            Error::new(
                RetryAdvice::retry_after(Duration::from_secs(30)),
                Underlying
            )
            .retry_advice(),
            RetryAdvice::Retry {
                after: Some(Duration::from_secs(30))
            }
        );
        assert_eq!(
            Error::new(RetryAdvice::No, Underlying).retry_advice(),
            RetryAdvice::No
        );
    }

    // A representative cause-to-`Error` conversion.
    impl From<Underlying> for Error {
        #[track_caller]
        fn from(source: Underlying) -> Self {
            Self::new(RetryAdvice::No, source)
        }
    }

    // `#[track_caller]` on `From` must preserve the location of `?`. Without it,
    // errors report the `Self::new` call inside the conversion.
    #[test]
    fn location_survives_the_question_mark_through_a_from_impl() {
        // Keep this adjacent to the closure: the test relies on the line offset.
        let expected_line = line!() + 2;
        let err = (|| -> Result<(), Error> {
            Err(Underlying)?;
            Ok(())
        })()
        .expect_err("the closure always fails");

        assert_eq!(err.location().file(), file!());
        assert_eq!(
            err.location().line(),
            expected_line,
            "the location must be the `?`, not the `From` impl's body"
        );
    }

    // `#[track_caller]` must name the construction site, not `Error::new`.
    #[test]
    fn location_is_the_construction_site() {
        let here = std::panic::Location::caller().file();
        let err = Error::new(RetryAdvice::No, Underlying);
        assert_eq!(err.location().file(), here, "{err:?}");
    }

    #[test]
    fn debug_names_the_public_error_type() {
        let rendered = format!("{:?}", Error::new(RetryAdvice::No, Underlying));

        assert!(rendered.starts_with("Error {"), "{rendered}");
        assert!(!rendered.contains("Inner"), "{rendered}");
    }

    // Establishing a classification over an existing one must be rejected.
    #[test]
    #[should_panic(expected = "discards its classification")]
    fn classifying_over_an_already_classified_error_panics() {
        let inner = Error::new(
            RetryAdvice::retry_after(Duration::from_secs(97)),
            "the underlying failure",
        );
        let _ = Error::new(RetryAdvice::No, Wrapping(inner));
    }

    // An intermediate source must not hide an existing classification.
    #[test]
    #[should_panic(expected = "discards its classification")]
    fn a_classification_two_layers_down_is_still_found() {
        #[derive(Debug)]
        struct Interposed(Wrapping);

        impl fmt::Display for Interposed {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("interposed")
            }
        }

        impl std::error::Error for Interposed {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let inner = Error::new(RetryAdvice::RETRY, "the underlying failure");
        let _ = Error::new(RetryAdvice::No, Interposed(Wrapping(inner)));
    }

    /// The two documented uses of `new` — a leaf cause type and a bare string —
    /// must not trip it. A check that fires on the common case gets disabled.
    #[test]
    fn a_leaf_cause_is_left_alone() {
        assert_eq!(
            Error::new(RetryAdvice::No, Outer(Underlying)).to_string(),
            "outer"
        );
        assert_eq!(
            Error::new(RetryAdvice::No, "the breaker is open").to_string(),
            "the breaker is open"
        );
    }

    /// And the correct route is unaffected, which is the whole point: the check
    /// pushes wrapping layers onto `propagate`, where the classification travels
    /// whole.
    ///
    /// Both members are non-default here. The per-cause-enum tables this
    /// replaces used a verdict-less witness, so they could only ever have caught
    /// a dropped *advice* — a wrapper that carried the advice and dropped the
    /// verdict passed them.
    #[test]
    fn propagate_carries_the_classification_whole() {
        let inner = Error::propagate(
            propagation::Classification::judged(
                RetryAdvice::retry_after(Duration::from_secs(97)),
                crate::oauth_error::OAuthError::new("invalid_grant"),
            ),
            "the underlying failure",
        );
        let expected = inner.classification();
        assert_eq!(
            expected,
            Error::propagate(expected.clone(), Wrapping(inner)).classification()
        );
    }
}

#[cfg(test)]
mod size {
    /// `Result<T, Error>` is nearly every return type, so the error variant
    /// stays one pointer wide — why [`super::Error`] boxes, as `io::Error` does.
    #[test]
    fn error_is_pointer_sized() {
        assert_eq!(size_of::<super::Error>(), size_of::<*const ()>());
    }
}

/// Callers embed [`Error`] in their own enums and send those across threads, so
/// losing either auto-trait would break dependents with an error naming *their*
/// enum. A `const` item, so it fails the build that introduces it.
#[cfg(not(target_arch = "wasm32"))]
const _: () = {
    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<Error>();
};
