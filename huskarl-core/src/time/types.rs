use core::{fmt, time::Duration};

/// A timestamp or duration cannot be represented by the destination type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeOverflow;

impl fmt::Display for TimeOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("time is outside the representable range")
    }
}

impl core::error::Error for TimeOverflow {}

/// Identity of a monotonic timeline, shared by providers with comparable readings.
///
/// Allocate once per independent timeline and retain it for every reading.
/// Clones share the identity. Tags are process-local and must not be persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerDomain(usize);

impl TimerDomain {
    /// Allocate a unique timeline identity.
    ///
    /// # Panics
    /// Panics if all process-local identities have been allocated.
    #[must_use]
    pub fn new() -> Self {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        #[allow(deprecated, reason = "try_update requires Rust 1.95; the MSRV is 1.92")]
        match NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1)) {
            Ok(id) => Self(id),
            #[allow(
                clippy::panic,
                reason = "Identity exhaustion must not reuse a timer domain"
            )]
            Err(id) => panic!("timer domain identities exhausted at {id}"),
        }
    }
}

impl Default for TimerDomain {
    fn default() -> Self {
        Self::new()
    }
}

/// A point on a tagged monotonic timeline, measured from its arbitrary origin.
///
/// Instants from different domains are unequal. Ordering operators are not
/// supported; use [`Self::checked_duration_since`] to measure elapsed time
/// between readings from the same domain.
/// This is not a Unix timestamp and must not be persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MonotonicInstant {
    domain: TimerDomain,
    offset: Duration,
}

impl MonotonicInstant {
    /// Construct a reading relative to the given domain's origin.
    #[must_use]
    pub const fn from_duration_since_origin(domain: TimerDomain, duration: Duration) -> Self {
        Self {
            domain,
            offset: duration,
        }
    }

    /// The timeline this reading belongs to.
    #[must_use]
    pub const fn domain(self) -> TimerDomain {
        self.domain
    }

    /// Assert that this instant belongs to the expected timer domain.
    ///
    /// Timer implementations can use this before scheduling a deadline.
    ///
    /// # Panics
    /// Panics if the domains differ.
    pub fn assert_same_domain(self, domain: TimerDomain) {
        assert_eq!(self.domain, domain, "timer domain mismatch");
    }

    /// Return the reading relative to the provider's origin, for backend adapters.
    #[must_use]
    pub const fn duration_since_origin(self) -> Duration {
        self.offset
    }

    /// Add a duration, preserving the domain and returning None on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.offset
            .checked_add(duration)
            .map(|offset| Self { offset, ..self })
    }

    /// Subtract a duration, preserving the domain and returning None before the origin.
    #[must_use]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        self.offset
            .checked_sub(duration)
            .map(|offset| Self { offset, ..self })
    }

    /// Measure elapsed time, returning None if the earlier reading is later than this one.
    ///
    /// # Panics
    /// Panics if the readings belong to different domains.
    #[must_use]
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.assert_same_domain(earlier.domain);
        self.offset.checked_sub(earlier.offset)
    }
}
