//! Injectable wall clocks and monotonic timers, independent of the async executor.
//!
//! Consumers can store `Arc<dyn Clock>` and `Arc<dyn Timer>` without adding type
//! parameters. [`ManualTime`] implements both interfaces on one shared timeline.
//! Existing [`crate::platform`] time APIs are unchanged and do not use these
//! providers automatically.
//!
//! The value types use `core`, and the traits need only `core` and `alloc`.
//! This does not make `huskarl-core` itself `no_std`: the supplied manual and
//! platform implementations currently use `std`. Embedded hosts can supply their
//! own implementations. Defaults are provided for native and browser/worker
//! hosts. WASI 0.1/0.2 retain the existing platform clock and Tokio sleep backend.
//!
//! Wall time uses [`jiff::Timestamp`] directly, with Jiff's range and signed
//! fractional-second representation.
//! Platform conversions are implementation details of the `SystemTime` migration.
//!
//! Jiff's Serde support serializes timestamps as strings, preserving nanoseconds.
//! For integer epoch fields, use `#[serde(with = "...")]` with Jiff's
//! `jiff::fmt::serde::timestamp::{second,millisecond,microsecond,nanosecond}`
//! `required` or `optional` adapters. Whole-second adapters discard fractions.
//! Existing OAuth/JWT `SystemTime` fields retain the numeric adapters in
//! [`crate::serde_utils::time`], including their validation and fractional-number
//! input rules.
//
// TODO(0.12): Replace public wall-time SystemTime fields, parameters, and return
// values across the workspace with jiff::Timestamp, including JWT claims and
// validation, token receipts/expiry, and authorization response deadlines. Keep
// validation and expiry arithmetic in Timestamp; convert SystemTime only at
// platform or explicit interoperability boundaries. Preserve the protocol's
// numeric timestamp encoding and validation rules through explicit Serde adapters.
// Duration and monotonic timer instants remain separate from wall timestamps.
//!
//! ```
//! use std::sync::Arc;
//!
//! use huskarl_core::time::{Clock, Duration, ManualTime, Timer};
//!
//! let time = ManualTime::new(jiff::Timestamp::UNIX_EPOCH);
//! let clock: Arc<dyn Clock> = Arc::new(time.clone());
//! let timer: Arc<dyn Timer> = Arc::new(time.clone());
//! let start = timer.now();
//! time.advance(Duration::from_secs(10))?;
//! assert_eq!(
//!     timer.now().checked_duration_since(start),
//!     Some(Duration::from_secs(10))
//! );
//! assert_eq!(clock.now().as_second(), 10);
//! # Ok::<(), huskarl_core::time::TimeOverflow>(())
//! ```

mod conversion;
mod manual;
mod platform;
mod types;

pub use core::time::Duration;

pub use conversion::timestamp_from_unix_parts;
// Cross-crate implementation helpers used by huskarl until the 0.12 migration.
#[doc(hidden)]
pub use conversion::{
    system_time_from_timestamp, system_time_from_timestamp_saturating,
    timestamp_from_system_time_saturating,
};
pub(crate) use conversion::{timestamp_from_std_system_time, unix_seconds_from_timestamp};
pub use manual::ManualTime;
pub use platform::{PlatformClock, PlatformTimer};
pub use types::{MonotonicInstant, TimeOverflow, TimerDomain};

use crate::platform::{MaybeSendBoxFuture, MaybeSendSync};

/// A source of wall-clock timestamps, which may move backward or forward.
///
/// Unwind-safety bounds preserve the guarantees of existing types storing clocks.
pub trait Clock:
    core::fmt::Debug + MaybeSendSync + core::panic::UnwindSafe + core::panic::RefUnwindSafe
{
    /// Read the current time relative to the Unix epoch.
    fn now(&self) -> jiff::Timestamp;
}

/// A monotonic clock and asynchronous deadline scheduler in the same domain.
///
/// Instants may only be compared or passed to a timer sharing their origin.
/// Each provider must retain one stable scheduling [`TimerDomain`].
/// Clones of a provider must share that domain and origin. Readings must not decrease;
/// whether time advances during system suspension is implementation-dependent.
/// Implementations must not require a particular executor unless documented.
/// Unwind-safety bounds preserve the guarantees of existing types storing timers.
pub trait Timer:
    core::fmt::Debug + MaybeSendSync + core::panic::UnwindSafe + core::panic::RefUnwindSafe
{
    /// Read the current monotonic time.
    fn now(&self) -> MonotonicInstant;

    /// Wait until this timer reaches `deadline`.
    ///
    /// An elapsed deadline is ready on its first poll. Polling must not block
    /// the executor thread. Completion may be late but must not be early.
    /// Dropping the future cancels the wait and releases its registration.
    /// Advancing time before the first poll must not lose the wakeup.
    ///
    /// # Panics
    /// The built-in timers panic before returning a future for a foreign domain.
    /// Custom implementations should reject foreign deadlines too; use
    /// [`MonotonicInstant::assert_same_domain`] to check before scheduling.
    fn sleep_until(&self, deadline: MonotonicInstant) -> MaybeSendBoxFuture<'_, ()>;
}

impl<T: Clock + ?Sized> Clock for alloc::sync::Arc<T> {
    fn now(&self) -> jiff::Timestamp {
        self.as_ref().now()
    }
}

impl<T: Timer + ?Sized> Timer for alloc::sync::Arc<T> {
    fn now(&self) -> MonotonicInstant {
        self.as_ref().now()
    }

    fn sleep_until(&self, deadline: MonotonicInstant) -> MaybeSendBoxFuture<'_, ()> {
        self.as_ref().sleep_until(deadline)
    }
}

#[cfg(test)]
pub(crate) mod test_support;
