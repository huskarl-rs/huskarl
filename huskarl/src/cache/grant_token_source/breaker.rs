//! The backoff breaker used by [`GrantTokenSource`](super::GrantTokenSource) to
//! bound repeated from-scratch failures.

use std::sync::{Mutex, PoisonError};

use crate::core::platform::{Duration, Instant};

/// Backoff breaker bounding repeated non-recoverable from-scratch acquisitions.
///
/// A self-contained state machine: it counts consecutive non-recoverable
/// failures and, once `threshold` of them accrue, opens for `cooldown`.
/// [`try_acquire`](Self::try_acquire) then denies permission until the cooldown
/// elapses, after which it permits one trial (half-open); any success
/// [`reset`](Self::reset)s it.
///
/// The `threshold`/`cooldown` knobs live on the owning
/// [`GrantTokenSource`](super::GrantTokenSource) (so they sit on its builder)
/// and are passed in per call — this type owns only the runtime state and its
/// lock. It is deliberately ignorant of the token error vocabulary: the owner
/// decides which failures count (see
/// [`counts_toward_breaker`](super::GrantTokenSource::counts_toward_breaker))
/// and which error to surface when blocked.
#[derive(Default)]
pub(super) struct Breaker {
    state: Mutex<BreakerState>,
}

#[derive(Default)]
struct BreakerState {
    /// Non-recoverable from-scratch failures since the last success.
    consecutive: u32,
    /// When set and not yet reached, the breaker is open (cooling down).
    open_until: Option<Instant>,
}

impl Breaker {
    /// Tries to acquire permission for one from-scratch attempt.
    ///
    /// Returns `true` if permitted. While cooling down it returns `false`; once
    /// the cooldown elapses it permits a single trial (half-open) and restarts
    /// the cooldown in the same locked section, so the trial is exclusive and
    /// the next one is a full `cooldown` away whatever this one does. Only
    /// [`reset`](Self::reset) — a success — closes the breaker; the failure
    /// count is retained meanwhile, so a countable failure re-opens it. A
    /// `threshold` of `0` disables the breaker (always permits).
    pub(super) fn try_acquire(&self, threshold: u32, cooldown: Duration) -> bool {
        if threshold == 0 {
            return true;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(open_until) = state.open_until {
            let now = Instant::now();
            if now < open_until {
                return false;
            }
            // Re-arm as the permit is handed out rather than waiting for the
            // trial to report back: the trial may resolve without calling
            // `record_failure` at all (a retryable or request-shape failure does
            // not count toward the breaker), which would otherwise leave the
            // breaker disarmed indefinitely. Also makes the permit exclusive
            // against concurrent callers.
            state.open_until = Some(now + cooldown);
        }
        true
    }

    /// Records a non-recoverable failure, opening the breaker for `cooldown`
    /// once `threshold` consecutive failures accrue. A `threshold` of `0`
    /// disables the breaker.
    pub(super) fn record_failure(&self, threshold: u32, cooldown: Duration) {
        if threshold == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.consecutive = state.consecutive.saturating_add(1);
        if state.consecutive >= threshold {
            state.open_until = Some(Instant::now() + cooldown);
        }
    }

    /// Resets after any success (or a fresh prime).
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = BreakerState::default();
    }
}

#[cfg(test)]
mod breaker_tests {
    use super::Breaker;
    use crate::core::platform::Duration;

    const COOLDOWN: Duration = Duration::from_mins(1);

    #[test]
    fn opens_after_threshold_consecutive_failures() {
        let breaker = Breaker::default();
        assert!(breaker.try_acquire(3, COOLDOWN));
        breaker.record_failure(3, COOLDOWN);
        breaker.record_failure(3, COOLDOWN);
        // Below threshold: still permits.
        assert!(breaker.try_acquire(3, COOLDOWN));
        breaker.record_failure(3, COOLDOWN);
        // Threshold reached: open and cooling down — permission denied.
        assert!(!breaker.try_acquire(3, COOLDOWN));
    }

    #[test]
    fn reset_closes_an_open_breaker() {
        let breaker = Breaker::default();
        breaker.record_failure(1, COOLDOWN);
        assert!(!breaker.try_acquire(1, COOLDOWN));
        breaker.reset();
        assert!(breaker.try_acquire(1, COOLDOWN));
    }

    #[test]
    fn zero_threshold_never_opens() {
        let breaker = Breaker::default();
        for _ in 0..10 {
            breaker.record_failure(0, COOLDOWN);
        }
        assert!(breaker.try_acquire(0, COOLDOWN));
    }

    #[tokio::test]
    async fn half_opens_one_trial_after_cooldown() {
        let breaker = Breaker::default();
        breaker.record_failure(1, Duration::from_millis(10));
        assert!(!breaker.try_acquire(1, COOLDOWN));

        crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;
        // Cooldown elapsed: the gate permits one trial while retaining the
        // failure count, so a failing trial re-opens at once.
        assert!(breaker.try_acquire(1, COOLDOWN));
        breaker.record_failure(1, COOLDOWN);
        assert!(!breaker.try_acquire(1, COOLDOWN));
    }

    // The trial permit must be exclusive on its own, without waiting for the
    // trial to report back. Two callers racing through the gate the moment the
    // cooldown elapses would otherwise both mount a from-scratch exchange.
    #[tokio::test]
    async fn half_open_trial_permits_exactly_one_caller() {
        let breaker = Breaker::default();
        breaker.record_failure(1, Duration::from_millis(10));
        crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;

        assert!(breaker.try_acquire(1, COOLDOWN), "the trial is permitted");
        assert!(
            !breaker.try_acquire(1, COOLDOWN),
            "a second caller must not also get through"
        );
    }

    // Not every from-scratch failure counts toward the breaker: a retryable or
    // request-shape failure resolves the trial without any `record_failure`. The
    // breaker must still be armed afterwards rather than permitting freely.
    #[tokio::test]
    async fn trial_that_records_nothing_still_leaves_the_breaker_armed() {
        let breaker = Breaker::default();
        breaker.record_failure(1, Duration::from_millis(10));
        crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;

        assert!(breaker.try_acquire(1, Duration::from_millis(10)));
        // Trial fails transiently — nothing is recorded.
        assert!(!breaker.try_acquire(1, Duration::from_millis(10)));

        // ...and the next cooldown still yields a trial, so it is backoff and
        // not a permanent lockout.
        crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;
        assert!(breaker.try_acquire(1, Duration::from_millis(10)));
    }
}
