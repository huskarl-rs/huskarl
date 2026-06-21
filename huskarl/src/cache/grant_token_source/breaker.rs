//! Backoff breaker bounding a doomed from-scratch grant-exchange loop.

use std::sync::{Mutex, PoisonError};

use crate::core::platform::{Duration, SystemTime};

/// Backoff breaker bounding a doomed from-scratch acquisition loop.
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
    open_until: Option<SystemTime>,
}

impl Breaker {
    /// Tries to acquire permission for one from-scratch attempt.
    ///
    /// Returns `true` if permitted. While cooling down it returns `false`; once
    /// the cooldown elapses it permits a single trial (half-open) — clearing
    /// `open_until` while retaining the failure count, so consuming that permit
    /// on a trial that fails non-recoverably re-opens the breaker immediately. A
    /// `threshold` of `0` disables the breaker (always permits).
    pub(super) fn try_acquire(&self, threshold: u32) -> bool {
        if threshold == 0 {
            return true;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(open_until) = state.open_until {
            if SystemTime::now() < open_until {
                return false;
            }
            // Cooldown elapsed: permit one trial. The failure count is retained,
            // so a failing trial re-opens the breaker immediately.
            state.open_until = None;
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
            state.open_until = Some(SystemTime::now() + cooldown);
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
        assert!(breaker.try_acquire(3));
        breaker.record_failure(3, COOLDOWN);
        breaker.record_failure(3, COOLDOWN);
        // Below threshold: still permits.
        assert!(breaker.try_acquire(3));
        breaker.record_failure(3, COOLDOWN);
        // Threshold reached: open and cooling down — permission denied.
        assert!(!breaker.try_acquire(3));
    }

    #[test]
    fn reset_closes_an_open_breaker() {
        let breaker = Breaker::default();
        breaker.record_failure(1, COOLDOWN);
        assert!(!breaker.try_acquire(1));
        breaker.reset();
        assert!(breaker.try_acquire(1));
    }

    #[test]
    fn zero_threshold_never_opens() {
        let breaker = Breaker::default();
        for _ in 0..10 {
            breaker.record_failure(0, COOLDOWN);
        }
        assert!(breaker.try_acquire(0));
    }

    #[tokio::test]
    async fn half_opens_one_trial_after_cooldown() {
        let breaker = Breaker::default();
        breaker.record_failure(1, Duration::from_millis(10));
        assert!(!breaker.try_acquire(1));

        crate::core::platform::sleep(std::time::Duration::from_millis(25)).await;
        // Cooldown elapsed: the gate permits one trial while retaining the
        // failure count, so a failing trial re-opens at once.
        assert!(breaker.try_acquire(1));
        breaker.record_failure(1, Duration::from_millis(10));
        assert!(!breaker.try_acquire(1));
    }
}
