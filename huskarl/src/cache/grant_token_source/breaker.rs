//! The backoff breaker used by [`GrantTokenSource`](super::GrantTokenSource) to
//! bound repeated from-scratch failures.

use std::sync::{Mutex, PoisonError};

use crate::core::{
    platform::Duration,
    time::{MonotonicInstant, Timer},
};

// Runtime state for the fresh-exchange backoff policy. The owner decides which
// failures count and maps an open breaker to the public error contract.
#[derive(Default)]
pub(super) struct Breaker {
    state: Mutex<BreakerState>,
}

#[derive(Default)]
struct BreakerState {
    /// Non-recoverable from-scratch failures since the last success.
    consecutive: u32,
    /// Start and duration of the current cooldown.
    cooldown: Option<(MonotonicInstant, Duration)>,
}

impl Breaker {
    // Returns the remaining cooldown while open. After cooldown, exactly one
    // caller receives the half-open trial permit. A zero threshold disables it.
    pub(super) fn try_acquire(
        &self,
        threshold: u32,
        cooldown: Duration,
        timer: &dyn Timer,
    ) -> Result<(), Duration> {
        if threshold == 0 {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((started_at, duration)) = state.cooldown {
            let now = timer.now();
            let elapsed = now.checked_duration_since(started_at).unwrap_or_default();
            let remaining = duration.saturating_sub(elapsed);
            if !remaining.is_zero() {
                return Err(remaining);
            }
            // Re-arm as the permit is handed out rather than waiting for the
            // trial to report back: the trial may resolve without calling
            // `record_failure` at all (a retryable or request-shape failure does
            // not count toward the breaker), which would otherwise leave the
            // breaker disarmed indefinitely. Also makes the permit exclusive
            // against concurrent callers.
            state.cooldown = Some((now, cooldown));
        }
        Ok(())
    }

    // Opens the breaker after `threshold` consecutive countable failures.
    pub(super) fn record_failure(&self, threshold: u32, cooldown: Duration, timer: &dyn Timer) {
        if threshold == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.consecutive = state.consecutive.saturating_add(1);
        if state.consecutive >= threshold {
            state.cooldown = Some((timer.now(), cooldown));
        }
    }

    // Any successful acquisition or fresh prime closes the breaker.
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = BreakerState::default();
    }
}

#[cfg(test)]
mod breaker_tests {
    use super::Breaker;
    use crate::core::{platform::Duration, time::ManualTime};

    const COOLDOWN: Duration = Duration::from_mins(1);

    #[test]
    fn opens_after_threshold_consecutive_failures() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        assert!(breaker.try_acquire(3, COOLDOWN, &time).is_ok());
        breaker.record_failure(3, COOLDOWN, &time);
        breaker.record_failure(3, COOLDOWN, &time);
        // Below threshold: still permits.
        assert!(breaker.try_acquire(3, COOLDOWN, &time).is_ok());
        breaker.record_failure(3, COOLDOWN, &time);
        // Threshold reached: open and cooling down — permission denied.
        assert!(breaker.try_acquire(3, COOLDOWN, &time).is_err());
    }

    #[test]
    fn reset_closes_an_open_breaker() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        breaker.record_failure(1, COOLDOWN, &time);
        assert!(breaker.try_acquire(1, COOLDOWN, &time).is_err());
        breaker.reset();
        assert!(breaker.try_acquire(1, COOLDOWN, &time).is_ok());
    }

    #[test]
    fn zero_threshold_never_opens() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        for _ in 0..10 {
            breaker.record_failure(0, COOLDOWN, &time);
        }
        assert!(breaker.try_acquire(0, COOLDOWN, &time).is_ok());
    }

    #[test]
    fn half_opens_one_trial_after_cooldown() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        breaker.record_failure(1, Duration::from_millis(10), &time);
        assert!(breaker.try_acquire(1, COOLDOWN, &time).is_err());

        time.advance(Duration::from_millis(10)).unwrap();
        // Cooldown elapsed: the gate permits one trial while retaining the
        // failure count, so a failing trial re-opens at once.
        assert!(breaker.try_acquire(1, COOLDOWN, &time).is_ok());
        breaker.record_failure(1, COOLDOWN, &time);
        assert!(breaker.try_acquire(1, COOLDOWN, &time).is_err());
    }

    // The trial permit must be exclusive on its own, without waiting for the
    // trial to report back. Two callers racing through the gate the moment the
    // cooldown elapses would otherwise both mount a from-scratch exchange.
    #[test]
    fn half_open_trial_permits_exactly_one_caller() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        breaker.record_failure(1, Duration::from_millis(10), &time);
        time.advance(Duration::from_millis(10)).unwrap();

        assert!(
            breaker.try_acquire(1, COOLDOWN, &time).is_ok(),
            "the trial is permitted"
        );
        assert!(
            breaker.try_acquire(1, COOLDOWN, &time).is_err(),
            "a second caller must not also get through"
        );
    }

    // Not every from-scratch failure counts toward the breaker: a retryable or
    // request-shape failure resolves the trial without any `record_failure`. The
    // breaker must still be armed afterwards rather than permitting freely.
    #[test]
    fn trial_that_records_nothing_still_leaves_the_breaker_armed() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        breaker.record_failure(1, Duration::from_millis(10), &time);
        time.advance(Duration::from_millis(10)).unwrap();

        assert!(
            breaker
                .try_acquire(1, Duration::from_millis(10), &time)
                .is_ok()
        );
        // Trial fails transiently — nothing is recorded.
        assert!(
            breaker
                .try_acquire(1, Duration::from_millis(10), &time)
                .is_err()
        );

        // ...and the next cooldown still yields a trial, so it is backoff and
        // not a permanent lockout.
        time.advance(Duration::from_millis(10)).unwrap();
        assert!(
            breaker
                .try_acquire(1, Duration::from_millis(10), &time)
                .is_ok()
        );
    }
    #[test]
    fn cooldown_uses_monotonic_time_and_opens_at_exact_boundary() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        breaker.record_failure(1, COOLDOWN, &time);
        for wall in [
            jiff::Timestamp::MAX,
            jiff::Timestamp::MIN,
            jiff::Timestamp::UNIX_EPOCH,
        ] {
            time.set_wall_time(wall);
            assert_eq!(breaker.try_acquire(1, COOLDOWN, &time), Err(COOLDOWN));
        }
        time.advance_monotonic(COOLDOWN.checked_sub(Duration::from_nanos(1)).unwrap())
            .unwrap();
        assert_eq!(
            breaker.try_acquire(1, COOLDOWN, &time),
            Err(Duration::from_nanos(1))
        );
        time.advance_monotonic(Duration::from_nanos(1)).unwrap();
        assert_eq!(breaker.try_acquire(1, COOLDOWN, &time), Ok(()));
        assert_eq!(breaker.try_acquire(1, COOLDOWN, &time), Err(COOLDOWN));
    }

    #[test]
    fn cooldown_can_exceed_representable_deadline() {
        let breaker = Breaker::default();
        let time = ManualTime::default();
        time.advance(Duration::from_secs(1)).unwrap();
        breaker.record_failure(1, Duration::MAX, &time);
        time.advance_monotonic(Duration::MAX.checked_sub(Duration::from_secs(1)).unwrap())
            .unwrap();
        assert_eq!(
            breaker.try_acquire(1, Duration::MAX, &time),
            Err(Duration::from_secs(1))
        );
    }
}
