#![allow(clippy::unwrap_used)]

use core::task::{Context, Poll};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Wake, Waker},
};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use core::prelude::v1::test;
use huskarl_core::time::*;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn timestamp(seconds: i64, nanos: i32) -> jiff::Timestamp {
    jiff::Timestamp::new(seconds, nanos).unwrap()
}

#[test]
fn timestamp_normalization_and_boundaries() {
    assert!(jiff::Timestamp::new(0, 1_000_000_000).is_err());
    let before = jiff::Timestamp::UNIX_EPOCH
        .checked_sub(Duration::from_nanos(1))
        .unwrap();
    assert_eq!(before, timestamp(-1, 999_999_999));
    assert_eq!(before, timestamp(0, -1));
    assert_eq!(
        before.checked_add(Duration::from_nanos(1)).unwrap(),
        jiff::Timestamp::UNIX_EPOCH
    );
    assert!(
        jiff::Timestamp::MAX
            .checked_add(Duration::from_nanos(1))
            .is_err()
    );
    assert!(
        jiff::Timestamp::MIN
            .checked_sub(Duration::from_nanos(1))
            .is_err()
    );
    assert!(jiff::Timestamp::MIN.checked_add(Duration::MAX).is_err());
}

#[test]
fn monotonic_arithmetic_is_checked() {
    let domain = TimerDomain::new();
    let origin = MonotonicInstant::from_duration_since_origin(domain, Duration::ZERO);
    let later = origin.checked_add(Duration::from_nanos(1)).unwrap();
    assert_eq!(origin.checked_sub(Duration::from_nanos(1)), None);
    assert_eq!(origin.checked_duration_since(later), None);
    assert_eq!(later.checked_sub(Duration::from_nanos(1)), Some(origin));
    assert_eq!(
        MonotonicInstant::from_duration_since_origin(domain, Duration::MAX)
            .checked_add(Duration::from_nanos(1)),
        None
    );
}

#[test]
fn ordinary_advancement_moves_shared_clocks_together() {
    let manual = ManualTime::new(timestamp(123, 45));
    let clock: Arc<dyn Clock> = Arc::new(manual.clone());
    let timer: Arc<dyn Timer> = Arc::new(manual.clone());
    let start = timer.now();
    manual.advance(Duration::from_millis(1500)).unwrap();
    assert_eq!(clock.now(), timestamp(124, 500_000_045));
    assert_eq!(
        timer.now().checked_duration_since(start),
        Some(Duration::from_millis(1500))
    );
}

#[test]
fn sleepers_wake_at_deadlines_and_cancellation_removes_registration() {
    let manual = ManualTime::default();
    let deadline = Timer::now(&manual)
        .checked_add(Duration::from_secs(10))
        .unwrap();
    let notifications = Arc::new(WakeCount::default());
    let waker = Waker::from(notifications.clone());
    let mut cx = Context::from_waker(&waker);
    let mut first = manual.sleep_until(deadline);
    let mut second = manual.sleep_until(deadline);
    let mut cancelled = manual.sleep_until(deadline);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    // Re-polling must not register a duplicate.
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert_eq!(manual.pending_sleeps(), 3);
    drop(cancelled);
    assert_eq!(manual.pending_sleeps(), 2);
    manual.advance(Duration::from_secs(9)).unwrap();
    assert_eq!(notifications.0.load(Ordering::SeqCst), 0);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    manual.advance(Duration::from_secs(1)).unwrap();
    assert_eq!(notifications.0.load(Ordering::SeqCst), 2);
    assert_eq!(manual.pending_sleeps(), 0);
    assert_eq!(first.as_mut().poll(&mut cx), Poll::Ready(()));
    assert_eq!(second.as_mut().poll(&mut cx), Poll::Ready(()));
}

#[test]
fn advancement_before_first_poll_and_waker_replacement() {
    let manual = ManualTime::default();
    let deadline = Timer::now(&manual)
        .checked_add(Duration::from_secs(1))
        .unwrap();
    let mut unpolled = manual.sleep_until(deadline);
    let mut polled = manual.sleep_until(deadline);
    let old = Arc::new(WakeCount::default());
    let new = Arc::new(WakeCount::default());
    let old_waker = Waker::from(old.clone());
    let new_waker = Waker::from(new.clone());
    assert!(
        polled
            .as_mut()
            .poll(&mut Context::from_waker(&old_waker))
            .is_pending()
    );
    assert!(
        polled
            .as_mut()
            .poll(&mut Context::from_waker(&new_waker))
            .is_pending()
    );
    manual.advance(Duration::from_secs(2)).unwrap();
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert_eq!(new.0.load(Ordering::SeqCst), 1);
    assert!(
        unpolled
            .as_mut()
            .poll(&mut Context::from_waker(&new_waker))
            .is_ready()
    );
    assert_eq!(manual.pending_sleeps(), 0);
}

#[test]
fn large_wall_jumps_do_not_change_monotonic_deadlines() {
    let manual = ManualTime::default();
    let deadline = Timer::now(&manual)
        .checked_add(Duration::from_secs(1))
        .unwrap();
    let mut sleep = manual.sleep_until(deadline);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(sleep.as_mut().poll(&mut cx).is_pending());
    for wall in [
        jiff::Timestamp::MAX,
        jiff::Timestamp::MIN,
        timestamp(-100, 0),
    ] {
        manual.set_wall_time(wall);
        assert_eq!(Clock::now(&manual), wall);
        assert!(sleep.as_mut().poll(&mut cx).is_pending());
    }
    manual.advance_monotonic(Duration::from_secs(1)).unwrap();
    assert!(sleep.as_mut().poll(&mut cx).is_ready());
    assert_eq!(Clock::now(&manual), timestamp(-100, 0));
}

#[test]
fn repeated_seconds_and_smearing_keep_monotonic_time_moving() {
    let initial = timestamp(1_483_228_799, 0);
    let manual = ManualTime::new(initial);
    let start = Timer::now(&manual);
    // A clock that repeats a second during a leap insertion.
    manual
        .advance_with_wall_time(Duration::from_secs(1), initial)
        .unwrap();
    assert_eq!(Clock::now(&manual), initial);
    assert_eq!(
        Timer::now(&manual).checked_duration_since(start),
        Some(Duration::from_secs(1))
    );
    // A clock that progresses at a slightly slower rate during a smear.
    let smeared = initial.checked_add(Duration::from_millis(999)).unwrap();
    manual
        .advance_with_wall_time(Duration::from_secs(1), smeared)
        .unwrap();
    assert_eq!(Clock::now(&manual), smeared);
    assert_eq!(
        Timer::now(&manual).checked_duration_since(start),
        Some(Duration::from_secs(2))
    );
    manual.advance(Duration::from_secs(1)).unwrap();
    assert_eq!(
        Clock::now(&manual),
        smeared.checked_add(Duration::from_secs(1)).unwrap()
    );
}

#[test]
fn overflow_leaves_both_clocks_and_sleepers_unchanged() {
    let manual = ManualTime::new(jiff::Timestamp::MAX);
    let start = Timer::now(&manual);
    let mut sleep = manual.sleep_until(start.checked_add(Duration::from_secs(1)).unwrap());
    assert!(
        sleep
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(manual.advance(Duration::from_nanos(1)), Err(TimeOverflow));
    assert_eq!(Timer::now(&manual), start);
    assert_eq!(Clock::now(&manual), jiff::Timestamp::MAX);
    assert_eq!(manual.pending_sleeps(), 1);
    manual.advance_monotonic(Duration::MAX).unwrap();
    assert_eq!(
        manual.advance_with_wall_time(Duration::from_nanos(1), jiff::Timestamp::MIN),
        Err(TimeOverflow)
    );
    assert_eq!(Clock::now(&manual), jiff::Timestamp::MAX);
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn native_platform_timer_works_without_tokio() {
    struct ThreadWake {
        thread: std::thread::Thread,
        notifications: AtomicUsize,
    }
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.notifications.fetch_add(1, Ordering::SeqCst);
            self.thread.unpark();
        }
    }
    let timer: PlatformTimer = Default::default();
    let independent: PlatformTimer = Default::default();
    let deadline = timer.now().checked_add(Duration::from_millis(5)).unwrap();
    let mut sleep = independent.sleep_until(deadline);
    let signal = Arc::new(ThreadWake {
        thread: std::thread::current(),
        notifications: AtomicUsize::new(0),
    });
    let waker = Waker::from(signal.clone());
    let mut cx = Context::from_waker(&waker);
    let watchdog = std::time::Instant::now();
    let mut received = 0;
    while sleep.as_mut().poll(&mut cx).is_pending() {
        // Re-poll only after a notification, so this tests the timer driver too.
        while signal.notifications.load(Ordering::SeqCst) == received {
            assert!(watchdog.elapsed() < Duration::from_secs(5));
            std::thread::park_timeout(Duration::from_millis(100));
        }
        received = signal.notifications.load(Ordering::SeqCst);
    }
    assert!(timer.now().checked_duration_since(deadline).is_some());
    let mut past = timer.sleep_until(deadline);
    assert!(past.as_mut().poll(&mut cx).is_ready());
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn browser_platform_timer_handles_small_and_cancelled_long_waits() {
    let timer: PlatformTimer = Default::default();
    let deadline = timer.now().checked_add(Duration::from_millis(2)).unwrap();
    let independent: PlatformTimer = Default::default();
    independent.sleep_until(deadline).await;
    assert!(timer.now().checked_duration_since(deadline).is_some());
    let long = timer
        .now()
        .checked_add(Duration::from_secs(u64::from(u32::MAX)))
        .unwrap();
    let mut cancelled = timer.sleep_until(long);
    assert!(
        cancelled
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(cancelled);
}

#[test]
fn monotonic_domains_are_distinct_and_arithmetic_preserves_them() {
    let first_domain = TimerDomain::new();
    let second_domain = TimerDomain::new();
    let first = MonotonicInstant::from_duration_since_origin(first_domain, Duration::from_secs(1));
    let second =
        MonotonicInstant::from_duration_since_origin(second_domain, Duration::from_secs(1));
    assert_ne!(first, second);
    let later = first.checked_add(Duration::from_secs(2)).unwrap();
    assert_eq!(later.domain(), first_domain);
    assert_eq!(first.checked_duration_since(later), None);
    assert_eq!(
        later.checked_duration_since(first),
        Some(Duration::from_secs(2))
    );
    assert_eq!(later.checked_sub(Duration::from_secs(2)), Some(first));
}

#[test]
fn manual_clones_share_a_domain_but_independent_clocks_do_not() {
    let first = ManualTime::default();
    let clone = first.clone();
    let independent = ManualTime::default();
    assert_eq!(Timer::now(&first), Timer::now(&clone));
    assert_ne!(
        Timer::now(&first).domain(),
        Timer::now(&independent).domain()
    );
    first.advance(Duration::from_secs(1)).unwrap();
    assert_eq!(Timer::now(&first), Timer::now(&clone));
    assert_ne!(Timer::now(&first), Timer::now(&independent));
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn sleep_rejects_foreign_domains_before_polling_or_registering() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let manual = ManualTime::default();
    let other_manual = ManualTime::default();
    let platform = PlatformTimer;

    for (timer, foreign) in [
        (&manual as &dyn Timer, Timer::now(&other_manual)),
        (&manual as &dyn Timer, platform.now()),
        (&platform as &dyn Timer, Timer::now(&manual)),
    ] {
        assert!(catch_unwind(AssertUnwindSafe(|| drop(timer.sleep_until(foreign)))).is_err());
    }
    assert_eq!(manual.pending_sleeps(), 0);
    assert_eq!(other_manual.pending_sleeps(), 0);
}

#[test]
fn independent_platform_timers_share_a_timeline() {
    let first: PlatformTimer = Default::default();
    let start = first.now();
    let second: PlatformTimer = Default::default();
    let later = second.now();
    assert_eq!(core::mem::size_of::<PlatformTimer>(), 0);
    assert_eq!(start.domain(), later.domain());
    assert!(later.checked_duration_since(start).is_some());
    let mut elapsed = second.sleep_until(start);
    assert!(
        elapsed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn elapsed_time_rejects_foreign_domains_instead_of_reporting_no_elapsed_time() {
    use std::panic::catch_unwind;

    let first = Timer::now(&ManualTime::default());
    let second = Timer::now(&ManualTime::default());
    assert!(catch_unwind(|| first.checked_duration_since(second)).is_err());
    assert!(catch_unwind(|| second.checked_duration_since(first)).is_err());
    first.assert_same_domain(first.domain());
    assert!(catch_unwind(|| first.assert_same_domain(second.domain())).is_err());
    let later = first.checked_add(Duration::from_secs(1)).unwrap();
    assert_eq!(first.checked_duration_since(later), None);
}

#[rstest::rstest]
#[case::minimum(jiff::Timestamp::MIN)]
#[case::pre_epoch(timestamp(0, -1))]
#[case::epoch(jiff::Timestamp::UNIX_EPOCH)]
#[case::fractional(timestamp(1_700_000_000, 123_456_789))]
#[case::maximum(jiff::Timestamp::MAX)]
#[crate::test]
fn timestamp_serde_preserves_signed_nanoseconds_and_range(#[case] value: jiff::Timestamp) {
    let json = serde_json::to_value(value).unwrap();
    assert!(json.is_string());
    assert_eq!(
        serde_json::from_value::<jiff::Timestamp>(json).unwrap(),
        value
    );
}

#[test]
fn unix_parts_preserve_pre_epoch_fractions_and_reject_invalid_input() {
    assert_eq!(
        timestamp_from_unix_parts(-1, 999_999_999).unwrap(),
        timestamp(0, -1)
    );
    assert_eq!(
        timestamp_from_unix_parts(0, 1_000_000_000),
        Err(TimeOverflow)
    );
    assert_eq!(timestamp_from_unix_parts(0, u32::MAX), Err(TimeOverflow));
    assert_eq!(timestamp_from_unix_parts(i64::MAX, 0), Err(TimeOverflow));
    assert_eq!(timestamp_from_unix_parts(i64::MIN, 0), Err(TimeOverflow));
}
