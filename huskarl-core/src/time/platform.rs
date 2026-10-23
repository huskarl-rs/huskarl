use super::{Clock, timestamp_from_system_time_saturating};
use crate::platform::SystemTime;

/// The platform wall clock: `std::time` natively and on WASI, `web_time` in browsers.
///
/// Readings outside [`jiff::Timestamp`]'s range saturate at its nearest boundary.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformClock;

impl Clock for PlatformClock {
    fn now(&self) -> jiff::Timestamp {
        timestamp_from_system_time_saturating(SystemTime::now())
    }
}

mod timer {
    use alloc::boxed::Box;

    use super::super::{Duration, MonotonicInstant, Timer, TimerDomain};
    use crate::platform::{Instant, MaybeSendBoxFuture};

    /// Monotonic timer using the backend selected for the current target.
    ///
    /// Native waits use `futures-timer`'s shared background driver; browser waits
    /// use host timeouts via `gloo-timers`. WASI 0.1/0.2 retain the existing
    /// Tokio sleep backend. Native and browser waits do not require Tokio.
    /// Instances share an origin and domain within the process (or Wasm instance).
    #[derive(Debug, Default, Clone, Copy)]
    pub struct PlatformTimer;

    static TIMELINE: std::sync::LazyLock<(Instant, TimerDomain)> =
        std::sync::LazyLock::new(|| (Instant::now(), TimerDomain::new()));

    impl Timer for PlatformTimer {
        fn now(&self) -> MonotonicInstant {
            let (origin, domain) = &*TIMELINE;
            MonotonicInstant::from_duration_since_origin(*domain, origin.elapsed())
        }

        fn sleep_until(&self, deadline: MonotonicInstant) -> MaybeSendBoxFuture<'_, ()> {
            deadline.assert_same_domain(TIMELINE.1);
            Box::pin(async move {
                loop {
                    let Some(remaining) = deadline.checked_duration_since(self.now()) else {
                        return;
                    };
                    if remaining.is_zero() {
                        return;
                    }
                    // Bound both host timeout arguments and underlying Instant arithmetic.
                    let chunk = remaining.min(Duration::from_hours(24));
                    #[cfg(not(target_family = "wasm"))]
                    futures_timer::Delay::new(chunk).await;
                    #[cfg(all(
                        target_family = "wasm",
                        not(all(target_arch = "wasm32", target_os = "unknown"))
                    ))]
                    crate::platform::sleep(chunk).await;
                    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                    {
                        // Round up: sub-millisecond waits must not repeatedly schedule zero.
                        let millis =
                            chunk.as_millis() + u128::from(chunk.subsec_nanos() % 1_000_000 != 0);
                        let millis = u32::try_from(millis).unwrap_or(86_400_000);
                        gloo_timers::future::TimeoutFuture::new(millis).await;
                    }
                }
            })
        }
    }
}

pub use timer::PlatformTimer;
