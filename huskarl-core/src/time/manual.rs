use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use std::sync::{Mutex, MutexGuard};

use futures_util::task::AtomicWaker;

use super::{Clock, Duration, MonotonicInstant, TimeOverflow, Timer, TimerDomain};
use crate::platform::MaybeSendBoxFuture;

struct Waiter {
    deadline: MonotonicInstant,
    waker: AtomicWaker,
}

struct State {
    wall: jiff::Timestamp,
    monotonic: Duration,
    waiters: Vec<Arc<Waiter>>,
}

#[derive(Clone, Copy)]
enum WallChange {
    Advance,
    Keep,
    Set(jiff::Timestamp),
}

/// A shared, frozen clock and timer advanced explicitly by tests or simulations.
///
/// Clones share time and pending waits. No executor or Tokio runtime is needed
/// to advance time; an executor must still poll futures that have been woken.
/// Wall-clock changes do not affect monotonic deadlines. There is no automatic
/// advancement or real-time start/resume mode.
///
/// Normally [`advance`](Self::advance) moves both timelines equally. Use
/// [`advance_with_wall_time`](Self::advance_with_wall_time) to model clock
/// corrections, leap-second repetition, smearing, or different clock rates.
/// A literal leap-second label is not representable by [`jiff::Timestamp`].
/// Daylight-saving transitions change local offsets, not this UTC timeline;
/// test local-time conversion separately using timestamps around the transition.
#[derive(Clone)]
pub struct ManualTime {
    domain: TimerDomain,
    state: Arc<Mutex<State>>,
}

impl core::fmt::Debug for ManualTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.lock();
        f.debug_struct("ManualTime")
            .field("domain", &self.domain)
            .field("wall", &state.wall)
            .field("monotonic", &state.monotonic)
            .field("pending_sleeps", &state.waiters.len())
            .finish_non_exhaustive()
    }
}

impl Default for ManualTime {
    fn default() -> Self {
        Self::new(jiff::Timestamp::UNIX_EPOCH)
    }
}

impl ManualTime {
    /// Start frozen at `wall`, with a monotonic reading of zero.
    #[must_use]
    pub fn new(wall: jiff::Timestamp) -> Self {
        Self {
            domain: TimerDomain::new(),
            state: Arc::new(Mutex::new(State {
                wall,
                monotonic: Duration::ZERO,
                waiters: Vec::new(),
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Set wall-clock time, including backward adjustments, without waking timers.
    pub fn set_wall_time(&self, wall: jiff::Timestamp) {
        self.lock().wall = wall;
    }

    /// Advance both timelines and wake sleepers whose deadlines have elapsed.
    ///
    /// # Errors
    /// Returns [`TimeOverflow`] without changing either timeline if either overflows.
    pub fn advance(&self, duration: Duration) -> Result<(), TimeOverflow> {
        self.advance_inner(duration, WallChange::Advance)
    }

    /// Advance only monotonic time and wake sleepers whose deadlines have elapsed.
    ///
    /// # Errors
    /// Returns [`TimeOverflow`] without changing time if the reading overflows.
    pub fn advance_monotonic(&self, duration: Duration) -> Result<(), TimeOverflow> {
        self.advance_inner(duration, WallChange::Keep)
    }

    /// Advance monotonic time and atomically set wall time to an independent value.
    ///
    /// This permits forward/backward wall-clock jumps, repeated seconds, and
    /// smearing without exposing an intermediate pair of clock readings.
    /// Separate calls to [`Clock::now`] and [`Timer::now`] are still separate reads.
    ///
    /// # Errors
    /// Returns [`TimeOverflow`] without changing either timeline if monotonic time overflows.
    pub fn advance_with_wall_time(
        &self,
        duration: Duration,
        wall: jiff::Timestamp,
    ) -> Result<(), TimeOverflow> {
        self.advance_inner(duration, WallChange::Set(wall))
    }

    fn advance_inner(
        &self,
        duration: Duration,
        wall_change: WallChange,
    ) -> Result<(), TimeOverflow> {
        let ready = {
            let mut state = self.lock();
            let monotonic = state.monotonic.checked_add(duration).ok_or(TimeOverflow)?;
            let wall = match wall_change {
                WallChange::Advance => {
                    state.wall.checked_add(duration).map_err(|_| TimeOverflow)?
                }
                WallChange::Keep => state.wall,
                WallChange::Set(wall) => wall,
            };
            state.wall = wall;
            state.monotonic = monotonic;
            let mut ready = Vec::new();
            state.waiters.retain(|waiter| {
                if waiter.deadline.duration_since_origin() <= monotonic {
                    ready.push(Arc::clone(waiter));
                    false
                } else {
                    true
                }
            });
            ready
        };
        // Wakers may run arbitrary executor code; never call them under the state lock.
        for waiter in ready {
            waiter.waker.wake();
        }
        Ok(())
    }

    /// Number of polled, pending sleep registrations (useful for test coordination).
    #[must_use]
    pub fn pending_sleeps(&self) -> usize {
        self.lock().waiters.len()
    }
}

impl Clock for ManualTime {
    fn now(&self) -> jiff::Timestamp {
        self.lock().wall
    }
}

impl Timer for ManualTime {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_duration_since_origin(self.domain, self.lock().monotonic)
    }

    fn sleep_until(&self, deadline: MonotonicInstant) -> MaybeSendBoxFuture<'_, ()> {
        deadline.assert_same_domain(self.domain);
        Box::pin(ManualSleep {
            time: self.clone(),
            waiter: Arc::new(Waiter {
                deadline,
                waker: AtomicWaker::new(),
            }),
            registered: false,
        })
    }
}

struct ManualSleep {
    time: ManualTime,
    waiter: Arc<Waiter>,
    registered: bool,
}

impl Future for ManualSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        this.waiter.waker.register(cx.waker());
        let mut state = this.time.lock();
        if state.monotonic >= this.waiter.deadline.duration_since_origin() {
            return Poll::Ready(());
        }
        if !this.registered {
            state.waiters.push(Arc::clone(&this.waiter));
            this.registered = true;
        }
        Poll::Pending
    }
}

impl Drop for ManualSleep {
    fn drop(&mut self) {
        if self.registered {
            self.time
                .lock()
                .waiters
                .retain(|waiter| !Arc::ptr_eq(waiter, &self.waiter));
        }
    }
}
