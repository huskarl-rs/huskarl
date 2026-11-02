//! Shared pacing and transient-failure policy for polling grants.
use crate::core::{
    RetryAdvice,
    platform::{Duration, MaybeSendFuture, MaybeSendSync, SystemTime},
    time::{Clock, Timer, system_time_from_timestamp_saturating},
};

/// Default minimum polling interval in seconds.
pub const DEFAULT_MIN_POLL_INTERVAL_SECS: u32 = 5;
/// Default number of consecutive retryable failures tolerated.
pub const DEFAULT_MAX_TRANSIENT_POLL_FAILURES: u32 = 5;

pub(crate) trait PollingState {
    fn interval_secs(&self) -> u32;
    fn expires_at(&self) -> SystemTime;
}

/// A polling operation with an explicit native Send guarantee on its future.
/// Avoid lending async closures here: their captured borrows can prevent callers
/// in other crates from proving that the automatic polling future is Send.
pub(crate) trait PollingGrant: MaybeSendSync {
    type State: PollingState;
    type Output;
    type Error;

    fn poll_once(
        &self,
        state: &mut Self::State,
        resource: Option<Vec<String>>,
    ) -> impl MaybeSendFuture<Output = Result<Option<Self::Output>, Self::Error>>;

    fn retry_advice(error: &Self::Error) -> RetryAdvice;
    fn expired() -> Self::Error;
}

pub(crate) fn slow_down(interval: &mut u32, floor: u32) {
    *interval = (*interval).max(floor).saturating_add(5);
}

pub(crate) struct PollingDriver<'a> {
    pub timer: &'a dyn Timer,
    pub clock: &'a dyn Clock,
    pub min_interval_secs: u32,
    pub max_transient_failures: u32,
}

impl PollingDriver<'_> {
    pub async fn run<G: PollingGrant>(
        &self,
        grant: &G,
        state: &mut G::State,
        resource: Option<Vec<String>>,
    ) -> Result<G::Output, G::Error> {
        let mut consecutive_failures = 0_u32;
        let mut retry_after = None;
        loop {
            // Restored state can contain zero. Enforce the configured floor to
            // avoid a zero-delay loop hammering the token endpoint.
            let interval =
                Duration::from_secs(state.interval_secs().max(self.min_interval_secs).into());
            let mut delay = interval.max(retry_after.take().unwrap_or_default());
            let expiry = state.expires_at();
            let remaining = expiry
                .duration_since(system_time_from_timestamp_saturating(self.clock.now()))
                .map_err(|_| G::expired())?;
            if remaining.is_zero() {
                return Err(G::expired());
            }
            delay = delay.min(remaining);
            let Some(deadline) = self.timer.now().checked_add(delay) else {
                // No reachable deadline remains on this timer's timeline.
                return Err(G::expired());
            };
            self.timer.sleep_until(deadline).await;
            if system_time_from_timestamp_saturating(self.clock.now()) >= expiry {
                return Err(G::expired());
            }
            let err = match grant.poll_once(state, resource.clone()).await {
                Ok(Some(output)) => return Ok(output),
                Ok(None) => {
                    // The server answered, so whatever was wrong is over.
                    consecutive_failures = 0;
                    continue;
                }
                Err(err) => err,
            };
            let RetryAdvice::Retry { after } = G::retry_advice(&err) else {
                return Err(err);
            };
            consecutive_failures += 1;
            if consecutive_failures > self.max_transient_failures {
                return Err(err);
            }
            retry_after = after;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use futures_util::FutureExt as _;

    use super::*;
    use crate::core::time::ManualTime;

    struct State {
        interval: u32,
        expiry: SystemTime,
    }

    impl PollingState for State {
        fn interval_secs(&self) -> u32 {
            self.interval
        }

        fn expires_at(&self) -> SystemTime {
            self.expiry
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Failure {
        Transient(Option<Duration>),
        Terminal,
        Expired,
    }

    struct Grant {
        responses: Mutex<VecDeque<Result<Option<()>, Failure>>>,
        resources: Mutex<Vec<Option<Vec<String>>>>,
    }

    impl PollingGrant for Grant {
        type State = State;
        type Output = ();
        type Error = Failure;

        fn poll_once(
            &self,
            _: &mut State,
            resource: Option<Vec<String>>,
        ) -> impl MaybeSendFuture<Output = Result<Option<()>, Failure>> {
            self.resources.lock().unwrap().push(resource);
            std::future::ready(
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected poll"),
            )
        }

        fn retry_advice(error: &Failure) -> RetryAdvice {
            match error {
                Failure::Transient(after) => RetryAdvice::Retry { after: *after },
                Failure::Terminal | Failure::Expired => RetryAdvice::No,
            }
        }

        fn expired() -> Failure {
            Failure::Expired
        }
    }

    fn state(time: &ManualTime, interval: u32) -> State {
        State {
            interval,
            expiry: system_time_from_timestamp_saturating(Clock::now(time))
                + Duration::from_secs(300),
        }
    }

    #[rstest::rstest]
    #[case::restored_zero(0, 5, 2, 5)]
    #[case::server_interval(10, 5, 2, 10)]
    #[case::configured_floor(5, 20, 2, 20)]
    #[case::retry_after(5, 5, 20, 20)]
    #[test]
    fn driver_enforces_cadence_and_retry_after(
        #[case] interval: u32,
        #[case] floor: u32,
        #[case] retry_after: u64,
        #[case] retry_delay: u64,
    ) {
        let time = ManualTime::default();
        let driver = PollingDriver {
            timer: &time,
            clock: &time,
            min_interval_secs: floor,
            max_transient_failures: 1,
        };
        let grant = Grant {
            responses: Mutex::new(VecDeque::from([
                Err(Failure::Transient(Some(Duration::from_secs(retry_after)))),
                Ok(Some(())),
            ])),
            resources: Mutex::default(),
        };
        let mut state = state(&time, interval);
        let resource = Some(vec!["https://resource.example".into()]);
        let mut polling = std::pin::pin!(driver.run(&grant, &mut state, resource.clone()));
        for delay in [u64::from(interval.max(floor)), retry_delay] {
            assert!(polling.as_mut().now_or_never().is_none());
            time.advance(Duration::from_secs(delay - 1)).unwrap();
            assert!(polling.as_mut().now_or_never().is_none());
            time.advance(Duration::from_secs(1)).unwrap();
        }
        assert_eq!(polling.as_mut().now_or_never(), Some(Ok(())));
        assert_eq!(
            *grant.resources.lock().unwrap(),
            [resource.clone(), resource]
        );
    }

    #[rstest::rstest]
    #[case::zero_budget(0, vec![Err(Failure::Transient(None))], Err(Failure::Transient(None)))]
    #[case::exhausted(1, vec![Err(Failure::Transient(None)), Err(Failure::Transient(None))], Err(Failure::Transient(None)))]
    #[case::pending_resets_budget(1, vec![Err(Failure::Transient(None)), Ok(None), Err(Failure::Transient(None)), Ok(Some(()))], Ok(()))]
    #[case::terminal(5, vec![Err(Failure::Terminal)], Err(Failure::Terminal))]
    #[test]
    fn driver_bounds_consecutive_failures(
        #[case] budget: u32,
        #[case] responses: Vec<Result<Option<()>, Failure>>,
        #[case] expected: Result<(), Failure>,
    ) {
        let time = ManualTime::default();
        let driver = PollingDriver {
            timer: &time,
            clock: &time,
            min_interval_secs: 5,
            max_transient_failures: budget,
        };
        let calls = responses.len();
        let grant = Grant {
            responses: Mutex::new(responses.into()),
            resources: Mutex::default(),
        };
        let mut state = state(&time, 5);
        let mut polling = std::pin::pin!(driver.run(&grant, &mut state, None));
        for _ in 0..calls {
            assert!(polling.as_mut().now_or_never().is_none());
            time.advance(Duration::from_secs(5)).unwrap();
        }
        assert_eq!(polling.as_mut().now_or_never(), Some(expected));
        assert_eq!(grant.resources.lock().unwrap().len(), calls);
    }
}
