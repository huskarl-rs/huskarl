use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use bon::bon;

use crate::{
    error::{Error, RetryAdvice},
    platform::{Duration, MaybeSendBoxFuture},
    secrets::{Secret, SecretOutput},
    time::{MonotonicInstant, PlatformTimer, Timer},
};

/// A load completed after its cache generation was invalidated.
#[derive(Debug, snafu::Snafu)]
#[snafu(display("the cached secret was invalidated while it was being loaded"))]
struct InvalidatedDuringLoad;

struct CachedEntry<T: Clone> {
    output: SecretOutput<T>,
    cached_at: MonotonicInstant,
}

struct CachedSecretInner<S: Secret> {
    secret: S,
    ttl: Option<Duration>,
    timer: Arc<dyn Timer>,
    cached: ArcSwapOption<CachedEntry<S::Output>>,
    refresh_lock: tokio::sync::Mutex<()>,
    generation: Mutex<u64>,
}

/// A wrapper around a [`Secret`] that caches the value in memory.
///
/// The cached value is returned on subsequent calls until it expires (if a TTL
/// is configured) or is explicitly invalidated via [`CachedSecret::invalidate`].
/// Expiry is measured against a monotonic clock, unaffected by wall-clock
/// adjustments.
///
/// All clones of a `CachedSecret` share the same underlying cache and timer.
///
/// Reloads fail closed: once the TTL has elapsed, an access whose reload fails
/// returns the error rather than serving the stale value. Only one reload runs
/// at a time.
#[derive(Clone)]
pub struct CachedSecret<S: Secret> {
    inner: Arc<CachedSecretInner<S>>,
}

impl<S: Secret> std::fmt::Debug for CachedSecret<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedSecret").finish_non_exhaustive()
    }
}

#[bon]
impl<S: Secret> CachedSecret<S> {
    /// Creates a new `CachedSecret` wrapping the given secret.
    ///
    /// Without a TTL, the value remains cached until [`invalidate`](Self::invalidate) is called.
    #[builder]
    pub fn new(
        /// Underlying provider to load when the cache is empty or stale.
        secret: S,
        /// Reload inline on the next access once this duration has elapsed.
        ttl: Option<Duration>,
        /// Timer used to measure cache expiry.
        #[builder(
            default = Arc::<PlatformTimer>::default(),
            with = |timer: impl Timer + 'static| Arc::new(timer) as Arc<dyn Timer>
        )]
        timer: Arc<dyn Timer>,
    ) -> CachedSecret<S> {
        CachedSecret {
            inner: Arc::new(CachedSecretInner {
                secret,
                ttl,
                timer,
                cached: ArcSwapOption::empty(),
                refresh_lock: tokio::sync::Mutex::new(()),
                generation: Mutex::new(0),
            }),
        }
    }

    /// Reloads the secret from the underlying source, updates the cache, and returns the new value.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying secret source fails, or a retryable
    /// error if this load is invalidated before it can be published.
    async fn reload(&self) -> Result<SecretOutput<S::Output>, Error> {
        let generation = *self
            .inner
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let output = self.inner.secret.get_secret_value().await?;

        // Publication and invalidation use the same short synchronous lock.
        // The source fetch remains outside it, so no thread is blocked across
        // an await and the lock has no effect on the cache-hit path.
        let current_generation = self
            .inner
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current_generation != generation {
            drop(current_generation);
            drop(output);
            return Err(Error::new(RetryAdvice::RETRY, InvalidatedDuringLoad));
        }

        self.inner.cached.store(Some(Arc::new(CachedEntry {
            output: output.clone(),
            cached_at: self.inner.timer.now(),
        })));
        Ok(output)
    }

    /// Invalidates the cached value, forcing a reload on the next access via
    /// [`Secret::get_secret_value`]. An in-flight load cannot restore the
    /// invalidated value to the cache; its caller receives a retryable error
    /// instead.
    pub fn invalidate(&self) {
        let mut generation = self
            .inner
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *generation = generation.wrapping_add(1);
        self.inner.cached.store(None);
    }

    fn is_expired(&self, entry: &CachedEntry<S::Output>, ttl: Duration) -> bool {
        self.inner
            .timer
            .now()
            .checked_duration_since(entry.cached_at)
            .is_some_and(|elapsed| elapsed >= ttl)
    }

    fn is_valid(&self, entry: &CachedEntry<S::Output>) -> bool {
        self.inner
            .ttl
            .is_none_or(|ttl| !self.is_expired(entry, ttl))
    }
}

impl<S: Secret> Secret for CachedSecret<S> {
    type Output = S::Output;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        Box::pin(async move {
            // Fast path: return cached value if present and not expired.
            if let Some(entry) = self.inner.cached.load_full()
                && self.is_valid(&entry)
            {
                return Ok(entry.output.clone());
            }

            // Slow path: serialize refreshes to avoid redundant fetches.
            let _lock = self.inner.refresh_lock.lock().await;

            // Double-check after acquiring the lock.
            if let Some(entry) = self.inner.cached.load_full()
                && self.is_valid(&entry)
            {
                return Ok(entry.output.clone());
            }

            self.reload().await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rstest::{fixture, rstest};
    use tokio::sync::Notify;

    use super::*;
    use crate::{secrets::SecretString, time::ManualTime};

    /// A secret whose value increments on every fetch (`secret-0`, `secret-1`,
    /// ...), so callers can tell a cache hit from a reload.
    #[derive(Clone)]
    struct MockSecret {
        counter: Arc<AtomicUsize>,
    }

    impl Secret for MockSecret {
        type Output = SecretString;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                let count = self.counter.fetch_add(1, Ordering::SeqCst);
                Ok(SecretOutput {
                    value: SecretString::new(format!("secret-{count}")),
                    identity: None,
                })
            })
        }
    }

    /// A `CachedSecret` over a fresh counting `MockSecret`. Override the TTL with
    /// `#[with(Some(...))]`; it defaults to no TTL (cache until invalidated).
    #[fixture]
    fn cached_secret(#[default(None)] ttl: Option<Duration>) -> CachedSecret<MockSecret> {
        let mock = MockSecret {
            counter: Arc::new(AtomicUsize::new(0)),
        };
        CachedSecret::builder().secret(mock).maybe_ttl(ttl).build()
    }

    #[fixture]
    fn timed_cached_secret(
        #[default(Some(Duration::from_secs(10)))] ttl: Option<Duration>,
    ) -> (ManualTime, CachedSecret<MockSecret>) {
        let time = ManualTime::default();
        let cached = CachedSecret::builder()
            .secret(MockSecret {
                counter: Arc::new(AtomicUsize::new(0)),
            })
            .maybe_ttl(ttl)
            .timer(time.clone())
            .build();
        (time, cached)
    }

    async fn assert_value(secret: &impl Secret<Output = SecretString>, expected: &str) {
        let value = secret.get_secret_value().await.unwrap();
        assert_eq!(value.value.expose_secret(), expected);
    }

    #[rstest]
    #[tokio::test]
    async fn returns_cached_value_without_ttl(cached_secret: CachedSecret<MockSecret>) {
        assert_value(&cached_secret, "secret-0").await;

        assert_value(&cached_secret, "secret-0").await; // cache hit, not refetched
    }

    #[rstest]
    #[tokio::test]
    async fn expires_exactly_at_ttl_and_clones_share_the_timer(
        #[from(timed_cached_secret)] (time, cached): (ManualTime, CachedSecret<MockSecret>),
    ) {
        let clone = cached.clone();
        assert_value(&cached, "secret-0").await;

        time.advance(Duration::from_secs(10) - Duration::from_nanos(1))
            .unwrap();
        assert_value(&clone, "secret-0").await;
        time.advance(Duration::from_nanos(1)).unwrap();

        assert_value(&clone, "secret-1").await;
        assert_value(&cached, "secret-1").await;
        // A successful reload starts a new TTL.
        time.advance(Duration::from_secs(10)).unwrap();
        assert_value(&cached, "secret-2").await;
    }

    #[rstest]
    #[tokio::test]
    async fn wall_clock_jumps_do_not_expire_the_cache(
        #[from(timed_cached_secret)] (time, cached): (ManualTime, CachedSecret<MockSecret>),
    ) {
        cached.get_secret_value().await.unwrap();
        crate::time::test_support::assert_wall_jumps_ignored(&time, async || {
            assert_value(&cached, "secret-0").await;
        })
        .await;
        time.advance_monotonic(Duration::from_secs(10)).unwrap();
        assert_value(&cached, "secret-1").await;
    }

    #[rstest::rstest]
    #[case::no_ttl(None, "secret-0", "secret-0")]
    #[case::zero_ttl(Some(Duration::ZERO), "secret-1", "secret-2")]
    #[tokio::test]
    async fn zero_ttl_reloads_and_no_ttl_ignores_time(
        #[case] ttl: Option<Duration>,
        #[case] immediate_value: &str,
        #[case] later_value: &str,
    ) {
        let (time, cached) = timed_cached_secret(ttl);
        cached.get_secret_value().await.unwrap();
        assert_value(&cached, immediate_value).await;
        time.advance_monotonic(Duration::MAX).unwrap();
        assert_value(&cached, later_value).await;
    }

    #[tokio::test]
    async fn existing_named_builder_remains_usable() {
        let mock = MockSecret {
            counter: Arc::new(AtomicUsize::new(0)),
        };
        let builder: CachedSecretBuilder<MockSecret> = CachedSecret::builder();
        let built = builder.secret(mock).build();
        assert_value(&built, "secret-0").await;
    }

    /// Succeeds on the first fetch, fails afterwards.
    #[derive(Clone)]
    struct FailingSecret {
        counter: Arc<AtomicUsize>,
    }

    impl Secret for FailingSecret {
        type Output = SecretString;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                let count = self.counter.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    Ok(SecretOutput {
                        value: SecretString::new("initial"),
                        identity: None,
                    })
                } else {
                    Err(Error::new(
                        crate::error::RetryAdvice::RETRY,
                        "upstream failure",
                    ))
                }
            })
        }
    }

    #[tokio::test]
    async fn expired_entry_with_failing_source_fails_closed() {
        let time = Arc::new(ManualTime::default());
        let failing = FailingSecret {
            counter: Arc::new(AtomicUsize::new(0)),
        };
        let cached = CachedSecret::builder()
            .secret(failing)
            .ttl(Duration::from_millis(10))
            .timer(time.clone())
            .build();

        assert_value(&cached, "initial").await;

        time.advance(Duration::from_millis(10)).unwrap();

        // The entry is expired and the source now fails: the error propagates
        // rather than serving the stale "initial" value.
        let err = cached.get_secret_value().await.unwrap_err();
        assert!(matches!(
            err.retry_advice(),
            crate::error::RetryAdvice::Retry { .. }
        ));
        // And the next access retries the source again rather than caching
        // the failure.
        cached.get_secret_value().await.unwrap_err();
    }

    #[rstest]
    #[tokio::test]
    async fn invalidate_forces_reload(cached_secret: CachedSecret<MockSecret>) {
        assert_value(&cached_secret, "secret-0").await;

        cached_secret.invalidate();

        assert_value(&cached_secret, "secret-1").await; // reloaded after invalidation
    }

    /// Blocks its first load so invalidation can cross the fetch boundary.
    struct BlockingSecret {
        calls: AtomicUsize,
        first_load_started: Notify,
        release_first_load: Notify,
    }

    impl Secret for BlockingSecret {
        type Output = SecretString;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    self.first_load_started.notify_one();
                    self.release_first_load.notified().await;
                }

                Ok(SecretOutput {
                    value: SecretString::from(format!("secret-{call}")),
                    identity: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn invalidate_fences_out_an_in_flight_load() {
        let source = Arc::new(BlockingSecret {
            calls: AtomicUsize::new(0),
            first_load_started: Notify::new(),
            release_first_load: Notify::new(),
        });
        let cached = CachedSecret::builder().secret(source.clone()).build();

        let load = cached.get_secret_value();
        let invalidate = async {
            source.first_load_started.notified().await;
            cached.invalidate();
            source.release_first_load.notify_one();
        };

        let (result, ()) = tokio::join!(load, invalidate);
        let error = result.expect_err("the pre-invalidation value must not escape");
        assert!(matches!(error.retry_advice(), RetryAdvice::Retry { .. }));

        assert_value(&cached, "secret-1").await;

        assert_value(&cached, "secret-1").await;
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }
}
