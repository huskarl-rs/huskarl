use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bon::bon;

use crate::{
    error::Error,
    platform::{Duration, Instant, MaybeSendBoxFuture},
    secrets::{Secret, SecretOutput},
};

struct CachedEntry<T: Clone> {
    output: SecretOutput<T>,
    cached_at: Instant,
}

struct CachedSecretInner<S: Secret> {
    secret: S,
    ttl: Option<Duration>,
    cached: ArcSwapOption<CachedEntry<S::Output>>,
    refresh_lock: tokio::sync::Mutex<()>,
}

/// A wrapper around a [`Secret`] that caches the value in memory.
///
/// The cached value is returned on subsequent calls until it expires (if a TTL
/// is configured) or is explicitly invalidated via [`CachedSecret::invalidate`].
/// Expiry is measured against a monotonic clock, unaffected by wall-clock
/// adjustments.
///
/// All clones of a `CachedSecret` share the same underlying cache.
///
/// Reloads fail closed: once the TTL has elapsed, an access whose reload fails
/// returns the error rather than serving the stale value. Reloads are
/// serialized by an internal lock, so concurrent waiters trigger one reload.
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
    /// Without a TTL, the value is cached indefinitely until [`invalidate`](Self::invalidate) is called.
    #[builder]
    pub fn new(
        secret: S,
        /// The cached value is reloaded inline on the next access after the TTL elapses.
        ttl: Option<Duration>,
    ) -> CachedSecret<S> {
        CachedSecret {
            inner: Arc::new(CachedSecretInner {
                secret,
                ttl,
                cached: ArcSwapOption::empty(),
                refresh_lock: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Reloads the secret from the underlying source, updates the cache, and returns the new value.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying secret source fails.
    async fn reload(&self) -> Result<SecretOutput<S::Output>, Error> {
        let output = self.inner.secret.get_secret_value().await?;
        self.inner.cached.store(Some(Arc::new(CachedEntry {
            output: output.clone(),
            cached_at: Instant::now(),
        })));
        Ok(output)
    }

    /// Invalidates the cached value, forcing a reload on the next call to [`Secret::get_secret_value`].
    pub fn invalidate(&self) {
        self.inner.cached.store(None);
    }

    fn is_expired(entry: &CachedEntry<S::Output>, ttl: Duration) -> bool {
        Instant::now()
            .checked_duration_since(entry.cached_at)
            .is_some_and(|elapsed| elapsed >= ttl)
    }

    fn is_valid(entry: &CachedEntry<S::Output>, ttl: Option<Duration>) -> bool {
        ttl.is_none_or(|ttl| !Self::is_expired(entry, ttl))
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
                && Self::is_valid(&entry, self.inner.ttl)
            {
                return Ok(entry.output.clone());
            }

            // Slow path: serialize refreshes to avoid redundant fetches.
            let _lock = self.inner.refresh_lock.lock().await;

            // Double-check after acquiring the lock.
            if let Some(entry) = self.inner.cached.load_full()
                && Self::is_valid(&entry, self.inner.ttl)
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

    use super::*;
    use crate::secrets::SecretString;

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

    #[rstest]
    #[tokio::test]
    async fn returns_cached_value_without_ttl(cached_secret: CachedSecret<MockSecret>) {
        let val1 = cached_secret.get_secret_value().await.unwrap();
        assert_eq!(val1.value.expose_secret(), "secret-0");

        let val2 = cached_secret.get_secret_value().await.unwrap();
        assert_eq!(val2.value.expose_secret(), "secret-0"); // cache hit, not refetched
    }

    #[rstest]
    #[tokio::test]
    async fn reloads_after_ttl_expires(
        #[with(Some(Duration::from_millis(10)))] cached_secret: CachedSecret<MockSecret>,
    ) {
        let val1 = cached_secret.get_secret_value().await.unwrap();
        assert_eq!(val1.value.expose_secret(), "secret-0");

        tokio::time::sleep(Duration::from_millis(20)).await;

        let val2 = cached_secret.get_secret_value().await.unwrap();
        assert_eq!(val2.value.expose_secret(), "secret-1"); // TTL elapsed, reloaded
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
        let failing = FailingSecret {
            counter: Arc::new(AtomicUsize::new(0)),
        };
        let cached = CachedSecret::builder()
            .secret(failing)
            .ttl(Duration::from_millis(10))
            .build();

        let val = cached.get_secret_value().await.unwrap();
        assert_eq!(val.value.expose_secret(), "initial");

        tokio::time::sleep(Duration::from_millis(20)).await;

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
        let val1 = cached_secret.get_secret_value().await.unwrap();
        assert_eq!(val1.value.expose_secret(), "secret-0");

        cached_secret.invalidate();

        let val2 = cached_secret.get_secret_value().await.unwrap();
        assert_eq!(val2.value.expose_secret(), "secret-1"); // reloaded after invalidation
    }
}
