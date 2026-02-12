use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bon::bon;

use crate::{
    platform::{Duration, SystemTime},
    secrets::{Secret, SecretOutput},
};

struct CachedEntry<T: Clone> {
    output: SecretOutput<T>,
    cached_at: SystemTime,
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
///
/// All clones of a `CachedSecret` share the same underlying cache.
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
    async fn reload(&self) -> Result<SecretOutput<S::Output>, S::Error> {
        let output = self.inner.secret.get_secret_value().await?;
        self.inner.cached.store(Some(Arc::new(CachedEntry {
            output: output.clone(),
            cached_at: SystemTime::now(),
        })));
        Ok(output)
    }

    /// Invalidates the cached value, forcing a reload on the next call to [`Secret::get_secret_value`].
    pub fn invalidate(&self) {
        self.inner.cached.store(None);
    }

    fn is_expired(entry: &CachedEntry<S::Output>, ttl: Duration) -> bool {
        SystemTime::now() >= entry.cached_at + ttl
    }

    fn is_valid(entry: &CachedEntry<S::Output>, ttl: Option<Duration>) -> bool {
        ttl.is_none_or(|ttl| !Self::is_expired(entry, ttl))
    }
}

impl<S: Secret> Secret for CachedSecret<S> {
    type Error = S::Error;
    type Output = S::Output;

    async fn get_secret_value(&self) -> Result<SecretOutput<Self::Output>, Self::Error> {
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
    }
}
