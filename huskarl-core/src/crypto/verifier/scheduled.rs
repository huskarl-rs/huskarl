use std::pin::Pin;

use crate::{
    crypto::{
        KeyMatchStrength,
        refreshable::ScheduledRefreshable,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    error::Error,
    platform::{Duration, MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsVerifier`] that bounds the age of its keyset to a TTL by reloading on
/// the read path — so a key *removed* upstream is dropped within the TTL even
/// though it never fails to verify (you still hold it). The TTL bounds how long a
/// removed key lingers; key *additions* are handled by the miss-triggered
/// [`RetryingVerifier`](super::RetryingVerifier) layered on top.
///
/// On each [`verify`](JwsVerifier::verify) past the TTL (and if the
/// rate-limit/backoff policy allows), the first caller to notice reloads
/// single-flight — non-blocking for concurrent callers, who keep serving the
/// current keyset. [`try_refresh`](JwsVerifier::try_refresh) drives the same
/// reload for the miss-triggered path, under the same policy.
///
/// For the common JWKS-backed stack (this layer +
/// [`RetryingVerifier`](super::RetryingVerifier) +
/// [`MultiKeyVerifier`](super::MultiKeyVerifier)) use
/// [`JwksSource`](crate::jwk::JwksSource) rather than composing by hand; its `ttl`
/// is this layer's TTL. See [composing crypto
/// strategies](crate::_docs::explanation::crypto_strategies) for the full stack.
///
/// # Warm start from a persisted cache
///
/// The factory's `Ok` value is served immediately as the current keyset, so a
/// factory that falls back to a *trusted local cache* comes up **warm** — able to
/// verify at once — even when the authorization server is unreachable at boot,
/// then picks up live keys on the next TTL refresh. This is distinct from
/// [`JwksStartup::SeedEmpty`](crate::jwk::JwksStartup::SeedEmpty), which comes up
/// *cold* and returns [`KeysUnavailable`](VerifyError::KeysUnavailable) until a
/// live fetch lands. Persist each successful fetch so the cache tracks key
/// rotations rather than a stale bake-in; if there is no live fetch *and* no
/// cache (a first-ever offline boot), the build still fails — you genuinely have
/// no keys.
///
/// ```rust,no_run
/// # use std::pin::Pin;
/// # use huskarl_core::{
/// #     crypto::verifier::{MultiKeyVerifier, ScheduledRefreshVerifier},
/// #     error::Error,
/// #     platform::MaybeSendFuture,
/// # };
/// # async fn fetch_live_keys() -> Result<MultiKeyVerifier, Error> { unimplemented!() }
/// # fn save_cached_keys(_keys: &MultiKeyVerifier) {}
/// # fn load_cached_keys() -> Result<MultiKeyVerifier, Error> { unimplemented!() }
/// # async fn example() -> Result<(), Error> {
/// let verifier = ScheduledRefreshVerifier::builder()
///     .factory(|| {
///         Box::pin(async {
///             match fetch_live_keys().await {
///                 // Persist every good fetch so a later cold boot loads the
///                 // freshest keyset the process ever saw, not a stale bake-in.
///                 Ok(keys) => {
///                     save_cached_keys(&keys);
///                     Ok(keys)
///                 }
///                 // Offline: serve the last good keyset so the build is warm.
///                 Err(_) => load_cached_keys(),
///             }
///         }) as Pin<Box<dyn MaybeSendFuture<Output = Result<MultiKeyVerifier, Error>>>>
///     })
///     .build()
///     .await?;
/// # let _ = verifier;
/// # Ok(())
/// # }
/// ```
pub struct ScheduledRefreshVerifier<V> {
    inner: ScheduledRefreshable<V>,
}

impl<V: std::fmt::Debug> std::fmt::Debug for ScheduledRefreshVerifier<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledRefreshVerifier")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

#[bon::bon]
impl<V: JwsVerifier + 'static> ScheduledRefreshVerifier<V> {
    /// Creates a new [`ScheduledRefreshVerifier`] using the given factory and policy parameters.
    ///
    /// The factory is called immediately to produce the initial verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>>
        + MaybeSendSync
        + 'static,
        /// The time-to-live for the cached verifier.
        #[builder(default = Duration::from_hours(1))]
        ttl: Duration,
        /// The backoff duration after a failed refresh.
        #[builder(default = Duration::from_secs(30))]
        failure_backoff: Duration,
        /// Minimum time between any two refresh attempts, regardless of outcome.
        /// Acts as a hard ceiling on refresh frequency for abuse prevention.
        #[builder(default = Duration::from_mins(1))]
        min_refresh_interval: Duration,
        /// Backoff floor while cold (no keyset has loaded), escalating up to
        /// `failure_backoff`.
        #[builder(default = Duration::from_millis(250))]
        cold_backoff: Duration,
        /// Opt-in placeholder verifier used if the initial fetch fails, so the
        /// stack comes up cold and self-heals instead of failing construction.
        /// `None` (the default) keeps a failed initial fetch fatal.
        fallback: Option<V>,
    ) -> Result<Self, Error> {
        let inner = ScheduledRefreshable::builder()
            .factory(factory)
            .ttl(ttl)
            .failure_backoff(failure_backoff)
            .min_refresh_interval(min_refresh_interval)
            .cold_backoff(cold_backoff)
            .maybe_fallback(fallback)
            .build()
            .await?;
        // Coming up cold (initial fetch failed, placeholder seeded) is no longer a
        // construction error, so surface it here — the only startup-time signal
        // that the stack is degraded until it self-heals.
        #[cfg(feature = "metrics")]
        if inner.is_cold() {
            ::metrics::counter!("huskarl.jws.cold_start").increment(1);
        }
        Ok(Self { inner })
    }
}

impl<V: JwsVerifier + 'static> JwsVerifier for ScheduledRefreshVerifier<V> {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.load().key_match(key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async move {
            // Cold: no keyset has ever loaded (the initial fetch failed and an
            // empty placeholder was seeded). Block on a single-flight reload so a
            // burst of first requests adopts one shared fetch rather than each
            // eating its own, then distinguish "keys never loaded" (infra) from an
            // unknown-`kid` miss (bad token).
            if self.inner.is_cold() {
                self.inner.try_refresh_on_miss().await;
                if self.inner.is_cold() {
                    return Err(VerifyError::KeysUnavailable);
                }
            } else {
                // Bound staleness on the read path: if the keyset has outlived its
                // TTL, the first verify to notice reloads it (single-flight,
                // non-blocking for others) before verifying. This is what drops a
                // retired key even when no token ever fails to verify.
                self.inner.poll_refresh_ahead().await;
            }
            self.inner
                .load_full()
                .verify(input, signature, key_match)
                .await
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        // Miss path: **not** TTL-gated. A miss driven by `RetryingVerifier` (or the
        // `MultiKeyVerifier` fan-out) must be able to reload within the TTL to pick
        // up a newly-added key — that is the whole point of the retry layer.
        Box::pin(self.inner.try_refresh_on_miss())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// A verifier that accepts or rejects based on a fixed flag, standing in for
    /// "the keyset still holds this key" vs "the key has been retired".
    #[derive(Debug)]
    struct FlagVerifier {
        accept: bool,
    }

    impl JwsVerifier for FlagVerifier {
        fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            self.accept.then_some(KeyMatchStrength::ByAlgorithm)
        }

        fn verify<'a>(
            &'a self,
            _input: &'a [u8],
            _signature: &'a [u8],
            _key_match: &'a KeyMatch<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
            let accept = self.accept;
            Box::pin(async move {
                if accept {
                    Ok(())
                } else {
                    Err(VerifyError::SignatureMismatch)
                }
            })
        }
    }

    /// A factory whose generation 0 accepts (holds the key) and every later
    /// generation rejects (the key has been retired upstream). Returns a shared
    /// build counter so tests can assert how many reloads happened.
    #[allow(clippy::type_complexity)]
    fn retiring_factory() -> (
        Arc<AtomicUsize>,
        impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<FlagVerifier, Error>>>>
        + MaybeSendSync
        + 'static,
    ) {
        let builds = Arc::new(AtomicUsize::new(0));
        let counter = builds.clone();
        let factory = move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(FlagVerifier { accept: n == 0 }) })
                as Pin<Box<dyn MaybeSendFuture<Output = Result<FlagVerifier, Error>>>>
        };
        (builds, factory)
    }

    fn km() -> KeyMatch<'static> {
        KeyMatch {
            alg: "ES256",
            kid: None,
        }
    }

    #[tokio::test]
    async fn stale_keyset_reloads_before_verify_and_retires_the_key() {
        // gen-0 would accept, but the keyset is past its TTL, so the read-path
        // reload swaps in gen-1 (key retired) *before* verifying — no verification
        // failure was ever needed to trigger it.
        let (builds, factory) = retiring_factory();
        let verifier = ScheduledRefreshVerifier::builder()
            .factory(factory)
            .ttl(Duration::ZERO)
            .min_refresh_interval(Duration::ZERO)
            .build()
            .await
            .unwrap();

        verifier
            .verify(b"input", b"sig", &km())
            .await
            .expect_err("the retired key is dropped by the staleness reload");
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "initial build + one reload"
        );
    }

    #[tokio::test]
    async fn fresh_keyset_is_not_reloaded() {
        // Within the TTL, verify is a pure read — no reload, gen-0 still accepts.
        let (builds, factory) = retiring_factory();
        let verifier = ScheduledRefreshVerifier::builder()
            .factory(factory)
            .ttl(Duration::from_hours(1))
            .build()
            .await
            .unwrap();

        verifier
            .verify(b"input", b"sig", &km())
            .await
            .expect("still on gen-0, which accepts");
        assert_eq!(builds.load(Ordering::SeqCst), 1, "no reload while fresh");
    }

    #[tokio::test]
    async fn read_path_reload_is_rate_limited() {
        // Stale on every read, but `min_refresh_interval` caps how often the
        // read-path reload actually fetches — one reload, then blocked.
        let (builds, factory) = retiring_factory();
        let verifier = ScheduledRefreshVerifier::builder()
            .factory(factory)
            .ttl(Duration::ZERO)
            .min_refresh_interval(Duration::from_hours(1))
            .build()
            .await
            .unwrap();

        let _ = verifier.verify(b"input", b"sig", &km()).await;
        let _ = verifier.verify(b"input", b"sig", &km()).await;
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "initial build + one reload; the second read is rate-limited"
        );
    }

    /// Stands in for a keyset that either holds the token's key (accept) or does
    /// not (a `NoMatchingKey` *miss*) — unlike [`FlagVerifier`], whose rejection is
    /// a signature mismatch. Used to drive the miss-triggered additions path.
    #[derive(Debug)]
    struct MissVerifier {
        present: bool,
    }

    impl JwsVerifier for MissVerifier {
        fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            self.present.then_some(KeyMatchStrength::ByAlgorithm)
        }

        fn verify<'a>(
            &'a self,
            _input: &'a [u8],
            _signature: &'a [u8],
            _key_match: &'a KeyMatch<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
            let present = self.present;
            Box::pin(async move {
                if present {
                    Ok(())
                } else {
                    Err(VerifyError::NoMatchingKey)
                }
            })
        }
    }

    /// A factory whose generation 0 is missing the key (a miss) and every later
    /// generation holds it — the inverse of [`retiring_factory`], modelling a key
    /// *added* upstream.
    #[allow(clippy::type_complexity)]
    fn adding_factory() -> (
        Arc<AtomicUsize>,
        impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<MissVerifier, Error>>>>
        + MaybeSendSync
        + 'static,
    ) {
        let builds = Arc::new(AtomicUsize::new(0));
        let counter = builds.clone();
        let factory = move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(MissVerifier { present: n >= 1 }) })
                as Pin<Box<dyn MaybeSendFuture<Output = Result<MissVerifier, Error>>>>
        };
        (builds, factory)
    }

    /// The additions fast path, end-to-end: `RetryingVerifier` over a *real*
    /// `ScheduledRefreshVerifier`. The token's key is absent at gen-0 (a miss) and
    /// present from gen-1, and the keyset is nowhere near its TTL. The miss must
    /// still drive a reload (gated only by `min_refresh_interval`) and the retry
    /// must then accept — rather than waiting out the hour-long TTL.
    ///
    /// This is the composition the previous test suite never exercised, which let
    /// a TTL-gated miss path go unnoticed.
    #[tokio::test]
    async fn retrying_over_scheduled_picks_up_an_added_key_within_ttl() {
        use crate::crypto::verifier::RetryingVerifier;

        let (builds, factory) = adding_factory();
        let scheduled = ScheduledRefreshVerifier::builder()
            .factory(factory)
            .ttl(Duration::from_hours(1)) // nowhere near stale
            .min_refresh_interval(Duration::ZERO) // the miss refresh is permitted
            .build()
            .await
            .unwrap();
        let verifier = RetryingVerifier::new(scheduled);

        verifier
            .verify(b"input", b"sig", &km())
            .await
            .expect("the miss reloads within the TTL and the added key verifies");
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "initial build + one miss-driven reload"
        );
    }

    /// An always-failing factory: the upstream is down at boot and stays down.
    #[allow(clippy::type_complexity)]
    fn always_down()
    -> impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<MissVerifier, Error>>>>
    + MaybeSendSync
    + 'static {
        || {
            Box::pin(async {
                Err(Error::new(
                    crate::error::ErrorKind::Transport { retryable: true },
                    "down",
                ))
            })
        }
    }

    /// A seeded-empty cold start reports [`VerifyError::KeysUnavailable`] — not a
    /// bare miss — while the upstream stays unreachable, so the failure reads as
    /// infrastructure rather than a bad token.
    #[tokio::test]
    async fn cold_verify_reports_keys_unavailable_while_upstream_down() {
        let verifier = ScheduledRefreshVerifier::builder()
            .factory(always_down())
            .cold_backoff(Duration::ZERO) // retry immediately in the test
            .fallback(MissVerifier { present: false })
            .build()
            .await
            .expect("cold start is tolerated, not fatal");

        let err = verifier
            .verify(b"input", b"sig", &km())
            .await
            .expect_err("no keys have ever loaded");
        assert!(matches!(err, VerifyError::KeysUnavailable));
    }

    /// The first verify recovers once the upstream returns: the cold miss-refresh
    /// loads the real keyset and the token verifies — no `KeysUnavailable`.
    #[tokio::test]
    async fn cold_verify_recovers_when_upstream_returns() {
        let calls = Arc::new(AtomicUsize::new(0));
        let factory = move || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if n == 0 {
                    Err(Error::new(
                        crate::error::ErrorKind::Transport { retryable: true },
                        "down at boot",
                    ))
                } else {
                    Ok(MissVerifier { present: true })
                }
            }) as Pin<Box<dyn MaybeSendFuture<Output = Result<MissVerifier, Error>>>>
        };
        let verifier = ScheduledRefreshVerifier::builder()
            .factory(factory)
            .cold_backoff(Duration::ZERO)
            .fallback(MissVerifier { present: false })
            .build()
            .await
            .expect("cold start is tolerated");

        verifier
            .verify(b"input", b"sig", &km())
            .await
            .expect("the cold miss-refresh loads the recovered keyset and verifies");
    }
}
