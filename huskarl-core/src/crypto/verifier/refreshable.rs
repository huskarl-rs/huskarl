use std::pin::Pin;

use crate::{
    crypto::{
        KeyMatchStrength,
        refreshable::Refreshable,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// A [`JwsVerifier`] that holds a hot-swappable verifier behind an [`ArcSwap`](arc_swap::ArcSwap).
///
/// This is the pure **mechanism** layer — it knows how to atomically swap the inner
/// verifier by re-invoking a factory closure. Concurrent refresh attempts are serialised
/// so that only one factory call runs at a time; waiters that arrive while a refresh is
/// in flight adopt the result.
///
/// Policy concerns (TTL, failure backoff) are handled by
/// [`ScheduledRefreshVerifier`](super::ScheduledRefreshVerifier), which wraps this type.
pub struct RefreshableVerifier<V> {
    inner: Refreshable<V>,
}

impl<V: std::fmt::Debug> std::fmt::Debug for RefreshableVerifier<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshableVerifier")
            .field("inner", &self.inner)
            .finish()
    }
}

#[bon::bon]
impl<V: JwsVerifier + 'static> RefreshableVerifier<V> {
    /// Creates a new [`RefreshableVerifier`] using the given factory.
    ///
    /// The factory is called immediately to produce the initial verifier. The same factory
    /// is called on subsequent refreshes via [`try_refresh`](JwsVerifier::try_refresh).
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        /// Asynchronous source of the current verifier, called at construction
        /// and on each explicit refresh.
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<V, Error>>>>
        + MaybeSendSync
        + 'static,
    ) -> Result<Self, Error> {
        let inner = Refreshable::builder().factory(factory).build().await?;
        Ok(Self { inner })
    }

    /// Refreshes the verifier by re-invoking the factory and atomically swapping
    /// the inner value.
    ///
    /// Concurrent callers are serialised — only one factory call runs at a time.
    /// If another task already refreshed while this one was waiting for the lock,
    /// the new value is adopted without a redundant fetch.
    ///
    /// Returns `Ok(true)` if new key material was fetched by this call, or
    /// `Ok(false)` if another task already refreshed concurrently.
    ///
    /// # Errors
    ///
    /// Returns an error if the factory call fails.
    pub async fn refresh(&self) -> Result<bool, Error> {
        self.inner.refresh().await
    }
}

impl<V: JwsVerifier + 'static> JwsVerifier for RefreshableVerifier<V> {
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
            self.inner
                .load_full()
                .verify(input, signature, key_match)
                .await
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        // `is_ok`, not `unwrap_or(false)`: `refresh` returns `Ok(false)` when
        // another task refreshed concurrently — the key material *is* fresh, so
        // the contract ("true if loaded or concurrently loaded") requires `true`.
        Box::pin(async move { self.refresh().await.is_ok() })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// A verifier whose acceptance is fixed at construction, so a swap to a
    /// differently-configured instance is observable through the trait.
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
                    Err(VerifyError::NoMatchingKey)
                }
            })
        }
    }

    /// First factory call accepts; every later one rejects — so a refresh
    /// flips the observable behaviour.
    async fn accept_then_reject() -> RefreshableVerifier<FlagVerifier> {
        let counter = Arc::new(AtomicUsize::new(0));
        RefreshableVerifier::builder()
            .factory(move || {
                let accept = counter.fetch_add(1, Ordering::SeqCst) == 0;
                Box::pin(async move { Ok(FlagVerifier { accept }) })
            })
            .build()
            .await
            .unwrap()
    }

    fn key_match() -> KeyMatch<'static> {
        KeyMatch {
            alg: "ES256",
            kid: None,
        }
    }

    #[tokio::test]
    async fn delegates_to_the_initial_verifier() {
        let verifier = accept_then_reject().await;
        assert_eq!(
            verifier.key_match(&key_match()),
            Some(KeyMatchStrength::ByAlgorithm)
        );
        verifier
            .verify(b"input", b"sig", &key_match())
            .await
            .expect("initial verifier accepts");
    }

    #[tokio::test]
    async fn refresh_swaps_the_inner_verifier() {
        let verifier = accept_then_reject().await;
        assert!(verifier.refresh().await.unwrap());

        // After the swap the rejecting verifier is in force.
        assert_eq!(verifier.key_match(&key_match()), None);
        verifier
            .verify(b"input", b"sig", &key_match())
            .await
            .expect_err("post-refresh verifier rejects");
    }

    #[tokio::test]
    async fn try_refresh_reports_success_and_swaps() {
        let verifier = accept_then_reject().await;
        assert!(verifier.try_refresh().await, "try_refresh succeeded");
        assert_eq!(verifier.key_match(&key_match()), None);
    }
}
