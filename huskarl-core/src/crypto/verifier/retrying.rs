use crate::{
    crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    platform::MaybeSendBoxFuture,
};

/// A [`JwsVerifier`] that, on a [`NoMatchingKey`](VerifyError::NoMatchingKey)
/// failure, refreshes the inner verifier and retries once.
///
/// A miss is an unambiguous "I hold no key for this token's `alg`/`kid`" signal, so
/// a refresh can plausibly fix it — the fast path for key *additions*. It reacts
/// *only* to a miss; a signature mismatch is returned as-is, since a refresh would
/// be wasted on a (usually forged) bad signature.
///
/// This is the single place in the verifier hierarchy where refresh-and-retry
/// lives; wrap the root verifier with it so any composition underneath — a
/// [`ScheduledRefreshVerifier`](crate::crypto::verifier::ScheduledRefreshVerifier),
/// a [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier), or arbitrary
/// nesting — gets the retry without implementing it itself. The retry's refresh is
/// still gated by the inner layer's policy (e.g. a scheduled layer's
/// `min_refresh_interval`), so a burst of unknown-`kid` tokens cannot force a burst
/// of upstream fetches.
///
/// See [composing crypto strategies](crate::_docs::explanation::crypto_strategies)
/// for how additions (here) and removals plus the same-algorithm kid-less edge (the
/// scheduled layer's TTL) are split between the two layers.
#[derive(Debug, Clone)]
pub struct RetryingVerifier<V> {
    inner: V,
}

impl<V: JwsVerifier> RetryingVerifier<V> {
    /// Wraps a verifier so that a `NoMatchingKey` result triggers a refresh and
    /// one retry.
    pub fn new(inner: V) -> Self {
        Self { inner }
    }
}

impl<V: JwsVerifier + 'static> JwsVerifier for RetryingVerifier<V> {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.key_match(key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async move {
            match self.inner.verify(input, signature, key_match).await {
                // A miss may be cured by a reload (a key added since the last
                // fetch); refresh once and retry. Everything else — including a
                // signature mismatch — is returned as-is.
                Err(VerifyError::NoMatchingKey) => {
                    if self.inner.try_refresh().await {
                        self.inner.verify(input, signature, key_match).await
                    } else {
                        Err(VerifyError::NoMatchingKey)
                    }
                }
                other => other,
            }
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        self.inner.try_refresh()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum Fail {
        NoMatchingKey,
        SignatureMismatch,
    }

    fn make_err(fail: Fail) -> VerifyError {
        match fail {
            Fail::NoMatchingKey => VerifyError::NoMatchingKey,
            Fail::SignatureMismatch => VerifyError::SignatureMismatch,
        }
    }

    /// A verifier that fails with `fail` until a refresh succeeds, then accepts.
    /// Counters are shared so a clone moved into the wrapper stays observable.
    #[derive(Debug, Clone)]
    struct FakeInner {
        fail: Fail,
        recover_on_refresh: bool,
        refreshed: Arc<AtomicBool>,
        refresh_calls: Arc<AtomicUsize>,
    }

    impl FakeInner {
        fn new(fail: Fail, recover_on_refresh: bool) -> Self {
            Self {
                fail,
                recover_on_refresh,
                refreshed: Arc::new(AtomicBool::new(false)),
                refresh_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn refresh_calls(&self) -> usize {
            self.refresh_calls.load(Ordering::SeqCst)
        }
    }

    impl JwsVerifier for FakeInner {
        fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            Some(KeyMatchStrength::ByAlgorithm)
        }

        fn verify<'a>(
            &'a self,
            _input: &'a [u8],
            _signature: &'a [u8],
            _key_match: &'a KeyMatch<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
            let recovered = self.refreshed.load(Ordering::SeqCst);
            let fail = self.fail;
            Box::pin(async move {
                if recovered {
                    Ok(())
                } else {
                    Err(make_err(fail))
                }
            })
        }

        fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            let recover = self.recover_on_refresh;
            let refreshed = self.refreshed.clone();
            Box::pin(async move {
                if recover {
                    refreshed.store(true, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })
        }
    }

    fn km() -> KeyMatch<'static> {
        KeyMatch {
            alg: "ES256",
            kid: None,
        }
    }

    #[tokio::test]
    async fn no_matching_key_refreshes_and_recovers() {
        let inner = FakeInner::new(Fail::NoMatchingKey, true);
        let verifier = RetryingVerifier::new(inner.clone());

        verifier
            .verify(b"input", b"sig", &km())
            .await
            .expect("a miss reloads and the added key verifies");
        assert_eq!(inner.refresh_calls(), 1);
    }

    #[tokio::test]
    async fn no_matching_key_without_new_material_returns_the_miss() {
        let inner = FakeInner::new(Fail::NoMatchingKey, false);
        let verifier = RetryingVerifier::new(inner.clone());

        assert!(verifier.verify(b"input", b"sig", &km()).await.is_err());
        // One refresh was attempted; with no new material there is no retry gain.
        assert_eq!(inner.refresh_calls(), 1);
    }

    #[tokio::test]
    async fn signature_mismatch_does_not_reload() {
        // Signature mismatches are handled by the scheduled verifier's TTL reload,
        // not here — a refresh on a (usually forged) bad signature would be wasted.
        let inner = FakeInner::new(Fail::SignatureMismatch, true);
        let verifier = RetryingVerifier::new(inner.clone());

        assert!(verifier.verify(b"input", b"sig", &km()).await.is_err());
        assert_eq!(inner.refresh_calls(), 0);
    }
}
