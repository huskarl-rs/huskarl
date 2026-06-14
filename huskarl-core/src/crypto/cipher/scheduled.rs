use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{
            AeadCipherSelector, AeadDecryptor, AeadEncryptor, AeadOutput, CipherMatch, DecryptError,
        },
        refreshable::ScheduledRefreshable,
    },
    error::Error,
    platform::{Duration, MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// An AEAD cipher that holds a hot-swappable inner cipher behind a
/// `ScheduledRefreshable`, gating refresh attempts with TTL and
/// failure-backoff policy.
///
/// This is the **policy** layer — it tracks when the last successful and failed
/// refreshes occurred and only delegates to the inner refresh when the TTL has
/// expired and the failure backoff has elapsed. The pure swap mechanism without
/// policy is [`RefreshableCipher`](super::RefreshableCipher).
///
/// All clones share the same underlying state, so a refresh performed through
/// any clone is visible to all others.
#[derive(Debug)]
pub struct ScheduledRefreshCipher<C> {
    inner: Arc<ScheduledRefreshable<C>>,
}

impl<C> Clone for ScheduledRefreshCipher<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[bon::bon]
impl<C: std::fmt::Debug + MaybeSendSync + 'static> ScheduledRefreshCipher<C> {
    /// Creates a new [`ScheduledRefreshCipher`] using the given factory and policy parameters.
    ///
    /// The factory is called immediately to produce the initial cipher.
    /// The same factory is called on subsequent refreshes.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<C, Error>>>>
        + MaybeSendSync
        + 'static,
        /// The time-to-live for the cached cipher.
        #[builder(default = Duration::from_hours(1))]
        ttl: Duration,
        /// The backoff duration after a failed refresh.
        #[builder(default = Duration::from_secs(30))]
        failure_backoff: Duration,
        /// Minimum time between any two refresh attempts, regardless of outcome.
        #[builder(default = Duration::from_mins(1))]
        min_refresh_interval: Duration,
    ) -> Result<Self, Error> {
        let inner = ScheduledRefreshable::builder()
            .factory(factory)
            .ttl(ttl)
            .failure_backoff(failure_backoff)
            .min_refresh_interval(min_refresh_interval)
            .build()
            .await?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Attempts a policy-gated refresh. Returns `true` if a refresh was performed
    /// and succeeded, `false` if the policy blocked the attempt or the refresh failed.
    pub async fn try_refresh(&self) -> bool {
        self.inner.try_refresh().await
    }

    /// Forces a refresh bypassing the scheduling policy, but still records the outcome.
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

impl<C: AeadEncryptor + 'static> AeadEncryptor for ScheduledRefreshCipher<C> {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        Cow::Owned(self.inner.load().enc_algorithm().into_owned())
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner
            .load()
            .key_id()
            .map(|kid| Cow::Owned(kid.into_owned()))
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        Box::pin(async move { self.inner.load_full().encrypt(plaintext, aad).await })
    }
}

impl<C: AeadDecryptor + 'static> AeadDecryptor for ScheduledRefreshCipher<C> {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.load().cipher_match(m)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            self.inner
                .load_full()
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(self.inner.try_refresh())
    }
}

impl<C: AeadCipherSelector + std::fmt::Debug + 'static> AeadCipherSelector
    for ScheduledRefreshCipher<C>
{
    fn select_cipher(&self) -> Arc<dyn AeadEncryptor> {
        self.inner.load().select_cipher()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rstest::rstest;

    use super::*;

    /// An identity cipher (ciphertext == plaintext) that reports a fixed `kid`,
    /// so the generation currently held by the wrapper is observable.
    #[derive(Debug)]
    struct FakeCipher {
        kid: String,
    }

    impl AeadEncryptor for FakeCipher {
        fn enc_algorithm(&self) -> Cow<'_, str> {
            "A256GCM".into()
        }
        fn key_id(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(&self.kid))
        }
        fn encrypt<'a>(
            &'a self,
            plaintext: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
            let ciphertext = plaintext.to_vec();
            Box::pin(async move {
                Ok(AeadOutput {
                    nonce: Vec::new(),
                    ciphertext,
                    tag: Vec::new(),
                })
            })
        }
    }

    impl AeadDecryptor for FakeCipher {
        fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
            Some(KeyMatchStrength::ByAlgorithm)
        }
        fn decrypt<'a>(
            &'a self,
            _cipher_match: Option<&'a CipherMatch<'a>>,
            _nonce: &'a [u8],
            ciphertext: &'a [u8],
            _tag: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
            let plaintext = ciphertext.to_vec();
            Box::pin(async move { Ok(plaintext) })
        }
    }

    /// A selector that hands out a `FakeCipher` carrying its `kid`.
    #[derive(Debug)]
    struct FakeSelector {
        kid: String,
    }

    impl AeadCipherSelector for FakeSelector {
        fn select_cipher(&self) -> Arc<dyn AeadEncryptor> {
            Arc::new(FakeCipher {
                kid: self.kid.clone(),
            })
        }
    }

    /// A generational cipher (`gen-0`, `gen-1`, …) with the given policy.
    async fn generational_cipher(
        ttl: Duration,
        min_refresh_interval: Duration,
    ) -> ScheduledRefreshCipher<FakeCipher> {
        let counter = Arc::new(AtomicUsize::new(0));
        ScheduledRefreshCipher::builder()
            .factory(move || {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    Ok(FakeCipher {
                        kid: format!("gen-{n}"),
                    })
                })
            })
            .ttl(ttl)
            .min_refresh_interval(min_refresh_interval)
            .build()
            .await
            .unwrap()
    }

    fn current_kid(cipher: &ScheduledRefreshCipher<FakeCipher>) -> Option<String> {
        cipher.key_id().map(std::borrow::Cow::into_owned)
    }

    #[tokio::test]
    async fn delegates_encryptor_metadata_to_inner() {
        let cipher = generational_cipher(Duration::from_hours(1), Duration::from_secs(0)).await;
        assert_eq!(cipher.enc_algorithm().as_ref(), "A256GCM");
        assert_eq!(current_kid(&cipher).as_deref(), Some("gen-0"));
    }

    #[tokio::test]
    async fn encrypt_and_decrypt_delegate_to_inner() {
        let cipher = generational_cipher(Duration::from_hours(1), Duration::from_secs(0)).await;
        let out = cipher.encrypt(b"plaintext", b"aad").await.unwrap();
        let recovered = cipher
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"aad")
            .await
            .unwrap();
        assert_eq!(recovered, b"plaintext");
    }

    #[tokio::test]
    async fn cipher_match_delegates_to_inner() {
        let cipher = generational_cipher(Duration::from_hours(1), Duration::from_secs(0)).await;
        let m = CipherMatch {
            enc: Some("A256GCM"),
            kid: None,
        };
        assert_eq!(cipher.cipher_match(&m), Some(KeyMatchStrength::ByAlgorithm));
    }

    #[tokio::test]
    async fn forced_refresh_bypasses_policy() {
        // A long TTL would block a policy-gated refresh, but `refresh` is forced.
        let cipher = generational_cipher(Duration::from_hours(1), Duration::from_mins(1)).await;
        assert_eq!(current_kid(&cipher).as_deref(), Some("gen-0"));
        assert!(cipher.refresh().await.unwrap());
        assert_eq!(current_kid(&cipher).as_deref(), Some("gen-1"));
    }

    /// `try_refresh` is gated by the TTL: a fresh value is left in place, a
    /// stale one (zero TTL) is swapped for the next generation.
    #[rstest]
    #[case::blocked_while_fresh(Duration::from_hours(1), false, "gen-0")]
    #[case::allowed_when_stale(Duration::from_secs(0), true, "gen-1")]
    #[tokio::test]
    async fn try_refresh_respects_ttl_policy(
        #[case] ttl: Duration,
        #[case] expected_refreshed: bool,
        #[case] expected_kid: &str,
    ) {
        let cipher = generational_cipher(ttl, Duration::from_secs(0)).await;
        assert_eq!(cipher.try_refresh().await, expected_refreshed);
        assert_eq!(current_kid(&cipher).as_deref(), Some(expected_kid));
    }

    #[tokio::test]
    async fn decryptor_try_refresh_delegates_through_the_trait() {
        let cipher = generational_cipher(Duration::from_secs(0), Duration::from_secs(0)).await;
        // Resolve the `AeadDecryptor` method explicitly (an inherent `try_refresh`
        // also exists and would otherwise win method resolution).
        assert!(AeadDecryptor::try_refresh(&cipher).await);
        assert_eq!(current_kid(&cipher).as_deref(), Some("gen-1"));
    }

    #[tokio::test]
    async fn select_cipher_delegates_to_inner() {
        let counter = Arc::new(AtomicUsize::new(0));
        let selector: ScheduledRefreshCipher<FakeSelector> = ScheduledRefreshCipher::builder()
            .factory(move || {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    Ok(FakeSelector {
                        kid: format!("gen-{n}"),
                    })
                })
            })
            .build()
            .await
            .unwrap();

        assert_eq!(selector.select_cipher().key_id().as_deref(), Some("gen-0"));
    }
}
