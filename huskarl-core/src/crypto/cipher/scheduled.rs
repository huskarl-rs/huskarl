use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{
            AeadCipherSelector, AeadDecryptor, AeadEncryptor, AeadOutput, AeadSealer,
            AeadSealerSelector, AeadUnsealer, AeadV1Cipher, CipherMatch, DecryptError,
        },
        refreshable::ScheduledRefreshable,
    },
    error::Error,
    platform::{Duration, MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// An AEAD cipher that bounds the age of its keys to a TTL by reloading on the
/// read path — so a decryption key *removed* upstream is dropped within the TTL
/// even though it never fails to decrypt (you still hold it). The TTL bounds how
/// long a removed key lingers; key *additions* are handled by the miss-triggered
/// [`RetryingDecryptor`](super::RetryingDecryptor) layered on top.
///
/// On each [`decrypt`](AeadDecryptor::decrypt)/[`unseal`](AeadUnsealer::unseal),
/// and inside each [`select_cipher`](AeadCipherSelector::select_cipher)/[`select_sealer`](AeadSealerSelector::select_sealer),
/// the first caller past the TTL reloads single-flight (non-blocking for others),
/// then proceeds against a frozen snapshot; for the outbound selectors the TTL
/// bounds how quickly a rotated-in key is discovered rather than how quickly a removed
/// one is dropped. Using the type directly as
/// an [`AeadEncryptor`] serves the current snapshot *without* a reload — go through
/// the selector for the freshness guarantee. The pure swap mechanism without policy
/// is [`RefreshableCipher`](super::RefreshableCipher).
///
/// See [composing crypto strategies](crate::_docs::explanation::crypto_strategies)
/// for how this layer (removals) pairs with the retrying layer (additions). All
/// clones share the same underlying state, so a refresh through any clone is
/// visible to all others.
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

    /// Reloads the key if it has outlived its TTL and the rate-limit/backoff
    /// policy permits; a within-TTL key is left in place. Blocking.
    ///
    /// A manual staleness poll: the selector paths
    /// ([`select_cipher`](AeadCipherSelector::select_cipher),
    /// [`select_sealer`](AeadSealerSelector::select_sealer)) already reload a stale
    /// key during selection, so this only pre-warms the key ahead of a
    /// latency-sensitive encrypt/seal. Distinct from the inbound miss path
    /// [`AeadDecryptor::try_refresh`], which is not TTL-gated;
    /// [`refresh`](Self::refresh) reloads unconditionally.
    ///
    /// Returns `true` if this call refreshed successfully, `false` if the policy
    /// blocked it or the refresh failed.
    pub async fn refresh_if_stale(&self) -> bool {
        self.inner.refresh_if_stale().await
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
            // Bound staleness on the read path: a decryption key removed upstream
            // yields no decrypt failure (you still hold it), so only a time bound
            // retires it. The first decrypt past the TTL reloads (single-flight,
            // non-blocking for others) before decrypting.
            self.inner.poll_refresh_ahead().await;
            self.inner
                .load_full()
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        // Miss path (`RetryingDecryptor` / `MultiKeyDecryptor` fan-out): **not**
        // TTL-gated, so an added key is picked up within the TTL. The inherent
        // `refresh_if_stale` above is the TTL-gated manual staleness poll — a
        // deliberately distinct operation.
        Box::pin(self.inner.try_refresh_on_miss())
    }
}

impl<C: AeadEncryptor + 'static> AeadCipherSelector for ScheduledRefreshCipher<C> {
    fn select_cipher(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        Box::pin(async move {
            // Reload a stale key during selection, then hand back the fresh key as
            // one frozen snapshot — the caller encrypts against exactly this key.
            self.inner.poll_refresh_ahead().await;
            let encryptor: Arc<dyn AeadEncryptor> = self.inner.load_full();
            encryptor
        })
    }
}

impl<C: AeadEncryptor + 'static> AeadSealerSelector for ScheduledRefreshCipher<C> {
    fn select_sealer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadSealer>> {
        Box::pin(async move {
            // Reload on the outbound read path, then frame the frozen snapshot as a
            // v1 sealer whose metadata and `seal` describe and use the same key.
            self.inner.poll_refresh_ahead().await;
            let sealer: Arc<dyn AeadSealer> = Arc::new(AeadV1Cipher::new(self.inner.load_full()));
            sealer
        })
    }
}

impl<C: AeadDecryptor + 'static> AeadUnsealer for ScheduledRefreshCipher<C> {
    fn unseal<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        bundle: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            // Same read-path staleness bound as `decrypt`: reload past the TTL,
            // then parse and open against the current snapshot.
            self.inner.poll_refresh_ahead().await;
            AeadV1Cipher::new(self.inner.load_full())
                .unseal(cipher_match, bundle, aad)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rstest::rstest;

    use super::*;

    /// An identity cipher (ciphertext == plaintext) that reports a fixed `kid`
    /// and stamps that `kid` into the authentication tag, so the generation that
    /// actually performed an operation is observable in both its metadata and its
    /// output.
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
            let tag = self.kid.clone().into_bytes();
            Box::pin(async move {
                Ok(AeadOutput {
                    nonce: Vec::new(),
                    ciphertext,
                    tag,
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

    /// `refresh_if_stale` is gated by the TTL: a fresh value is left in place, a
    /// stale one (zero TTL) is swapped for the next generation.
    #[rstest]
    #[case::blocked_while_fresh(Duration::from_hours(1), false, "gen-0")]
    #[case::allowed_when_stale(Duration::from_secs(0), true, "gen-1")]
    #[tokio::test]
    async fn refresh_if_stale_respects_ttl_policy(
        #[case] ttl: Duration,
        #[case] expected_refreshed: bool,
        #[case] expected_kid: &str,
    ) {
        let cipher = generational_cipher(ttl, Duration::from_secs(0)).await;
        assert_eq!(cipher.refresh_if_stale().await, expected_refreshed);
        assert_eq!(current_kid(&cipher).as_deref(), Some(expected_kid));
    }

    /// The inbound miss path (`AeadDecryptor::try_refresh`) is **not** TTL-gated:
    /// even a fresh keyset reloads, so a `RetryingDecryptor` picks up an added key
    /// within the TTL. Its TTL-gated sibling is the inherent `refresh_if_stale`.
    #[tokio::test]
    async fn decryptor_try_refresh_is_not_ttl_gated() {
        // A large TTL — the value is nowhere near stale — yet the miss path still
        // reloads, swapping gen-0 for gen-1.
        let cipher = generational_cipher(Duration::from_hours(1), Duration::from_secs(0)).await;
        assert!(AeadDecryptor::try_refresh(&cipher).await);
        assert_eq!(current_kid(&cipher).as_deref(), Some("gen-1"));
    }

    /// A decryptor whose generation 0 decrypts (holds the key) and every later
    /// generation rejects (the key has been retired upstream).
    #[derive(Debug)]
    struct RetiringDecryptor {
        holds_key: bool,
    }

    impl AeadDecryptor for RetiringDecryptor {
        fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
            self.holds_key.then_some(KeyMatchStrength::ByAlgorithm)
        }

        fn decrypt<'a>(
            &'a self,
            _cipher_match: Option<&'a CipherMatch<'a>>,
            _nonce: &'a [u8],
            ciphertext: &'a [u8],
            _tag: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
            let holds_key = self.holds_key;
            let plaintext = ciphertext.to_vec();
            Box::pin(async move {
                if holds_key {
                    Ok(plaintext)
                } else {
                    Err(DecryptError::NoMatchingKey)
                }
            })
        }
    }

    #[allow(clippy::type_complexity)]
    fn retiring_decryptor() -> (
        Arc<AtomicUsize>,
        impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<RetiringDecryptor, Error>>>>
        + MaybeSendSync
        + 'static,
    ) {
        let builds = Arc::new(AtomicUsize::new(0));
        let counter = builds.clone();
        let factory = move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(RetiringDecryptor { holds_key: n == 0 }) })
                as Pin<Box<dyn MaybeSendFuture<Output = Result<RetiringDecryptor, Error>>>>
        };
        (builds, factory)
    }

    #[tokio::test]
    async fn stale_keyset_reloads_before_decrypt_and_retires_the_key() {
        // gen-0 would decrypt, but the keyset is past its TTL, so the read-path
        // reload swaps in gen-1 (key retired) before decrypting — no decrypt
        // failure was ever needed to trigger it.
        let (builds, factory) = retiring_decryptor();
        let cipher: ScheduledRefreshCipher<RetiringDecryptor> = ScheduledRefreshCipher::builder()
            .factory(factory)
            .ttl(Duration::ZERO)
            .min_refresh_interval(Duration::ZERO)
            .build()
            .await
            .unwrap();

        cipher
            .decrypt(None, b"", b"data", b"", b"")
            .await
            .expect_err("the retired decryption key is dropped by the staleness reload");
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "initial build + one reload"
        );
    }

    #[tokio::test]
    async fn fresh_keyset_decrypts_without_reload() {
        let (builds, factory) = retiring_decryptor();
        let cipher: ScheduledRefreshCipher<RetiringDecryptor> = ScheduledRefreshCipher::builder()
            .factory(factory)
            .ttl(Duration::from_hours(1))
            .build()
            .await
            .unwrap();

        let recovered = cipher.decrypt(None, b"", b"data", b"", b"").await.unwrap();
        assert_eq!(recovered, b"data");
        assert_eq!(builds.load(Ordering::SeqCst), 1, "no reload while fresh");
    }

    #[tokio::test]
    async fn select_cipher_hands_back_the_current_snapshot() {
        let cipher = generational_cipher(Duration::from_hours(1), Duration::from_secs(0)).await;
        assert_eq!(
            cipher.select_cipher().await.key_id().as_deref(),
            Some("gen-0")
        );
    }

    #[tokio::test]
    async fn select_cipher_reloads_a_stale_key_during_selection() {
        // Zero TTL: the outbound read path reloads before handing back the snapshot.
        let cipher = generational_cipher(Duration::ZERO, Duration::ZERO).await;
        assert_eq!(
            cipher.select_cipher().await.key_id().as_deref(),
            Some("gen-1")
        );
    }

    /// The crux of the sealer-selector: a sealer is a *frozen* snapshot, so a
    /// rotation landing after selection cannot make its `key_id` and its `seal`
    /// describe different keys. `FakeCipher` tags every bundle with its `kid`, so
    /// the key that actually sealed is observable in the ciphertext.
    #[tokio::test]
    async fn selected_sealer_kid_and_ciphertext_agree_across_a_rotation() {
        let cipher = generational_cipher(Duration::from_hours(1), Duration::ZERO).await;

        let sealer = cipher.select_sealer().await;
        let kid = sealer.key_id().map(std::borrow::Cow::into_owned);
        assert_eq!(kid.as_deref(), Some("gen-0"));

        // Rotate the underlying key out from under the held sealer.
        assert!(cipher.refresh().await.unwrap());
        assert_eq!(current_kid(&cipher).as_deref(), Some("gen-1"));

        // The frozen sealer still seals with gen-0 — the key its `kid` named —
        // not the freshly rotated gen-1.
        let bundle = sealer.seal(b"payload", b"aad").await.unwrap();
        // v1 layout: [0x01, nonce_len=0, tag_len=5, ciphertext="payload", tag="gen-0"]
        let tag = &bundle[bundle.len() - 5..];
        assert_eq!(tag, b"gen-0");
    }
}
