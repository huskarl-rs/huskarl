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
