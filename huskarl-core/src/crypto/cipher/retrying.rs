use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, CipherMatch, DecryptError},
    },
    platform::MaybeSendBoxFuture,
};

/// An [`AeadDecryptor`] that retries once after a
/// [`NoMatchingKey`](DecryptError::NoMatchingKey) error by calling
/// [`try_refresh`](AeadDecryptor::try_refresh) on the inner decryptor.
///
/// It covers cross-server key propagation during rotation (one server seals with a
/// freshly rotated key another has not loaded yet) and is the cipher analogue of
/// [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier). Wrap the root
/// decryptor with it so any composition underneath — a
/// [`ScheduledRefreshCipher`](super::ScheduledRefreshCipher), a
/// [`MultiKeyDecryptor`](super::MultiKeyDecryptor), or arbitrary nesting — gets one
/// retry without implementing it. The retry's refresh is gated by the inner layer's
/// policy, so a burst of unknown-`kid` bundles cannot force a burst of upstream
/// fetches.
///
/// The retry fires only on `NoMatchingKey`, so callers must pass a [`CipherMatch`]
/// with a `kid` **and** register kids on all keys in the set. A key with no
/// registered kid can never be ruled out: it falls back to a
/// [`ByAlgorithm`](crate::crypto::KeyMatchStrength::ByAlgorithm) match, is
/// attempted, and its authentication failure masks the miss as
/// [`Other`](DecryptError::Other) — no retry fires. Likewise, with no
/// [`CipherMatch`] at all, a stale key set surfaces as an authentication failure
/// from try-all dispatch, indistinguishable from tampering and deliberately not
/// retried.
///
/// See [composing crypto strategies](crate::_docs::explanation::crypto_strategies)
/// for how this layer (additions) pairs with the scheduled layer (removals).
#[derive(Debug, Clone)]
pub struct RetryingDecryptor<D> {
    inner: D,
}

impl<D: AeadDecryptor> RetryingDecryptor<D> {
    /// Wraps a decryptor so that a `NoMatchingKey` result triggers a refresh and one retry.
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D: AeadDecryptor> AeadDecryptor for RetryingDecryptor<D> {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.cipher_match(m)
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
            match self
                .inner
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await
            {
                Err(DecryptError::NoMatchingKey) => {
                    if self.inner.try_refresh().await {
                        self.inner
                            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                            .await
                    } else {
                        Err(DecryptError::NoMatchingKey)
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
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
    };

    use super::*;
    use crate::{
        crypto::cipher::{MultiKeyDecryptor, RefreshableCipher},
        error::Error,
        platform::MaybeSendFuture,
    };

    /// A decryptor whose key identity is its kid; decryption succeeds only
    /// when the bundle's tag carries the same kid.
    #[derive(Debug)]
    struct KeyedDecryptor {
        kid: String,
    }

    impl AeadDecryptor for KeyedDecryptor {
        fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
            m.strength_for("mock", Some(&self.kid))
        }

        fn decrypt<'a>(
            &'a self,
            _cipher_match: Option<&'a CipherMatch<'a>>,
            _nonce: &'a [u8],
            ciphertext: &'a [u8],
            tag: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
            Box::pin(async move {
                if tag == self.kid.as_bytes() {
                    Ok(ciphertext.to_vec())
                } else {
                    Err(Error::from(crate::error::ErrorKind::Crypto).into())
                }
            })
        }
    }

    /// Each refresh widens the key set by one version: refresh n yields
    /// keys v0..=vn, simulating another server's rotation propagating.
    async fn rotating_decryptor() -> RefreshableCipher<MultiKeyDecryptor> {
        let generation = Arc::new(AtomicU32::new(0));
        let factory =
            move || -> Pin<Box<dyn MaybeSendFuture<Output = Result<MultiKeyDecryptor, Error>>>> {
                let generation = Arc::clone(&generation);
                Box::pin(async move {
                    let n = generation.fetch_add(1, Ordering::SeqCst);
                    let keys = (0..=n)
                        .map(|v| {
                            Arc::new(KeyedDecryptor {
                                kid: format!("v{v}"),
                            }) as Arc<dyn AeadDecryptor>
                        })
                        .collect();
                    Ok(MultiKeyDecryptor::new(keys))
                })
            };
        RefreshableCipher::builder()
            .factory(factory)
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn retries_after_refresh_on_no_matching_key() {
        let decryptor = RetryingDecryptor::new(rotating_decryptor().await);

        // Sealed elsewhere with v1, which this decryptor (holding only v0)
        // has not loaded yet.
        let m = CipherMatch::builder().enc("mock").kid("v1").build();
        let plaintext = decryptor
            .decrypt(Some(&m), b"", b"hello", b"v1", b"")
            .await
            .unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[tokio::test]
    async fn retries_only_once() {
        let decryptor = RetryingDecryptor::new(rotating_decryptor().await);

        // v9 is never loaded: one refresh happens (v0 -> v0..=v1), the retry
        // still misses, and the miss is returned without further refreshes.
        let m = CipherMatch::builder().enc("mock").kid("v9").build();
        let err = decryptor
            .decrypt(Some(&m), b"", b"hello", b"v9", b"")
            .await
            .unwrap_err();
        assert!(matches!(err, DecryptError::NoMatchingKey));
        let m = CipherMatch::builder().kid("v1").build();
        assert_eq!(decryptor.cipher_match(&m), Some(KeyMatchStrength::ByKeyId));
    }

    #[tokio::test]
    async fn real_failures_are_not_retried() {
        let decryptor = RetryingDecryptor::new(rotating_decryptor().await);

        // Tag mismatch on a key that exists: authentication failure, no retry.
        let m = CipherMatch::builder().enc("mock").kid("v0").build();
        let err = decryptor
            .decrypt(Some(&m), b"", b"hello", b"tampered", b"")
            .await
            .unwrap_err();
        assert!(matches!(err, DecryptError::Other { .. }));
        // No refresh happened: v1 is still unknown.
        let m = CipherMatch::builder().kid("v1").build();
        assert_eq!(decryptor.cipher_match(&m), None);
    }
}
