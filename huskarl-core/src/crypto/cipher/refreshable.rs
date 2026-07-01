use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{
            AeadCipherSelector, AeadDecryptor, AeadEncryptor, AeadOutput, AeadSealer,
            AeadSealerSelector, AeadUnsealer, AeadV1Cipher, CipherMatch, DecryptError,
        },
        refreshable::Refreshable,
    },
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// An AEAD cipher that holds a hot-swappable inner cipher behind an
/// [`ArcSwap`](arc_swap::ArcSwap).
///
/// This is the pure **mechanism** layer — it knows how to atomically swap the
/// inner cipher by re-invoking a factory closure. Concurrent refresh attempts
/// are serialised so that only one factory call runs at a time; waiters that
/// arrive while a refresh is in flight adopt the result.
///
/// Policy concerns (TTL, failure backoff) are handled by
/// [`ScheduledRefreshCipher`](super::ScheduledRefreshCipher), which wraps the
/// same mechanism.
///
/// This allows runtime rotation of encryption keys (e.g. from a KMS or secret
/// manager) without restarting the application.
///
/// For emitting, go through the selector API
/// ([`select_cipher`](AeadCipherSelector::select_cipher) /
/// [`select_sealer`](AeadSealerSelector::select_sealer)), which hands back a frozen
/// snapshot. Using the type directly as an [`AeadEncryptor`] takes a fresh snapshot
/// per call, so reading metadata and then encrypting can straddle a rotation — the
/// hazard the selector exists to prevent (see [composing crypto
/// strategies](crate::_docs::explanation::crypto_strategies)); the bare impl exists
/// only for composition and erasure.
///
/// All clones share the same underlying state, so a refresh performed through
/// any clone is visible to all others — a single `RefreshableCipher` can be
/// cloned into a sealer and an unsealer while one handle is kept for refresh.
#[derive(Debug)]
pub struct RefreshableCipher<C> {
    inner: Arc<Refreshable<C>>,
}

impl<C> Clone for RefreshableCipher<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[bon::bon]
impl<C: std::fmt::Debug + MaybeSendSync + 'static> RefreshableCipher<C> {
    /// Creates a new [`RefreshableCipher`] using the given factory.
    ///
    /// The factory is called immediately to produce the initial cipher. The
    /// same factory is called on subsequent refreshes via
    /// [`refresh`](Self::refresh).
    ///
    /// # Errors
    ///
    /// Returns an error if the initial factory call fails.
    #[builder]
    pub async fn new(
        factory: impl Fn() -> Pin<Box<dyn MaybeSendFuture<Output = Result<C, Error>>>>
        + MaybeSendSync
        + 'static,
    ) -> Result<Self, Error> {
        let refreshable = Refreshable::builder().factory(factory).build().await?;
        Ok(Self {
            inner: Arc::new(refreshable),
        })
    }

    /// Refreshes the cipher by re-invoking the factory and atomically swapping
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

impl<C: AeadEncryptor + 'static> AeadEncryptor for RefreshableCipher<C> {
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

impl<C: AeadDecryptor + 'static> AeadDecryptor for RefreshableCipher<C> {
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
        // `is_ok`, not `unwrap_or(false)`: `refresh` returns `Ok(false)` when
        // another task refreshed concurrently — the key material *is* fresh, so
        // the contract ("true if loaded or concurrently loaded") requires `true`.
        Box::pin(async move { self.refresh().await.is_ok() })
    }
}

impl<C: AeadEncryptor + 'static> AeadCipherSelector for RefreshableCipher<C> {
    fn select_cipher(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        // Hand back the current key as one frozen snapshot: reading its metadata
        // and encrypting against it then describe and use the same key, even if a
        // rotation lands afterwards.
        let encryptor: Arc<dyn AeadEncryptor> = self.inner.load_full();
        Box::pin(async move { encryptor })
    }
}

impl<C: AeadEncryptor + 'static> AeadSealerSelector for RefreshableCipher<C> {
    fn select_sealer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadSealer>> {
        // Frame the frozen snapshot as a v1 sealer. Because it is one fixed key,
        // `key_id`/`enc_algorithm` and `seal` on the returned sealer agree even
        // across a concurrent rotation.
        let sealer: Arc<dyn AeadSealer> = Arc::new(AeadV1Cipher::new(self.inner.load_full()));
        Box::pin(async move { sealer })
    }
}

impl<C: AeadDecryptor + 'static> AeadUnsealer for RefreshableCipher<C> {
    fn unseal<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        bundle: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            AeadV1Cipher::new(self.inner.load_full())
                .unseal(cipher_match, bundle, aad)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[derive(Debug)]
    struct KeyedCipher {
        kid: String,
    }

    impl AeadEncryptor for KeyedCipher {
        fn enc_algorithm(&self) -> Cow<'_, str> {
            "mock".into()
        }

        fn key_id(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(&self.kid))
        }

        fn encrypt<'a>(
            &'a self,
            plaintext: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
            Box::pin(async move {
                Ok(AeadOutput {
                    nonce: vec![],
                    ciphertext: plaintext.to_vec(),
                    tag: self.kid.clone().into_bytes(),
                })
            })
        }
    }

    impl AeadDecryptor for KeyedCipher {
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

    async fn versioned_cipher() -> RefreshableCipher<KeyedCipher> {
        let counter = Arc::new(AtomicU32::new(0));
        let factory =
            move || -> Pin<Box<dyn MaybeSendFuture<Output = Result<KeyedCipher, Error>>>> {
                let counter = Arc::clone(&counter);
                Box::pin(async move {
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    Ok(KeyedCipher {
                        kid: format!("v{n}"),
                    })
                })
            };
        RefreshableCipher::builder()
            .factory(factory)
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn refresh_swaps_cipher_for_all_clones() {
        let cipher = versioned_cipher().await;
        let clone = cipher.clone();

        assert_eq!(cipher.key_id().as_deref(), Some("v0"));
        assert!(cipher.refresh().await.unwrap());
        assert_eq!(clone.key_id().as_deref(), Some("v1"));
    }

    #[tokio::test]
    async fn try_refresh_swaps_through_dyn_decryptor() {
        let cipher = versioned_cipher().await;
        let output = cipher.encrypt(b"hello", b"").await.unwrap();

        let decryptor: Arc<dyn AeadDecryptor> = Arc::new(cipher);
        decryptor
            .decrypt(None, &output.nonce, &output.ciphertext, &output.tag, b"")
            .await
            .unwrap();

        assert!(decryptor.try_refresh().await);

        // The old bundle was sealed with v0; after refresh only v1 decrypts.
        let err = decryptor
            .decrypt(None, &output.nonce, &output.ciphertext, &output.tag, b"")
            .await
            .unwrap_err();
        let DecryptError::Other { source } = err else {
            unreachable!("expected DecryptError::Other, got {err:?}");
        };
        assert_eq!(source.kind(), crate::error::ErrorKind::Crypto);

        let m = CipherMatch::builder().kid("v1").build();
        assert_eq!(decryptor.cipher_match(&m), Some(KeyMatchStrength::ByKeyId));
    }
}
