use std::{borrow::Cow, sync::Arc};

use futures_util::future::join_all;

use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadOutput, CipherMatch, DecryptError},
    },
    error::Error,
    platform::MaybeSendBoxFuture,
};

/// An [`AeadDecryptor`] that holds multiple keys and applies [`CipherMatch`] /
/// [`KeyMatchStrength`] selection semantics.
///
/// This is the cipher analogue of
/// [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier).
///
/// # Key selection
///
/// [`cipher_match`](AeadDecryptor::cipher_match) follows [`KeyMatchStrength`] priority:
/// - A [`ByKeyId`](KeyMatchStrength::ByKeyId) match (algorithm + kid) is definitive.
/// - A single [`ByAlgorithm`](KeyMatchStrength::ByAlgorithm) match is used directly.
///
/// [`decrypt`](AeadDecryptor::decrypt) uses the optional [`CipherMatch`] to select
/// the correct key when available. When no `CipherMatch` is provided, keys are
/// tried in order.
///
/// Unlike [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier), which
/// fails closed on ambiguity, trying every candidate is safe here: an AEAD tag
/// self-authenticates, so a wrong key fails decryption rather than risking
/// wrong-key acceptance. Try-all is standard practice for rotated symmetric
/// keys (e.g. cookie-key rotation).
///
/// # Errors
///
/// When no candidate matches the criteria, decryption fails with
/// [`DecryptError::NoMatchingKey`] without attempting decryption — this is
/// what lets [`RetryingDecryptor`](crate::crypto::cipher::RetryingDecryptor)
/// trigger a key refresh. When candidates were attempted and all failed, the
/// last real failure is returned (non-retryable preferred over retryable),
/// matching the verifier's dispatch discipline.
#[derive(Debug)]
pub struct MultiKeyDecryptor {
    decryptors: Vec<Arc<dyn AeadDecryptor>>,
}

impl MultiKeyDecryptor {
    /// Creates a new `MultiKeyDecryptor` from the given decryptors.
    #[must_use]
    pub fn new(decryptors: Vec<Arc<dyn AeadDecryptor>>) -> Self {
        Self { decryptors }
    }
}

enum SelectedDecryptor<'a> {
    /// A single key matched definitively by key ID.
    ByKeyId(&'a Arc<dyn AeadDecryptor>),
    /// One or more keys matched by algorithm only.
    ByAlgorithm(Vec<&'a Arc<dyn AeadDecryptor>>),
    /// No keys matched.
    None,
}

impl MultiKeyDecryptor {
    fn select<'a>(&'a self, m: &CipherMatch<'_>) -> SelectedDecryptor<'a> {
        let mut by_algorithm: Vec<&'a Arc<dyn AeadDecryptor>> = Vec::new();

        for decryptor in &self.decryptors {
            match decryptor.cipher_match(m) {
                Some(KeyMatchStrength::ByKeyId) => {
                    return SelectedDecryptor::ByKeyId(decryptor);
                }
                Some(KeyMatchStrength::ByAlgorithm) => {
                    by_algorithm.push(decryptor);
                }
                None => {}
            }
        }

        if by_algorithm.is_empty() {
            SelectedDecryptor::None
        } else {
            SelectedDecryptor::ByAlgorithm(by_algorithm)
        }
    }

    async fn try_decrypt(
        decryptors: impl Iterator<Item = &Arc<dyn AeadDecryptor>>,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut last_retryable = None;
        let mut last_non_retryable = None;

        for decryptor in decryptors {
            match decryptor
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await
            {
                Ok(plaintext) => return Ok(plaintext),
                // NoMatchingKey means the decryptor didn't attempt decryption —
                // it is the implicit fallback, not a result to prefer over others.
                Err(DecryptError::NoMatchingKey) => {}
                Err(e) => {
                    if e.is_retryable() {
                        last_retryable = Some(e);
                    } else {
                        last_non_retryable = Some(e);
                    }
                }
            }
        }

        Err(last_non_retryable
            .or(last_retryable)
            .unwrap_or(DecryptError::NoMatchingKey))
    }
}

impl AeadDecryptor for MultiKeyDecryptor {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        let mut by_algorithm = false;

        for decryptor in &self.decryptors {
            match decryptor.cipher_match(m) {
                Some(KeyMatchStrength::ByKeyId) => return Some(KeyMatchStrength::ByKeyId),
                Some(KeyMatchStrength::ByAlgorithm) => by_algorithm = true,
                None => {}
            }
        }

        by_algorithm.then_some(KeyMatchStrength::ByAlgorithm)
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
            if let Some(m) = cipher_match {
                return match self.select(m) {
                    SelectedDecryptor::ByKeyId(decryptor) => {
                        decryptor
                            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                            .await
                    }
                    SelectedDecryptor::ByAlgorithm(decryptors) => {
                        Self::try_decrypt(
                            decryptors.into_iter(),
                            cipher_match,
                            nonce,
                            ciphertext,
                            tag,
                            aad,
                        )
                        .await
                    }
                    SelectedDecryptor::None => Err(DecryptError::NoMatchingKey),
                };
            }

            // No cipher_match — try all keys in order.
            Self::try_decrypt(self.decryptors.iter(), None, nonce, ciphertext, tag, aad).await
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async move {
            join_all(self.decryptors.iter().map(AeadDecryptor::try_refresh))
                .await
                .into_iter()
                .any(|b| b)
        })
    }
}

/// An [`AeadEncryptor`] + [`AeadDecryptor`] that encrypts with a single key
/// and decrypts with a [`MultiKeyDecryptor`].
///
/// This allows a single value to be passed where both encryption and decryption
/// capabilities are needed (e.g. encrypted cookies with key rotation).
#[derive(Debug)]
pub struct MultiKeyCipher<E> {
    encryptor: E,
    decryptor: MultiKeyDecryptor,
}

impl<E> MultiKeyCipher<E> {
    /// Creates a new `MultiKeyCipher`.
    pub fn new(encryptor: E, decryptor: MultiKeyDecryptor) -> Self {
        Self {
            encryptor,
            decryptor,
        }
    }
}

impl<E: AeadEncryptor> AeadEncryptor for MultiKeyCipher<E> {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.encryptor.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.encryptor.key_id()
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        self.encryptor.encrypt(plaintext, aad)
    }
}

impl<E: AeadEncryptor> AeadDecryptor for MultiKeyCipher<E> {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.decryptor.cipher_match(m)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.decryptor
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        self.decryptor.try_refresh()
    }
}
