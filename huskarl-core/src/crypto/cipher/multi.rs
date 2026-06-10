use std::{borrow::Cow, sync::Arc};

use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadOutput, CipherMatch},
    },
    error::{Error, ErrorKind},
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

fn no_matching_key() -> Error {
    Error::from(ErrorKind::Crypto).with_context("no matching decryption key")
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
        count: usize,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut last_error = None;

        for decryptor in decryptors {
            match decryptor
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await
            {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => last_error = Some(e),
            }
        }

        match last_error {
            // With exactly one candidate, the underlying failure is the
            // meaningful diagnostic; with several, no single failure is.
            Some(source) if count == 1 => Err(source),
            _ => Err(no_matching_key()),
        }
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
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            if let Some(m) = cipher_match {
                return match self.select(m) {
                    SelectedDecryptor::ByKeyId(decryptor) => {
                        decryptor
                            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                            .await
                    }
                    SelectedDecryptor::ByAlgorithm(decryptors) => {
                        let count = decryptors.len();
                        Self::try_decrypt(
                            decryptors.into_iter(),
                            count,
                            cipher_match,
                            nonce,
                            ciphertext,
                            tag,
                            aad,
                        )
                        .await
                    }
                    SelectedDecryptor::None => Err(no_matching_key()),
                };
            }

            // No cipher_match — try all keys in order.
            Self::try_decrypt(
                self.decryptors.iter(),
                self.decryptors.len(),
                None,
                nonce,
                ciphertext,
                tag,
                aad,
            )
            .await
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
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        self.decryptor
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }
}
