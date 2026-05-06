use std::borrow::Cow;

use snafu::prelude::*;

use crate::{
    BoxedError,
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadOutput, BoxedAeadDecryptor, CipherMatch},
    },
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
pub struct MultiKeyDecryptor {
    decryptors: Vec<BoxedAeadDecryptor>,
}

impl MultiKeyDecryptor {
    /// Creates a new `MultiKeyDecryptor` from the given decryptors.
    #[must_use]
    pub fn new(decryptors: Vec<BoxedAeadDecryptor>) -> Self {
        Self { decryptors }
    }
}

/// Errors that can occur during [`MultiKeyDecryptor`] decryption.
#[derive(Debug, Snafu)]
pub enum MultiKeyDecryptorError {
    /// No key could decrypt the ciphertext.
    #[snafu(display("no matching key"))]
    NoMatchingKey,
    /// The single matching key failed to decrypt.
    #[snafu(display("decryption failed"))]
    DecryptionFailed {
        /// The underlying error.
        source: BoxedError,
    },
}

impl crate::Error for MultiKeyDecryptorError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::NoMatchingKey => false,
            Self::DecryptionFailed { source } => source.is_retryable(),
        }
    }
}

enum SelectedDecryptor<'a> {
    /// A single key matched definitively by key ID.
    ByKeyId(&'a BoxedAeadDecryptor),
    /// One or more keys matched by algorithm only.
    ByAlgorithm(Vec<&'a BoxedAeadDecryptor>),
    /// No keys matched.
    None,
}

impl MultiKeyDecryptor {
    fn select<'a>(&'a self, m: &CipherMatch<'_>) -> SelectedDecryptor<'a> {
        let mut by_algorithm: Vec<&'a BoxedAeadDecryptor> = Vec::new();

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
        decryptors: impl Iterator<Item = &BoxedAeadDecryptor>,
        count: usize,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, MultiKeyDecryptorError> {
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
            Some(source) if count == 1 => Err(MultiKeyDecryptorError::DecryptionFailed { source }),
            _ => NoMatchingKeySnafu.fail(),
        }
    }
}

impl AeadDecryptor for MultiKeyDecryptor {
    type Error = MultiKeyDecryptorError;

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

    async fn decrypt(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if let Some(m) = cipher_match {
            match self.select(m) {
                SelectedDecryptor::ByKeyId(decryptor) => {
                    return decryptor
                        .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                        .await
                        .map_err(|source| MultiKeyDecryptorError::DecryptionFailed { source });
                }
                SelectedDecryptor::ByAlgorithm(decryptors) => {
                    let count = decryptors.len();
                    return Self::try_decrypt(
                        decryptors.into_iter(),
                        count,
                        cipher_match,
                        nonce,
                        ciphertext,
                        tag,
                        aad,
                    )
                    .await;
                }
                SelectedDecryptor::None => return NoMatchingKeySnafu.fail(),
            }
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
    }
}

/// An [`AeadEncryptor`] + [`AeadDecryptor`] that encrypts with a single key
/// and decrypts with a [`MultiKeyDecryptor`].
///
/// This allows a single value to be passed where both encryption and decryption
/// capabilities are needed (e.g. encrypted cookies with key rotation).
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
    type Error = E::Error;

    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.encryptor.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.encryptor.key_id()
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AeadOutput, Self::Error> {
        self.encryptor.encrypt(plaintext, aad).await
    }
}

impl<E: AeadEncryptor> AeadDecryptor for MultiKeyCipher<E> {
    type Error = MultiKeyDecryptorError;

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.decryptor.cipher_match(m)
    }

    async fn decrypt(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.decryptor
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
            .await
    }
}
