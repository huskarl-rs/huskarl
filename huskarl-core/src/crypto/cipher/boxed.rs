use std::{borrow::Cow, pin::Pin, sync::Arc};

use crate::{
    BoxedError,
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadOutput, CipherMatch},
    },
    platform::{MaybeSendFuture, MaybeSendSync},
};

/// Boxed AEAD encryptor.
pub struct BoxedAeadEncryptor {
    inner: Arc<dyn DynAeadEncryptor>,
}

impl BoxedAeadEncryptor {
    /// Creates a new encryptor.
    pub fn new<E: AeadEncryptor + 'static>(encryptor: E) -> Self {
        Self {
            inner: Arc::new(encryptor),
        }
    }
}

impl Clone for BoxedAeadEncryptor {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl AeadEncryptor for BoxedAeadEncryptor {
    type Error = BoxedError;

    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.inner.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.key_id()
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AeadOutput, Self::Error> {
        self.inner.encrypt(plaintext, aad).await
    }
}

trait DynAeadEncryptor: MaybeSendSync {
    fn enc_algorithm(&self) -> Cow<'_, str>;
    fn key_id(&self) -> Option<Cow<'_, str>>;

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<AeadOutput, BoxedError>> + 'a>>;
}

impl<E: AeadEncryptor> DynAeadEncryptor for E {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        AeadEncryptor::enc_algorithm(self)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        AeadEncryptor::key_id(self)
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<AeadOutput, BoxedError>> + 'a>> {
        Box::pin(async move {
            self.encrypt(plaintext, aad)
                .await
                .map_err(BoxedError::from_err)
        })
    }
}

/// Boxed AEAD decryptor.
pub struct BoxedAeadDecryptor {
    inner: Arc<dyn DynAeadDecryptor>,
}

impl BoxedAeadDecryptor {
    /// Crates a new decryptor.
    pub fn new<D: AeadDecryptor + 'static>(decryptor: D) -> Self {
        Self {
            inner: Arc::new(decryptor),
        }
    }
}

impl Clone for BoxedAeadDecryptor {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl AeadDecryptor for BoxedAeadDecryptor {
    type Error = BoxedError;

    fn nonce_length(&self) -> usize {
        self.inner.nonce_length()
    }

    fn tag_length(&self) -> usize {
        self.inner.tag_length()
    }

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.cipher_match(m)
    }

    async fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.inner.decrypt(nonce, ciphertext, tag, aad).await
    }
}

trait DynAeadDecryptor: MaybeSendSync {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength>;
    fn nonce_length(&self) -> usize;
    fn tag_length(&self) -> usize;

    fn decrypt<'a>(
        &'a self,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>>;
}

impl<D: AeadDecryptor> DynAeadDecryptor for D {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        AeadDecryptor::cipher_match(self, m)
    }

    fn nonce_length(&self) -> usize {
        AeadDecryptor::nonce_length(self)
    }

    fn tag_length(&self) -> usize {
        AeadDecryptor::tag_length(self)
    }

    fn decrypt<'a>(
        &'a self,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<Vec<u8>, BoxedError>> + 'a>> {
        Box::pin(async move {
            self.decrypt(nonce, ciphertext, tag, aad)
                .await
                .map_err(BoxedError::from_err)
        })
    }
}
