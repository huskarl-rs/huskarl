use std::{borrow::Cow, sync::Arc};

use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{
            AeadDecryptor, AeadEncryptor, AeadEncryptorSelector, AeadOutput, CipherMatch,
            DecryptError,
        },
    },
    error::Error,
    platform::MaybeSendBoxFuture,
};

/// An [`AeadEncryptorSelector`] wrapper that records a `huskarl.aead.select`
/// counter for each key selection and a `huskarl.aead.encrypt` counter for
/// each encryption.
///
/// Wrap your cipher's encrypt side to instrument encryptions per key — under
/// rotation, the `kid` label shows traffic moving to the new key. Both `kid`
/// labels are read off the frozen snapshot itself, so a rotation landing
/// mid-operation cannot mislabel a count. Select and encrypt need not be 1:1:
/// a caller may hold one snapshot across many encryptions.
///
/// # Labels
///
/// `huskarl.aead.select`:
///
/// | Label     | Values                            | Description                        |
/// |-----------|-----------------------------------|------------------------------------|
/// | `name`    | user-provided                     | Identifies this encryptor instance |
/// | `kid`     | registered key ID, or `(none)`    | Key the selection resolved to      |
///
/// `huskarl.aead.encrypt`:
///
/// | Label     | Values                            | Description                        |
/// |-----------|-----------------------------------|------------------------------------|
/// | `name`    | user-provided                     | Identifies this encryptor instance |
/// | `kid`     | registered key ID, or `(none)`    | Key that performed the encryption  |
/// | `outcome` | `success`, `error`                | Encryption result                  |
///
/// The `kid` names a key you registered, so its cardinality is bounded by
/// your keyset — unlike the wire-supplied [`CipherMatch`] values kept off
/// [`MetricsAeadDecryptor`]'s labels.
///
/// [`AeadDecryptor`] passes through untouched, so wrapping a full
/// [`AeadCipher`](crate::crypto::cipher::AeadCipher) preserves both
/// directions; pair with [`MetricsAeadDecryptor`] to instrument decryption.
///
/// [`MetricsAeadDecryptor`]: crate::crypto::cipher::MetricsAeadDecryptor
///
/// # Example
///
/// ```rust,no_run
/// # use huskarl_core::crypto::cipher::{AeadV1Cipher, MetricsAeadEncryptorSelector};
/// # let my_cipher = (); // your inner `AeadCipher` / `AeadEncryptorSelector`
/// let sealer = AeadV1Cipher::new(
///     MetricsAeadEncryptorSelector::builder()
///         .inner(my_cipher)
///         .name("session-cookie")
///         .build(),
/// );
/// # let _ = sealer;
/// ```
#[derive(Debug)]
pub struct MetricsAeadEncryptorSelector<S> {
    inner: S,
    name: Arc<str>,
}

#[bon::bon]
impl<S> MetricsAeadEncryptorSelector<S> {
    /// Creates a new [`MetricsAeadEncryptorSelector`].
    ///
    /// `name` is included as a label on every counter to distinguish this
    /// encryptor from others. Typically set to the purpose of the key.
    #[builder]
    pub fn new(inner: S, #[builder(into)] name: Arc<str>) -> Self {
        Self { inner, name }
    }
}

impl<S> MetricsAeadEncryptorSelector<S> {
    /// Returns a reference to the inner selector.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Unwraps the inner selector.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AeadEncryptorSelector> AeadEncryptorSelector for MetricsAeadEncryptorSelector<S> {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        Box::pin(async move {
            let snapshot = self.inner.select_encryptor().await;

            ::metrics::counter!(
                "huskarl.aead.select",
                "name" => self.name.to_string(),
                "kid" => kid_label(snapshot.as_ref()),
            )
            .increment(1);

            Arc::new(MetricsAeadEncryptor {
                inner: snapshot,
                name: Arc::clone(&self.name),
            }) as Arc<dyn AeadEncryptor>
        })
    }
}

impl<S: AeadDecryptor> AeadDecryptor for MetricsAeadEncryptorSelector<S> {
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
        self.inner
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        self.inner.try_refresh()
    }
}

/// The `kid` label for a snapshot: its registered key ID, or `(none)`.
fn kid_label(snapshot: &dyn AeadEncryptor) -> String {
    snapshot
        .key_id()
        .map_or_else(|| "(none)".to_owned(), Cow::into_owned)
}

/// The counting snapshot handed out by [`MetricsAeadEncryptorSelector`]: it
/// reads the `kid` label off its own frozen snapshot, so the key it names is
/// exactly the key that encrypted.
#[derive(Debug)]
struct MetricsAeadEncryptor {
    inner: Arc<dyn AeadEncryptor>,
    name: Arc<str>,
}

impl AeadEncryptor for MetricsAeadEncryptor {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.inner.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.key_id()
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        Box::pin(async move {
            let result = self.inner.encrypt(plaintext, aad).await;

            let outcome = if result.is_ok() { "success" } else { "error" };

            ::metrics::counter!(
                "huskarl.aead.encrypt",
                "name" => self.name.to_string(),
                "kid" => kid_label(self.inner.as_ref()),
                "outcome" => outcome,
            )
            .increment(1);

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockEncryptor;

    impl AeadEncryptor for MockEncryptor {
        fn enc_algorithm(&self) -> Cow<'_, str> {
            "A256GCM".into()
        }

        fn key_id(&self) -> Option<Cow<'_, str>> {
            Some("kid-1".into())
        }

        fn encrypt<'a>(
            &'a self,
            plaintext: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
            Box::pin(async move {
                Ok(AeadOutput {
                    nonce: vec![1],
                    ciphertext: plaintext.to_vec(),
                    tag: vec![2],
                })
            })
        }
    }

    #[derive(Debug)]
    struct MockKey {
        inner: Arc<MockEncryptor>,
    }

    impl AeadEncryptorSelector for MockKey {
        fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
            let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
            Box::pin(async move { snapshot })
        }
    }

    #[tokio::test]
    async fn snapshot_passes_through_metadata_and_output() {
        let selector = MetricsAeadEncryptorSelector::builder()
            .inner(MockKey {
                inner: Arc::new(MockEncryptor),
            })
            .name("test")
            .build();

        let snapshot = selector.select_encryptor().await;
        assert_eq!(snapshot.enc_algorithm(), "A256GCM");
        assert_eq!(snapshot.key_id().as_deref(), Some("kid-1"));

        let output = snapshot.encrypt(b"hello", b"aad").await.unwrap();
        assert_eq!(output.ciphertext, b"hello");
        assert_eq!(output.nonce, vec![1]);
        assert_eq!(output.tag, vec![2]);
    }
}
