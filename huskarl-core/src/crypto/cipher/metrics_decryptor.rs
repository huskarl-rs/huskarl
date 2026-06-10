use crate::{
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, CipherMatch, DecryptError},
    },
    platform::MaybeSendBoxFuture,
};

/// An [`AeadDecryptor`] wrapper that records a `huskarl.aead.decrypt` counter
/// for each decryption attempt and a `huskarl.aead.refresh` counter for each
/// refresh attempt.
///
/// Wrap your decryptor with this type to instrument AEAD decryptions. The
/// `name` parameter is included as a label on every counter, allowing metrics
/// from multiple wrapped decryptors to be distinguished — typically set to
/// the purpose of the key (e.g. `"session-cookie"`).
///
/// # Labels
///
/// `huskarl.aead.decrypt`:
///
/// | Label     | Values                                 | Description                        |
/// |-----------|----------------------------------------|------------------------------------|
/// | `name`    | user-provided                          | Identifies this decryptor instance |
/// | `outcome` | `success`, `no_matching_key`, `error`  | Decryption result                  |
///
/// `huskarl.aead.refresh`:
///
/// | Label     | Values                         | Description                        |
/// |-----------|--------------------------------|------------------------------------|
/// | `name`    | user-provided                  | Identifies this decryptor instance |
/// | `outcome` | `refreshed`, `not_refreshed`   | Refresh result                     |
///
/// `no_matching_key` and `error` are particularly useful for security
/// monitoring — elevated rates may indicate key rotation in progress or
/// tampered input. The [`CipherMatch`] `enc`/`kid` values are deliberately
/// **not** used as labels: they can be attacker-supplied (JWE headers, cookie
/// attributes), and unbounded label values degrade metrics backends.
///
/// Note that `not_refreshed` covers "no refresh warranted", "blocked by
/// policy", and "refresh failed" alike — the [`try_refresh`](AeadDecryptor::try_refresh)
/// contract does not distinguish them.
///
/// # Example
///
/// ```rust,ignore
/// let decryptor = MetricsAeadDecryptor::builder()
///     .inner(my_decryptor)
///     .name("session-cookie")
///     .build();
/// ```
#[derive(Debug)]
pub struct MetricsAeadDecryptor<D> {
    inner: D,
    name: String,
}

#[bon::bon]
impl<D> MetricsAeadDecryptor<D> {
    /// Creates a new [`MetricsAeadDecryptor`].
    ///
    /// `name` is included as a label on every counter to distinguish this
    /// decryptor from others. Typically set to the purpose of the key.
    #[builder]
    pub fn new(inner: D, #[builder(into)] name: String) -> Self {
        Self { inner, name }
    }
}

impl<D> MetricsAeadDecryptor<D> {
    /// Returns a reference to the inner decryptor.
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Unwraps the inner decryptor.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: AeadDecryptor> AeadDecryptor for MetricsAeadDecryptor<D> {
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
            let result = self
                .inner
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await;

            let outcome = match &result {
                Ok(_) => "success",
                Err(DecryptError::NoMatchingKey) => "no_matching_key",
                Err(DecryptError::Other { .. }) => "error",
            };

            ::metrics::counter!(
                "huskarl.aead.decrypt",
                "name" => self.name.clone(),
                "outcome" => outcome,
            )
            .increment(1);

            result
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async move {
            let refreshed = self.inner.try_refresh().await;

            let outcome = if refreshed {
                "refreshed"
            } else {
                "not_refreshed"
            };

            ::metrics::counter!(
                "huskarl.aead.refresh",
                "name" => self.name.clone(),
                "outcome" => outcome,
            )
            .increment(1);

            refreshed
        })
    }
}
