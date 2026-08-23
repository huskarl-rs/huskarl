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
/// attributes), and unbounded label values degrade metrics backends. Per-key
/// metrics keyed by your registered kids are still available — see
/// [Per-key rotation metrics](#per-key-rotation-metrics) and, for the encrypt
/// side,
/// [`MetricsAeadEncryptorSelector`](crate::crypto::cipher::MetricsAeadEncryptorSelector).
///
/// Note that `not_refreshed` covers "no refresh warranted", "blocked by
/// policy", and "refresh failed" alike — the [`try_refresh`](AeadDecryptor::try_refresh)
/// contract does not distinguish them.
///
/// # Per-key rotation metrics
///
/// Each [`MultiKeyDecryptor`](crate::crypto::cipher::MultiKeyDecryptor) entry
/// can carry its own wrapper with a per-key `name`. The `success` series shows
/// which key opens live traffic — when the retired key's successes reach zero,
/// it is safe to remove. Try-all probing records an `error` on each wrong key,
/// so only `success` is a clean per-key signal.
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use huskarl_core::crypto::cipher::{AeadDecryptor, MetricsAeadDecryptor, MultiKeyDecryptor};
/// # fn keys() -> (Arc<dyn AeadDecryptor>, Arc<dyn AeadDecryptor>) { unimplemented!() }
/// # let (current_key, retired_key) = keys();
/// let decryptor = MultiKeyDecryptor::new(vec![
///     Arc::new(
///         MetricsAeadDecryptor::builder()
///             .inner(current_key)
///             .name("session-cookie/2026-07")
///             .build(),
///     ),
///     Arc::new(
///         MetricsAeadDecryptor::builder()
///             .inner(retired_key)
///             .name("session-cookie/2026-01")
///             .build(),
///     ),
/// ]);
/// # let _ = decryptor;
/// ```
///
/// # Example
///
/// ```rust,no_run
/// # use huskarl_core::crypto::cipher::MetricsAeadDecryptor;
/// # let my_decryptor = (); // your inner `AeadDecryptor`
/// let decryptor = MetricsAeadDecryptor::builder()
///     .inner(my_decryptor)
///     .name("session-cookie")
///     .build();
/// # let _ = decryptor;
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
    pub fn new(
        /// Decryptor to instrument.
        inner: D,
        /// Stable metric-label value identifying this decryptor.
        #[builder(into)]
        name: String,
    ) -> Self {
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
