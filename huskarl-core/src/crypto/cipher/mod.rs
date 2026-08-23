//! AEAD content encryption and decryption: the parts-level
//! `(nonce, ciphertext, tag)` primitives that content-encryption schemes such
//! as JWE and the [sealing](crate::crypto::seal) layer build on.

mod error;
#[cfg(feature = "metrics")]
mod metrics_decryptor;
#[cfg(feature = "metrics")]
mod metrics_encryptor;
mod multi;
mod refreshable;
mod retrying;
mod scheduled;

use std::{borrow::Cow, sync::Arc};

use bon::Builder;
pub use error::DecryptError;
#[cfg(feature = "metrics")]
pub use metrics_decryptor::MetricsAeadDecryptor;
#[cfg(feature = "metrics")]
pub use metrics_encryptor::MetricsAeadEncryptorSelector;
pub use multi::{MultiKeyCipher, MultiKeyDecryptor};
pub use refreshable::RefreshableCipher;
pub use retrying::RetryingDecryptor;
pub use scheduled::ScheduledRefreshCipher;

use crate::{
    crypto::KeyMatchStrength,
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// The output from [`AeadEncryptor::encrypt`]
pub struct AeadOutput {
    /// The nonce (IV) used to encrypt.
    pub nonce: Vec<u8>,
    /// The ciphertext resulting from the encryption.
    pub ciphertext: Vec<u8>,
    /// The authentication tag resulting from the encryption.
    pub tag: Vec<u8>,
}

/// Selection criteria used to choose a content decryption key.
///
/// Both fields are optional. When `enc` is `None`, algorithm matching is
/// skipped and the key is considered algorithm-compatible. When `kid` is
/// `None`, key ID matching is skipped.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Builder)]
pub struct CipherMatch<'a> {
    /// The content encryption algorithm (e.g. from the JWE `enc` header).
    /// When `None`, the algorithm is not used for matching.
    pub enc: Option<&'a str>,
    /// The key ID (e.g. from the JWE `kid` header or an out-of-band source).
    pub kid: Option<&'a str>,
}

impl CipherMatch<'_> {
    /// Computes the match strength for a single key, applying the standard
    /// rules documented on [`AeadDecryptor::cipher_match`].
    ///
    /// `enc_algorithm` is the content encryption algorithm of the key;
    /// `registered_kid` is the key ID registered for the key, if any.
    ///
    /// Single-key [`AeadDecryptor`] implementations should delegate to this
    /// from [`cipher_match`](AeadDecryptor::cipher_match) rather than
    /// re-implementing the rules — in particular the requirement that a
    /// `kid` mismatch returns `None` rather than `Some(ByAlgorithm)`.
    #[must_use]
    pub fn strength_for(
        &self,
        enc_algorithm: &str,
        registered_kid: Option<&str>,
    ) -> Option<KeyMatchStrength> {
        if let Some(enc) = self.enc
            && enc != enc_algorithm
        {
            return None;
        }

        crate::crypto::kid_match_strength(self.kid, registered_kid)
    }
}

/// Trait for AEAD encryption.
///
/// This trait is dyn-capable: consumers store it as `Arc<dyn AeadEncryptor>`.
/// Write the `encrypt` body as `Box::pin(async move { ... })`; a failure is an
/// [`Error`] whose cause names what the cipher could not do.
pub trait AeadEncryptor: std::fmt::Debug + MaybeSendSync {
    /// Returns the content encryption algorithm identifier (e.g. `A256GCM`).
    fn enc_algorithm(&self) -> Cow<'_, str>;

    /// Returns the key ID for this encryptor, if any.
    fn key_id(&self) -> Option<Cow<'_, str>>;

    /// Asynchronously encrypts the given plaintext with the associated data.
    ///
    /// Implementations that draw a random nonce per call (e.g. AES-GCM with
    /// its 96-bit nonce) carry a per-key encryption bound — NIST SP 800-38D
    /// §8.3 caps random-nonce GCM at 2^32 invocations per key. See the
    /// implementation's documentation, and size key rotation accordingly.
    ///
    /// # Errors
    ///
    /// Returns an error if the encryption operation fails.
    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>>;
}

impl<T: AeadEncryptor + ?Sized> AeadEncryptor for Arc<T> {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.as_ref().enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.as_ref().key_id()
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        self.as_ref().encrypt(plaintext, aad)
    }
}

/// Trait for AEAD decryption.
///
/// Exposes key selection via [`cipher_match`](Self::cipher_match) so that
/// multi-key types can dispatch to the correct decryptor.
///
/// This trait is dyn-capable: consumers store it as `Arc<dyn AeadDecryptor>`.
pub trait AeadDecryptor: std::fmt::Debug + MaybeSendSync {
    /// Returns how well this decryptor matches the given selection criteria.
    ///
    /// Implementations must return:
    ///
    /// - `Some(ByKeyId)` — the algorithm is compatible (matches or was not specified)
    ///   **and** both the criteria and this decryptor have a `kid`, and they are equal.
    /// - `Some(ByAlgorithm)` — the algorithm is compatible, but the `kid` could not be
    ///   used for matching: either the criteria has no `kid`, or this decryptor has no
    ///   `kid` registered.
    /// - `None` — the algorithm is unsupported by this decryptor, **or** both the
    ///   criteria and this decryptor have a `kid` but they differ.
    ///
    /// Single-key implementations should delegate to
    /// [`CipherMatch::strength_for`], which implements these rules.
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength>;

    /// Asynchronously decrypts the given ciphertext with the provided nonce, tag, and associated data.
    ///
    /// `cipher_match` carries the selection criteria (algorithm and key ID) from the
    /// caller, when available. Multi-key implementations use this to dispatch to
    /// the correct key without trying every candidate. Single-key implementations
    /// may ignore it.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError::NoMatchingKey`] if no key matched the selection
    /// criteria — decryption was not attempted, and
    /// [`RetryingDecryptor`] treats this as grounds for a refresh and one
    /// retry. All other failures — including authentication failure — arrive as
    /// [`DecryptError::Other`].
    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>>;

    /// Requests a best-effort refresh of the decryptor's key material — the cipher
    /// analogue of
    /// [`JwsVerifier::try_refresh`](crate::crypto::verifier::JwsVerifier::try_refresh).
    ///
    /// Called automatically by [`RetryingDecryptor`] when no key
    /// matches, and may also be called manually. A wrapping policy layer may
    /// rate-limit or decline the request, so it can return `false` without
    /// reloading; for a guaranteed reload, use a refreshable wrapper's inherent
    /// `refresh`.
    ///
    /// Returns `true` if new key material was loaded (or was concurrently loaded by another
    /// task). Returns `false` if no refresh was needed, attempted, or successful. The default
    /// implementation always returns `false`.
    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async { false })
    }
}

impl<T: AeadDecryptor + ?Sized> AeadDecryptor for Arc<T> {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.as_ref().cipher_match(m)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.as_ref()
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        self.as_ref().try_refresh()
    }
}

/// Combined trait for types that can both select an encryptor and decrypt.
///
/// Automatically implemented for any type with both capabilities. Store as
/// `Arc<dyn AeadCipher>` when both directions must come from the same source
/// (e.g. a symmetric AEAD key).
pub trait AeadCipher: AeadEncryptorSelector + AeadDecryptor {}

impl<T: AeadEncryptorSelector + AeadDecryptor + ?Sized> AeadCipher for T {}

/// A selector for an AEAD encryptor.
///
/// Returns an encryptor that is a frozen snapshot of the current key; hold it
/// briefly (for one encryption) and drop it. Selection is **async** so a
/// refreshing implementation (e.g. `ScheduledRefreshCipher`) can reload a stale
/// key before handing it back. See [composing crypto
/// strategies](crate::_docs::explanation::crypto_strategies) for why outbound
/// operations select rather than hot-swap.
///
/// This trait is dyn-capable: consumers store it as
/// `Arc<dyn AeadEncryptorSelector>`.
pub trait AeadEncryptorSelector: std::fmt::Debug + MaybeSendSync {
    /// Selects the current encryptor to use for encryption, refreshing stale key
    /// material first where the implementation supports it.
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>>;
}

impl<T: AeadEncryptorSelector + ?Sized> AeadEncryptorSelector for Arc<T> {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        self.as_ref().select_encryptor()
    }
}

// ── Compatibility shims (deprecated in 0.9.1) ──────────────────────────────
// The sealing seam moved to [`crate::crypto::seal`], and `AeadV1Cipher` was
// renamed to `AeadV1Sealer`. These re-exports keep the 0.9.0 paths compiling.

/// Renamed and moved to [`crate::crypto::seal::AeadV1Sealer`].
#[deprecated(
    since = "0.9.1",
    note = "renamed and moved to `huskarl_core::crypto::seal::AeadV1Sealer`"
)]
pub type AeadV1Cipher<C> = crate::crypto::seal::AeadV1Sealer<C>;

/// Moved to [`crate::crypto::seal::SealOutput`].
#[deprecated(
    since = "0.9.1",
    note = "moved to `huskarl_core::crypto::seal::SealOutput`"
)]
pub type SealOutput = crate::crypto::seal::SealOutput;

/// Moved to [`crate::crypto::seal::UnsealError`].
#[deprecated(
    since = "0.9.1",
    note = "moved to `huskarl_core::crypto::seal::UnsealError`"
)]
pub type UnsealError = crate::crypto::seal::UnsealError;

// Trait re-exports: rustc does not lint deprecated `use` re-exports, so these
// resolve silently for back-compat (rustdoc still renders the deprecation).
// Prefer the `crate::crypto::seal` paths.
#[deprecated(since = "0.9.1", note = "moved to `huskarl_core::crypto::seal`")]
pub use crate::crypto::seal::{AeadSealer, AeadSealerUnsealer, AeadUnsealer};

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher_match<'a>(enc: Option<&'a str>, kid: Option<&'a str>) -> CipherMatch<'a> {
        CipherMatch { enc, kid }
    }

    #[test]
    fn strength_for_enc_mismatch() {
        let m = cipher_match(Some("A128GCM"), Some("kid-1"));
        assert_eq!(m.strength_for("A256GCM", Some("kid-1")), None);
    }

    #[test]
    fn strength_for_no_enc_is_compatible() {
        let m = cipher_match(None, None);
        assert_eq!(
            m.strength_for("A256GCM", None),
            Some(KeyMatchStrength::ByAlgorithm)
        );
    }

    #[test]
    fn strength_for_matching_kid() {
        let m = cipher_match(Some("A256GCM"), Some("kid-1"));
        assert_eq!(
            m.strength_for("A256GCM", Some("kid-1")),
            Some(KeyMatchStrength::ByKeyId)
        );
    }

    #[test]
    fn strength_for_kid_mismatch_is_none_not_by_algorithm() {
        let m = cipher_match(None, Some("kid-1"));
        assert_eq!(m.strength_for("A256GCM", Some("kid-2")), None);
    }

    #[test]
    fn strength_for_missing_kid_falls_back_to_algorithm() {
        let m = cipher_match(Some("A256GCM"), None);
        assert_eq!(
            m.strength_for("A256GCM", Some("kid-1")),
            Some(KeyMatchStrength::ByAlgorithm)
        );
        let m = cipher_match(Some("A256GCM"), Some("kid-1"));
        assert_eq!(
            m.strength_for("A256GCM", None),
            Some(KeyMatchStrength::ByAlgorithm)
        );
    }
}
