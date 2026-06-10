//! Cipher implementations for encryption and decryption.

mod error;
#[cfg(feature = "metrics")]
mod metrics_decryptor;
mod multi;
mod refreshable;
mod retrying;
mod scheduled;

use std::{borrow::Cow, sync::Arc};

use bon::Builder;
pub use error::{DecryptError, UnsealError};
#[cfg(feature = "metrics")]
pub use metrics_decryptor::MetricsAeadDecryptor;
pub use multi::{MultiKeyCipher, MultiKeyDecryptor};
pub use refreshable::RefreshableCipher;
pub use retrying::RetryingDecryptor;
pub use scheduled::ScheduledRefreshCipher;

use crate::{
    crypto::KeyMatchStrength,
    error::{Error, ErrorKind},
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
/// Write the `encrypt` body as `Box::pin(async move { ... })`; failures
/// classify as [`ErrorKind::Crypto`].
pub trait AeadEncryptor: std::fmt::Debug + MaybeSendSync {
    /// Returns the content encryption algorithm identifier (e.g. `A256GCM`).
    fn enc_algorithm(&self) -> Cow<'_, str>;

    /// Returns the key ID for this encryptor, if any.
    fn key_id(&self) -> Option<Cow<'_, str>>;

    /// Asynchronously encrypts the given plaintext with the associated data.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Crypto`] if the encryption operation fails.
    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>>;
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
    /// caller, when available. Multi-key implementations like
    /// multi-key decryptors use this to dispatch to the correct key. Single-key
    /// implementations may ignore it.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError::NoMatchingKey`] if no key matched the selection
    /// criteria — decryption was not attempted, and
    /// [`RetryingDecryptor`] treats this as grounds for a refresh and one
    /// retry. All other failures — including authentication failure — classify
    /// as [`ErrorKind::Crypto`] via [`DecryptError::Other`].
    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>>;

    /// Attempts to refresh the decryptor's key material if warranted.
    ///
    /// This can be called manually to force a key reload (e.g. after a
    /// rotation event), analogous to
    /// [`JwsVerifier::try_refresh`](crate::crypto::verifier::JwsVerifier::try_refresh).
    ///
    /// Returns `true` if new key material was loaded (or was concurrently loaded by another
    /// task). Returns `false` if no refresh was needed, attempted, or successful. The default
    /// implementation always returns `false`.
    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async { false })
    }
}

/// Combined trait for types that can both encrypt and decrypt.
///
/// Automatically implemented for any type with both capabilities. Store as
/// `Arc<dyn AeadCipher>` when both directions must come from the same source
/// (e.g. a symmetric AEAD key).
pub trait AeadCipher: AeadEncryptor + AeadDecryptor {}

impl<T: AeadEncryptor + AeadDecryptor + ?Sized> AeadCipher for T {}

/// A selector for an AEAD encryptor.
///
/// Returns an encryptor with fixed identity and key material. The resulting
/// encryptor should be held for a short period of time, as longer periods
/// would work against system policies like key rotation.
///
/// This trait is dyn-capable: consumers store it as
/// `Arc<dyn AeadCipherSelector>`.
pub trait AeadCipherSelector: MaybeSendSync {
    /// Selects the current encryptor to use for encryption.
    fn select_cipher(&self) -> Arc<dyn AeadEncryptor>;
}

/// An encryptor that produces self-contained bundles with a prepended version byte and IV.
pub trait AeadSealer: AeadEncryptor {
    /// Encrypts `plaintext` and returns a versioned bundle:
    /// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>>;
}

/// A decryptor that consumes self-contained bundles produced by [`AeadSealer`].
pub trait AeadUnsealer: AeadDecryptor {
    /// Decrypts a versioned bundle produced by [`AeadSealer::seal`].
    ///
    /// `cipher_match` carries optional key selection criteria from an out-of-band
    /// source (e.g. a cookie attribute or database column). Multi-key decryptors
    /// use this to select the correct key without trying all candidates.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError::NoMatchingKey`] if no key matched the selection
    /// criteria; all other failures — malformed bundles, authentication
    /// failure — classify as [`ErrorKind::Crypto`] via [`DecryptError::Other`].
    fn unseal<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        bundle: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>>;
}

macro_rules! forward_aead_encryptor {
    ($wrapper:ty) => {
        impl<T: AeadEncryptor + ?Sized> AeadEncryptor for $wrapper {
            fn enc_algorithm(&self) -> Cow<'_, str> {
                (**self).enc_algorithm()
            }

            fn key_id(&self) -> Option<Cow<'_, str>> {
                (**self).key_id()
            }

            fn encrypt<'a>(
                &'a self,
                plaintext: &'a [u8],
                aad: &'a [u8],
            ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
                (**self).encrypt(plaintext, aad)
            }
        }
    };
}

forward_aead_encryptor!(&T);
forward_aead_encryptor!(Box<T>);
forward_aead_encryptor!(Arc<T>);

macro_rules! forward_aead_decryptor {
    ($wrapper:ty) => {
        impl<T: AeadDecryptor + ?Sized> AeadDecryptor for $wrapper {
            fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
                (**self).cipher_match(m)
            }

            fn decrypt<'a>(
                &'a self,
                cipher_match: Option<&'a CipherMatch<'a>>,
                nonce: &'a [u8],
                ciphertext: &'a [u8],
                tag: &'a [u8],
                aad: &'a [u8],
            ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
                (**self).decrypt(cipher_match, nonce, ciphertext, tag, aad)
            }

            fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
                (**self).try_refresh()
            }
        }
    };
}

forward_aead_decryptor!(&T);
forward_aead_decryptor!(Box<T>);
forward_aead_decryptor!(Arc<T>);

macro_rules! forward_aead_cipher_selector {
    ($wrapper:ty) => {
        impl<T: AeadCipherSelector + ?Sized> AeadCipherSelector for $wrapper {
            fn select_cipher(&self) -> Arc<dyn AeadEncryptor> {
                (**self).select_cipher()
            }
        }
    };
}

forward_aead_cipher_selector!(&T);
forward_aead_cipher_selector!(Box<T>);
forward_aead_cipher_selector!(Arc<T>);

/// An [`AeadSealer`] using the v1 bundle format:
/// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
#[derive(Debug)]
pub struct AeadV1Sealer<E: AeadEncryptor>(E);

impl<E: AeadEncryptor> AeadV1Sealer<E> {
    /// Creates a new sealer.
    pub fn new(encryptor: E) -> Self {
        Self(encryptor)
    }
}

impl<E: AeadEncryptor> AeadEncryptor for AeadV1Sealer<E> {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.0.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.0.key_id()
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        self.0.encrypt(plaintext, aad)
    }
}

impl<E: AeadEncryptor> AeadSealer for AeadV1Sealer<E> {
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let output = self.encrypt(plaintext, aad).await?;

            let nonce_len: u8 = output
                .nonce
                .len()
                .try_into()
                .expect("nonce length exceeds u8::MAX");
            let tag_len: u8 = output
                .tag
                .len()
                .try_into()
                .expect("tag length exceeds u8::MAX");

            let mut bundle = Vec::with_capacity(
                3 + output.nonce.len() + output.ciphertext.len() + output.tag.len(),
            );
            bundle.push(0x01);
            bundle.push(nonce_len);
            bundle.push(tag_len);
            bundle.extend_from_slice(&output.nonce);
            bundle.extend_from_slice(&output.ciphertext);
            bundle.extend_from_slice(&output.tag);

            Ok(bundle)
        })
    }
}

/// An [`AeadUnsealer`] using the v1 bundle format:
/// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
#[derive(Debug)]
pub struct AeadV1Unsealer<D: AeadDecryptor>(D);

impl<D: AeadDecryptor> AeadV1Unsealer<D> {
    /// Creates a new unsealer.
    pub fn new(decryptor: D) -> Self {
        Self(decryptor)
    }
}

fn invalid_bundle() -> Error {
    Error::new(ErrorKind::Crypto, UnsealError::InvalidBundle)
}

impl<D: AeadDecryptor> AeadDecryptor for AeadV1Unsealer<D> {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.0.cipher_match(m)
    }

    fn decrypt<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.0.decrypt(cipher_match, nonce, ciphertext, tag, aad)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        self.0.try_refresh()
    }
}

impl<D: AeadDecryptor> AeadUnsealer for AeadV1Unsealer<D> {
    fn unseal<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        bundle: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            if bundle.len() < 3 || bundle[0] != 0x01 {
                return Err(invalid_bundle().into());
            }

            let nonce_len = bundle[1] as usize;
            let tag_len = bundle[2] as usize;

            if bundle.len() < 3 + nonce_len + tag_len {
                return Err(invalid_bundle().into());
            }

            let nonce = &bundle[3..3 + nonce_len];
            let tag = &bundle[bundle.len() - tag_len..];
            let ciphertext = &bundle[3 + nonce_len..bundle.len() - tag_len];

            self.decrypt(cipher_match, nonce, ciphertext, tag, aad)
                .await
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
            "mock".into()
        }

        fn key_id(&self) -> Option<Cow<'_, str>> {
            None
        }

        fn encrypt<'a>(
            &'a self,
            plaintext: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
            Box::pin(async move {
                Ok(AeadOutput {
                    nonce: vec![1, 2, 3],
                    ciphertext: plaintext.iter().map(|b| b ^ 0xFF).collect(),
                    tag: vec![4, 5, 6, 7],
                })
            })
        }
    }

    #[derive(Debug)]
    struct MockDecryptor;

    impl AeadDecryptor for MockDecryptor {
        fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
            Some(KeyMatchStrength::ByAlgorithm)
        }

        fn decrypt<'a>(
            &'a self,
            _cipher_match: Option<&'a CipherMatch<'a>>,
            _nonce: &'a [u8],
            ciphertext: &'a [u8],
            _tag: &'a [u8],
            _aad: &'a [u8],
        ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
            // Reverse the XOR
            Box::pin(async move { Ok(ciphertext.iter().map(|b| b ^ 0xFF).collect()) })
        }
    }

    fn assert_invalid_bundle(err: &DecryptError) {
        let DecryptError::Other { source } = err else {
            unreachable!("expected DecryptError::Other, got {err:?}");
        };
        assert_eq!(source.kind(), ErrorKind::Crypto);
        assert_eq!(source.to_string(), "cryptographic operation failed");
        assert_eq!(
            std::error::Error::source(source)
                .expect("source")
                .to_string(),
            "invalid bundle"
        );
    }

    #[tokio::test]
    async fn seal_roundtrip() {
        let plaintext = b"hello world";
        let aad = b"associated";

        let sealer = AeadV1Sealer::new(MockEncryptor);
        let bundle = sealer.seal(plaintext, aad).await.unwrap();

        let unsealer = AeadV1Unsealer::new(MockDecryptor);
        let recovered = unsealer.unseal(None, &bundle, aad).await.unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn erased_cipher_roundtrip() {
        let sealer: Arc<dyn AeadSealer> = Arc::new(AeadV1Sealer::new(MockEncryptor));
        let bundle = sealer.seal(b"hello", b"").await.unwrap();

        let unsealer: Arc<dyn AeadUnsealer> = Arc::new(AeadV1Unsealer::new(MockDecryptor));
        let recovered = unsealer.unseal(None, &bundle, b"").await.unwrap();
        assert_eq!(recovered, b"hello");
    }

    #[tokio::test]
    async fn bundle_format() {
        let plaintext = b"AB";
        let sealer = AeadV1Sealer::new(MockEncryptor);
        let bundle = sealer.seal(plaintext, b"").await.unwrap();

        // [0x01, nonce_len=3, tag_len=4, nonce=[1,2,3], ciphertext=[0xBE, 0xBD], tag=[4,5,6,7]]
        assert_eq!(bundle[0], 0x01);
        assert_eq!(bundle[1], 3); // nonce_len
        assert_eq!(bundle[2], 4); // tag_len
        assert_eq!(&bundle[3..6], &[1, 2, 3]); // nonce
        assert_eq!(&bundle[6..8], &[0x41 ^ 0xFF, 0x42 ^ 0xFF]); // ciphertext
        assert_eq!(&bundle[8..12], &[4, 5, 6, 7]); // tag
    }

    #[tokio::test]
    async fn unseal_wrong_version() {
        let unsealer = AeadV1Unsealer::new(MockDecryptor);
        let err = unsealer.unseal(None, &[0x02, 0, 0], b"").await.unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_too_short() {
        let unsealer = AeadV1Unsealer::new(MockDecryptor);
        let err = unsealer.unseal(None, &[0x01], b"").await.unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_truncated() {
        let unsealer = AeadV1Unsealer::new(MockDecryptor);
        // nonce_len=10, tag_len=10, but only 1 byte of data after header
        let err = unsealer
            .unseal(None, &[0x01, 10, 10, 0x00], b"")
            .await
            .unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_empty() {
        let unsealer = AeadV1Unsealer::new(MockDecryptor);
        let err = unsealer.unseal(None, &[], b"").await.unwrap_err();
        assert_invalid_bundle(&err);
    }

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
