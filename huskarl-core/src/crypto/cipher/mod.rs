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
    /// Implementations that draw a random nonce per call (e.g. AES-GCM with
    /// its 96-bit nonce) carry a per-key encryption bound — NIST SP 800-38D
    /// §8.3 caps random-nonce GCM at 2^32 invocations per key. See the
    /// implementation's documentation, and size key rotation accordingly.
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

/// An encryptor that produces self-contained bundles.
///
/// Where [`AeadEncryptor::encrypt`] returns the nonce, ciphertext, and tag as
/// separate fields, a sealer hands back one opaque byte string so the value
/// can travel on its own — an encrypted cookie, a stateless token — and be
/// re-opened later ([`AeadUnsealer`]) with just the bundle and the key.
/// [`AeadV1Cipher`] is the local implementation; see it for a worked example.
///
/// This trait is dyn-capable: consumers store it as `Arc<dyn AeadSealer>`, or
/// as `Arc<dyn AeadSealerUnsealer>` when both directions are needed.
pub trait AeadSealer: std::fmt::Debug + MaybeSendSync {
    /// Encrypts `plaintext` and returns an opaque, self-describing bundle that
    /// a matching [`AeadUnsealer`] can re-open. The layout belongs to the
    /// implementation — an externally-managed sealer returns its service's
    /// token verbatim.
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>>;
}

/// A decryptor that consumes self-contained bundles produced by [`AeadSealer`].
///
/// This trait is dyn-capable: consumers store it as `Arc<dyn AeadUnsealer>`, or
/// as `Arc<dyn AeadSealerUnsealer>` when both directions are needed.
pub trait AeadUnsealer: std::fmt::Debug + MaybeSendSync {
    /// Decrypts a bundle produced by [`AeadSealer::seal`].
    ///
    /// `cipher_match` carries optional key selection criteria known out-of-band.
    /// Multi-key decryptors use this to select the correct key without trying
    /// all candidates; without it, try-all is still safe — the AEAD tag makes a
    /// wrong key a clean failure.
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

/// Combined trait for types that can both seal and unseal.
///
/// Automatically implemented for any type with both capabilities. Store as
/// `Arc<dyn AeadSealerUnsealer>` when both directions must come from the same
/// source — an [`AeadV1Cipher`] over one key, or an externally-managed sealer
/// (e.g. a KMS/Vault encrypt endpoint) whose tokens only it can re-open.
pub trait AeadSealerUnsealer: AeadSealer + AeadUnsealer {}

impl<T: AeadSealer + AeadUnsealer + ?Sized> AeadSealerUnsealer for T {}

impl<T: AeadSealer + ?Sized> AeadSealer for Arc<T> {
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        self.as_ref().seal(plaintext, aad)
    }
}

impl<T: AeadUnsealer + ?Sized> AeadUnsealer for Arc<T> {
    fn unseal<'a>(
        &'a self,
        cipher_match: Option<&'a CipherMatch<'a>>,
        bundle: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.as_ref().unseal(cipher_match, bundle, aad)
    }
}

/// A bundle wrapper over an AEAD cipher using the v1 format:
/// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
///
/// The implementations are conditional on the inner type's capabilities:
/// wrapping an [`AeadCipher`] (a symmetric key, a rotating multi-key stack, or
/// a KMS-backed cipher that handles both directions as one consistent object)
/// yields an [`AeadSealerUnsealer`]; an [`AeadEncryptorSelector`] alone yields
/// only an [`AeadSealer`], and a decrypt-only [`AeadDecryptor`] (e.g. a
/// retired rotation key) only an [`AeadUnsealer`]. Each `seal` selects a
/// frozen encryptor snapshot internally, so a rotation landing mid-seal cannot
/// split one bundle across two keys.
///
/// # Example
///
/// ```
/// # use std::borrow::Cow;
/// # use huskarl_core::crypto::KeyMatchStrength;
/// # use std::sync::Arc;
/// # use huskarl_core::crypto::cipher::{
/// #     AeadDecryptor, AeadEncryptor, AeadEncryptorSelector, AeadOutput, AeadSealer,
/// #     AeadUnsealer, AeadV1Cipher, CipherMatch, DecryptError,
/// # };
/// # use huskarl_core::error::Error;
/// # use huskarl_core::platform::MaybeSendBoxFuture;
/// # // Stand-in for the AEAD key a crypto backend (native / WebCrypto) provides:
/// # // the key is a selector handing out its shared inner encryptor.
/// # #[derive(Debug)]
/// # struct BackendEncryptor;
/// # impl AeadEncryptor for BackendEncryptor {
/// #     fn enc_algorithm(&self) -> Cow<'_, str> { "A256GCM".into() }
/// #     fn key_id(&self) -> Option<Cow<'_, str>> { None }
/// #     fn encrypt<'a>(&'a self, plaintext: &'a [u8], _aad: &'a [u8])
/// #         -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
/// #         let ciphertext = plaintext.to_vec();
/// #         Box::pin(async move { Ok(AeadOutput { nonce: vec![7], ciphertext, tag: vec![9] }) })
/// #     }
/// # }
/// # #[derive(Debug)]
/// # struct BackendCipher { inner: Arc<BackendEncryptor> }
/// # impl BackendCipher {
/// #     fn new() -> Self { Self { inner: Arc::new(BackendEncryptor) } }
/// # }
/// # impl AeadEncryptorSelector for BackendCipher {
/// #     fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
/// #         let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
/// #         Box::pin(async move { snapshot })
/// #     }
/// # }
/// # impl AeadDecryptor for BackendCipher {
/// #     fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
/// #         Some(KeyMatchStrength::ByAlgorithm)
/// #     }
/// #     fn decrypt<'a>(&'a self, _cm: Option<&'a CipherMatch<'a>>, _nonce: &'a [u8],
/// #         ciphertext: &'a [u8], _tag: &'a [u8], _aad: &'a [u8])
/// #         -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
/// #         let plaintext = ciphertext.to_vec();
/// #         Box::pin(async move { Ok(plaintext) })
/// #     }
/// # }
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cipher = AeadV1Cipher::new(BackendCipher::new());
///
/// // `seal` packs the version byte, nonce, tag and ciphertext into one bundle...
/// let bundle = cipher.seal(b"session-state", b"aad").await?;
/// // ...that `unseal` re-opens with only the bundle and the same aad.
/// let recovered = cipher.unseal(None, &bundle, b"aad").await?;
/// assert_eq!(recovered, b"session-state");
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct AeadV1Cipher<C>(C);

impl<C> AeadV1Cipher<C> {
    /// Wraps a cipher in the v1 bundle format.
    pub fn new(cipher: C) -> Self {
        Self(cipher)
    }
}

impl<C: AeadEncryptorSelector> AeadSealer for AeadV1Cipher<C> {
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            // One frozen snapshot per seal: under rotation, the key that seals
            // is the key any metadata read off the same snapshot names.
            let output = self
                .0
                .select_encryptor()
                .await
                .encrypt(plaintext, aad)
                .await?;

            let nonce_len: u8 = output.nonce.len().try_into().map_err(|_| {
                Error::new(crate::ErrorKind::Crypto, "nonce length exceeds u8::MAX")
            })?;
            let tag_len: u8 =
                output.tag.len().try_into().map_err(|_| {
                    Error::new(crate::ErrorKind::Crypto, "tag length exceeds u8::MAX")
                })?;

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

fn invalid_bundle() -> Error {
    Error::new(ErrorKind::Crypto, UnsealError::InvalidBundle)
}

impl<C: AeadDecryptor> AeadUnsealer for AeadV1Cipher<C> {
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

            self.0
                .decrypt(cipher_match, nonce, ciphertext, tag, aad)
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

    /// Raw-key shape: a selector handing out its shared inner encryptor.
    #[derive(Debug)]
    struct MockKey {
        inner: Arc<MockEncryptor>,
    }

    impl MockKey {
        fn new() -> Self {
            Self {
                inner: Arc::new(MockEncryptor),
            }
        }
    }

    impl AeadEncryptorSelector for MockKey {
        fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
            let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
            Box::pin(async move { snapshot })
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

    /// One object with both capabilities (the symmetric-key / KMS shape).
    #[derive(Debug)]
    struct MockCipher {
        inner: Arc<MockEncryptor>,
    }

    impl MockCipher {
        fn new() -> Self {
            Self {
                inner: Arc::new(MockEncryptor),
            }
        }
    }

    impl AeadEncryptorSelector for MockCipher {
        fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
            let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
            Box::pin(async move { snapshot })
        }
    }

    impl AeadDecryptor for MockCipher {
        fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
            MockDecryptor.cipher_match(m)
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
                MockDecryptor
                    .decrypt(cipher_match, nonce, ciphertext, tag, aad)
                    .await
            })
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

        let sealer = AeadV1Cipher::new(MockKey::new());
        let bundle = sealer.seal(plaintext, aad).await.unwrap();

        let unsealer = AeadV1Cipher::new(MockDecryptor);
        let recovered = unsealer.unseal(None, &bundle, aad).await.unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn erased_cipher_roundtrip() {
        let sealer: Arc<dyn AeadSealer> = Arc::new(AeadV1Cipher::new(MockKey::new()));
        let bundle = sealer.seal(b"hello", b"").await.unwrap();

        let unsealer: Arc<dyn AeadUnsealer> = Arc::new(AeadV1Cipher::new(MockDecryptor));
        let recovered = unsealer.unseal(None, &bundle, b"").await.unwrap();
        assert_eq!(recovered, b"hello");
    }

    /// The erased combined type must satisfy generic `S: AeadSealerUnsealer`
    /// bounds (e.g. `SealedTimestampNonce`) — construction, not just method calls.
    #[tokio::test]
    async fn erased_sealer_unsealer_satisfies_combined_bound() {
        fn assert_combined<S: AeadSealerUnsealer>(s: S) -> S {
            s
        }

        let cipher: Arc<dyn AeadSealerUnsealer> = Arc::new(AeadV1Cipher::new(MockCipher::new()));
        let cipher = assert_combined(cipher);
        let bundle = cipher.seal(b"hello", b"aad").await.unwrap();
        let recovered = cipher.unseal(None, &bundle, b"aad").await.unwrap();
        assert_eq!(recovered, b"hello");
    }

    #[tokio::test]
    async fn bundle_format() {
        let plaintext = b"AB";
        let sealer = AeadV1Cipher::new(MockKey::new());
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
        let unsealer = AeadV1Cipher::new(MockDecryptor);
        let err = unsealer.unseal(None, &[0x02, 0, 0], b"").await.unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_too_short() {
        let unsealer = AeadV1Cipher::new(MockDecryptor);
        let err = unsealer.unseal(None, &[0x01], b"").await.unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_truncated() {
        let unsealer = AeadV1Cipher::new(MockDecryptor);
        // nonce_len=10, tag_len=10, but only 1 byte of data after header
        let err = unsealer
            .unseal(None, &[0x01, 10, 10, 0x00], b"")
            .await
            .unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_empty() {
        let unsealer = AeadV1Cipher::new(MockDecryptor);
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
