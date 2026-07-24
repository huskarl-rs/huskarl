//! Sealing: encrypt a value into one opaque, self-contained bundle and re-open
//! it later — a convenience layer over [`cipher`](crate::crypto::cipher) for
//! values that travel on their own (encrypted cookies, stateless tokens). See
//! [composing crypto strategies](crate::_docs::explanation::crypto_strategies)
//! for how it relates to JWE and the parts-level cipher traits.

use std::{borrow::Cow, sync::Arc};

use snafu::Snafu;

use crate::{
    crypto::cipher::{AeadDecryptor, AeadEncryptorSelector, CipherMatch, DecryptError},
    error::{Error, ErrorKind},
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// Errors that could occur during AEAD unsealing.
///
/// Used as the source of [`ErrorKind::Crypto`] errors — sealer implementations
/// construct these to describe *why* an unseal
/// failed without expanding the kind-level vocabulary.
///
/// This covers only failures the framing layer itself detects. An
/// authentication-tag mismatch is raised by the inner
/// [`AeadDecryptor`] and flows through as
/// [`DecryptError::Other`], not as an `UnsealError`.
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum UnsealError {
    /// The bundle is malformed or uses an unsupported version.
    #[snafu(display("invalid bundle"))]
    InvalidBundle,
}

/// The output from [`AeadSealer::seal`]
pub struct SealOutput {
    /// The opaque, self-describing bundle.
    pub bundle: Vec<u8>,
    /// The key ID of the key that sealed, when the implementation tracks one.
    pub kid: Option<String>,
}

/// An encryptor that produces self-contained bundles.
///
/// Where [`AeadEncryptor::encrypt`](crate::crypto::cipher::AeadEncryptor::encrypt)
/// returns the nonce, ciphertext, and tag as separate fields, a sealer hands
/// back one opaque byte string so the value can travel on its own — an
/// encrypted cookie, a stateless token — and be re-opened later
/// ([`AeadUnsealer`]) with just the bundle and the key. [`AeadV1Sealer`] is the
/// local implementation; see it for a worked example.
///
/// This trait is dyn-capable: consumers store it as `Arc<dyn AeadSealer>`, or
/// as `Arc<dyn AeadSealerUnsealer>` when both directions are needed.
pub trait AeadSealer: std::fmt::Debug + MaybeSendSync {
    /// Encrypts `plaintext` into a [`SealOutput`]: an opaque, self-describing
    /// bundle that a matching [`AeadUnsealer`] can re-open, plus the kid of
    /// the key that sealed it, when the implementation tracks one. The bundle
    /// layout belongs to the implementation — an externally-managed sealer
    /// returns its service's token verbatim.
    ///
    /// Store the kid beside the bundle for direct key dispatch in
    /// [`unseal`](AeadUnsealer::unseal); discarding it is equally valid.
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<SealOutput, Error>>;
}

/// A decryptor that consumes self-contained bundles produced by [`AeadSealer`].
///
/// This trait is dyn-capable: consumers store it as `Arc<dyn AeadUnsealer>`, or
/// as `Arc<dyn AeadSealerUnsealer>` when both directions are needed.
pub trait AeadUnsealer: std::fmt::Debug + MaybeSendSync {
    /// Decrypts a bundle produced by [`AeadSealer::seal`].
    ///
    /// `kid` is the key ID [`seal`](AeadSealer::seal) returned with the
    /// bundle, if the caller stored it: multi-key implementations use it to
    /// select the key directly. `None` is always safe — the AEAD tag makes a
    /// wrong key a clean failure. A kid only selects, so an untrusted value
    /// can at worst cause a miss.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError::NoMatchingKey`] if no key matched the given
    /// `kid`; all other failures — malformed bundles, authentication
    /// failure — classify as [`ErrorKind::Crypto`] via [`DecryptError::Other`].
    fn unseal<'a>(
        &'a self,
        bundle: &'a [u8],
        aad: &'a [u8],
        kid: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>>;
}

/// Combined trait for types that can both seal and unseal.
///
/// Automatically implemented for any type with both capabilities. Store as
/// `Arc<dyn AeadSealerUnsealer>` when both directions must come from the same
/// source — an [`AeadV1Sealer`] over one key, or an externally-managed sealer
/// (e.g. a KMS/Vault encrypt endpoint) whose tokens only it can re-open.
pub trait AeadSealerUnsealer: AeadSealer + AeadUnsealer {}

impl<T: AeadSealer + AeadUnsealer + ?Sized> AeadSealerUnsealer for T {}

impl<T: AeadSealer + ?Sized> AeadSealer for Arc<T> {
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<SealOutput, Error>> {
        self.as_ref().seal(plaintext, aad)
    }
}

impl<T: AeadUnsealer + ?Sized> AeadUnsealer for Arc<T> {
    fn unseal<'a>(
        &'a self,
        bundle: &'a [u8],
        aad: &'a [u8],
        kid: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        self.as_ref().unseal(bundle, aad, kid)
    }
}

/// A bundle wrapper over an AEAD cipher using the v1 format:
/// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
///
/// The implementations are conditional on the inner type's capabilities:
/// wrapping an [`AeadCipher`](crate::crypto::cipher::AeadCipher) (a symmetric
/// key, a rotating multi-key stack, or a KMS-backed cipher that handles both
/// directions as one consistent object) yields an [`AeadSealerUnsealer`]; an
/// [`AeadEncryptorSelector`] alone yields only an [`AeadSealer`], and a
/// decrypt-only [`AeadDecryptor`] (e.g. a retired rotation key) only an
/// [`AeadUnsealer`]. Each `seal` selects a frozen encryptor snapshot
/// internally, so a rotation landing mid-seal cannot split one bundle across
/// two keys.
///
/// # Example
///
/// ```
/// # use std::borrow::Cow;
/// # use huskarl_core::crypto::KeyMatchStrength;
/// # use std::sync::Arc;
/// # use huskarl_core::crypto::cipher::{
/// #     AeadDecryptor, AeadEncryptor, AeadEncryptorSelector, AeadOutput, CipherMatch, DecryptError,
/// # };
/// # use huskarl_core::crypto::seal::{AeadSealer, AeadUnsealer, AeadV1Sealer, SealOutput};
/// # use huskarl_core::error::Error;
/// # use huskarl_core::platform::MaybeSendBoxFuture;
/// # // Stand-in for the AEAD key a crypto backend (native / WebCrypto) provides:
/// # // the key is a selector handing out its shared inner encryptor.
/// # #[derive(Debug)]
/// # struct BackendEncryptor;
/// # impl AeadEncryptor for BackendEncryptor {
/// #     fn enc_algorithm(&self) -> Cow<'_, str> { "A256GCM".into() }
/// #     fn key_id(&self) -> Option<Cow<'_, str>> { Some("2026-07".into()) }
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
/// let cipher = AeadV1Sealer::new(BackendCipher::new());
///
/// // `seal` packs the version byte, nonce, tag and ciphertext into one
/// // bundle, plus the kid of the key that sealed it...
/// let SealOutput { bundle, kid } = cipher.seal(b"session-state", b"aad").await?;
/// // ...which dispatches `unseal` straight to that key (`None` tries all).
/// let recovered = cipher.unseal(&bundle, b"aad", kid.as_deref()).await?;
/// assert_eq!(recovered, b"session-state");
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct AeadV1Sealer<C>(C);

impl<C> AeadV1Sealer<C> {
    /// Wraps a cipher in the v1 bundle format.
    pub fn new(cipher: C) -> Self {
        Self(cipher)
    }
}

impl<C: AeadEncryptorSelector> AeadSealer for AeadV1Sealer<C> {
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<SealOutput, Error>> {
        Box::pin(async move {
            // One frozen snapshot per seal: under rotation, the returned kid
            // names exactly the key that sealed.
            let encryptor = self.0.select_encryptor().await;
            let kid = encryptor.key_id().map(Cow::into_owned);
            let output = encryptor.encrypt(plaintext, aad).await?;

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

            Ok(SealOutput { bundle, kid })
        })
    }
}

fn invalid_bundle() -> Error {
    Error::new(ErrorKind::Crypto, UnsealError::InvalidBundle)
}

impl<C: AeadDecryptor> AeadUnsealer for AeadV1Sealer<C> {
    fn unseal<'a>(
        &'a self,
        bundle: &'a [u8],
        aad: &'a [u8],
        kid: Option<&'a str>,
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

            let cipher_match = kid.map(|kid| CipherMatch::builder().kid(kid).build());

            self.0
                .decrypt(cipher_match.as_ref(), nonce, ciphertext, tag, aad)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        KeyMatchStrength,
        cipher::{AeadEncryptor, AeadOutput},
    };

    #[derive(Debug)]
    struct MockEncryptor;

    impl AeadEncryptor for MockEncryptor {
        fn enc_algorithm(&self) -> Cow<'_, str> {
            "mock".into()
        }

        fn key_id(&self) -> Option<Cow<'_, str>> {
            Some("mock-kid".into())
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
            panic!("expected DecryptError::Other, got {err:?}");
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

        let sealer = AeadV1Sealer::new(MockKey::new());
        let SealOutput { bundle, kid } = sealer.seal(plaintext, aad).await.unwrap();
        assert_eq!(kid.as_deref(), Some("mock-kid"));

        let unsealer = AeadV1Sealer::new(MockDecryptor);
        let recovered = unsealer.unseal(&bundle, aad, kid.as_deref()).await.unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn erased_cipher_roundtrip() {
        let sealer: Arc<dyn AeadSealer> = Arc::new(AeadV1Sealer::new(MockKey::new()));
        let SealOutput { bundle, .. } = sealer.seal(b"hello", b"").await.unwrap();

        let unsealer: Arc<dyn AeadUnsealer> = Arc::new(AeadV1Sealer::new(MockDecryptor));
        let recovered = unsealer.unseal(&bundle, b"", None).await.unwrap();
        assert_eq!(recovered, b"hello");
    }

    /// The erased combined type must satisfy generic `S: AeadSealerUnsealer`
    /// bounds (e.g. `SealedTimestampNonce`) — construction, not just method calls.
    #[tokio::test]
    async fn erased_sealer_unsealer_satisfies_combined_bound() {
        fn assert_combined<S: AeadSealerUnsealer>(s: S) -> S {
            s
        }

        let cipher: Arc<dyn AeadSealerUnsealer> = Arc::new(AeadV1Sealer::new(MockCipher::new()));
        let cipher = assert_combined(cipher);
        let SealOutput { bundle, .. } = cipher.seal(b"hello", b"aad").await.unwrap();
        let recovered = cipher.unseal(&bundle, b"aad", None).await.unwrap();
        assert_eq!(recovered, b"hello");
    }

    #[tokio::test]
    async fn bundle_format() {
        let plaintext = b"AB";
        let sealer = AeadV1Sealer::new(MockKey::new());
        let SealOutput { bundle, .. } = sealer.seal(plaintext, b"").await.unwrap();

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
        let unsealer = AeadV1Sealer::new(MockDecryptor);
        let err = unsealer.unseal(&[0x02, 0, 0], b"", None).await.unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_too_short() {
        let unsealer = AeadV1Sealer::new(MockDecryptor);
        let err = unsealer.unseal(&[0x01], b"", None).await.unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_truncated() {
        let unsealer = AeadV1Sealer::new(MockDecryptor);
        // nonce_len=10, tag_len=10, but only 1 byte of data after header
        let err = unsealer
            .unseal(&[0x01, 10, 10, 0x00], b"", None)
            .await
            .unwrap_err();
        assert_invalid_bundle(&err);
    }

    #[tokio::test]
    async fn unseal_empty() {
        let unsealer = AeadV1Sealer::new(MockDecryptor);
        let err = unsealer.unseal(&[], b"", None).await.unwrap_err();
        assert_invalid_bundle(&err);
    }

    /// The kid handed to `unseal` must reach the inner decryptor as a
    /// kid-only [`CipherMatch`]; `None` must arrive as no criteria at all.
    #[tokio::test]
    async fn unseal_forwards_kid_as_cipher_match() {
        #[derive(Debug)]
        struct KidAssertingDecryptor {
            expected: Option<&'static str>,
        }

        impl AeadDecryptor for KidAssertingDecryptor {
            fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
                Some(KeyMatchStrength::ByAlgorithm)
            }

            fn decrypt<'a>(
                &'a self,
                cipher_match: Option<&'a CipherMatch<'a>>,
                _nonce: &'a [u8],
                ciphertext: &'a [u8],
                _tag: &'a [u8],
                _aad: &'a [u8],
            ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
                assert_eq!(cipher_match.and_then(|m| m.kid), self.expected);
                assert_eq!(cipher_match.and_then(|m| m.enc), None);
                Box::pin(async move { Ok(ciphertext.to_vec()) })
            }
        }

        let SealOutput { bundle, .. } = AeadV1Sealer::new(MockKey::new())
            .seal(b"x", b"")
            .await
            .unwrap();
        for (unsealer, kid) in [
            (
                AeadV1Sealer::new(KidAssertingDecryptor {
                    expected: Some("mock-kid"),
                }),
                Some("mock-kid"),
            ),
            (
                AeadV1Sealer::new(KidAssertingDecryptor { expected: None }),
                None,
            ),
        ] {
            unsealer.unseal(&bundle, b"", kid).await.unwrap();
        }
    }
}
