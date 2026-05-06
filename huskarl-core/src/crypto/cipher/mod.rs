//! Cipher implementations for encryption and decryption.

mod boxed;
mod error;

use std::borrow::Cow;

use snafu::ensure;

pub use boxed::{BoxedAeadDecryptor, BoxedAeadEncryptor};
pub(crate) use error::InvalidBundleSnafu;
pub use error::UnsealError;

use crate::{
    crypto::KeyMatchStrength,
    platform::{MaybeSend, MaybeSendSync},
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
#[derive(Debug, Clone, Copy)]
pub struct CipherMatch<'a> {
    /// The content encryption algorithm (e.g. from the JWE `enc` header).
    /// When `None`, the algorithm is not used for matching.
    pub enc: Option<&'a str>,
    /// The key ID (e.g. from the JWE `kid` header or an out-of-band source).
    pub kid: Option<&'a str>,
}

/// Trait for AEAD encryption.
pub trait AeadEncryptor: MaybeSendSync {
    /// The error type returned by encryption operations.
    type Error: crate::Error;

    /// Returns the content encryption algorithm identifier (e.g. `A256GCM`).
    fn enc_algorithm(&self) -> Cow<'_, str>;

    /// Returns the key ID for this encryptor, if any.
    fn key_id(&self) -> Option<Cow<'_, str>>;

    /// Asynchronously encrypts the given plaintext with the associated data.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the encryption operation fails.
    fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<AeadOutput, Self::Error>> + MaybeSend;
}

/// Trait for AEAD decryption.
///
/// Exposes key selection via [`cipher_match`](Self::cipher_match) so that
/// multi-key types can dispatch to the correct decryptor.
pub trait AeadDecryptor: MaybeSendSync {
    /// The error type returned by decryption operations.
    type Error: crate::Error;

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
    /// Returns [`Self::Error`] if the decryption operation fails or if the data was tampered with.
    fn decrypt(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// A selector for an AEAD encryptor.
///
/// Returns an encryptor with fixed identity and key material. The resulting
/// encryptor should be held for a short period of time, as longer periods
/// would work against system policies like key rotation.
pub trait AeadCipherSelector: MaybeSendSync {
    /// The type of encryptor returned by this selector.
    type Encryptor: AeadEncryptor;

    /// Selects the current encryptor to use for encryption.
    fn select_cipher(&self) -> Self::Encryptor;
}

/// An encryptor that produces self-contained bundles with a prepended version byte and IV.
pub trait AeadSealer: AeadEncryptor {
    /// Encrypts `plaintext` and returns a versioned bundle:
    /// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
    fn seal(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// A decryptor that consumes self-contained bundles produced by [`AeadSealer`].
pub trait AeadUnsealer: AeadDecryptor {
    /// Decrypts a versioned bundle produced by [`AeadSealer::seal`].
    ///
    /// `cipher_match` carries optional key selection criteria from an out-of-band
    /// source (e.g. a cookie attribute or database column). Multi-key decryptors
    /// use this to select the correct key without trying all candidates.
    fn unseal(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        bundle: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// An [`AeadSealer`] using the v1 bundle format:
/// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
pub struct AeadV1Sealer<E: AeadEncryptor>(E);

impl<E: AeadEncryptor> AeadV1Sealer<E> {
    /// Creates a new sealer.
    pub fn new(encryptor: E) -> Self {
        Self(encryptor)
    }
}

impl<E: AeadEncryptor> AeadEncryptor for AeadV1Sealer<E> {
    type Error = E::Error;

    fn enc_algorithm(&self) -> Cow<'_, str> {
        self.0.enc_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.0.key_id()
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AeadOutput, Self::Error> {
        self.0.encrypt(plaintext, aad).await
    }
}

impl<E: AeadEncryptor> AeadSealer for AeadV1Sealer<E> {
    async fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Self::Error> {
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

        let mut bundle =
            Vec::with_capacity(3 + output.nonce.len() + output.ciphertext.len() + output.tag.len());
        bundle.push(0x01);
        bundle.push(nonce_len);
        bundle.push(tag_len);
        bundle.extend_from_slice(&output.nonce);
        bundle.extend_from_slice(&output.ciphertext);
        bundle.extend_from_slice(&output.tag);

        Ok(bundle)
    }
}

/// An [`AeadUnsealer`] using the v1 bundle format:
/// `[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`.
pub struct AeadV1Unsealer<D: AeadDecryptor>(D);

impl<D: AeadDecryptor> AeadV1Unsealer<D> {
    /// Creates a new unsealer.
    pub fn new(decryptor: D) -> Self {
        Self(decryptor)
    }
}

impl<D: AeadDecryptor> AeadDecryptor for AeadV1Unsealer<D> {
    type Error = UnsealError<D::Error>;

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.0.cipher_match(m)
    }

    async fn decrypt(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.0
            .decrypt(cipher_match, nonce, ciphertext, tag, aad)
            .await
            .map_err(Into::into)
    }
}

impl<D: AeadDecryptor> AeadUnsealer for AeadV1Unsealer<D> {
    async fn unseal(
        &self,
        cipher_match: Option<&CipherMatch<'_>>,
        bundle: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        ensure!(bundle.len() >= 3 && bundle[0] == 0x01, InvalidBundleSnafu);

        let nonce_len = bundle[1] as usize;
        let tag_len = bundle[2] as usize;

        ensure!(bundle.len() >= 3 + nonce_len + tag_len, InvalidBundleSnafu);

        let nonce = &bundle[3..3 + nonce_len];
        let tag = &bundle[bundle.len() - tag_len..];
        let ciphertext = &bundle[3 + nonce_len..bundle.len() - tag_len];

        self.decrypt(cipher_match, nonce, ciphertext, tag, aad)
            .await
    }
}
