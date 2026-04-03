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

/// The output from [`AeadEncryptor::encrypt_with_iv`]
pub struct AeadOutput {
    /// The ciphertext resulting from the encryption.
    pub ciphertext: Vec<u8>,
    /// The authentication tag resulting from the encryption.
    pub tag: Vec<u8>,
}

/// The set of JWE header parameters used to select a content decryption key.
#[derive(Debug, Clone, Copy)]
pub struct CipherMatch<'a> {
    /// The content encryption algorithm (`enc`) from the JWE header.
    pub enc: &'a str,
    /// The key ID (`kid`) from the JWE header.
    pub kid: Option<&'a str>,
}

/// Shared parameters for an AEAD key, independent of direction.
///
/// Both [`AeadEncryptor`] and [`AeadDecryptor`] require this, ensuring that
/// IV and tag lengths are defined once and consistent across both directions.
pub trait AeadKey: MaybeSendSync {
    /// Returns the required IV length in bytes.
    fn iv_length(&self) -> usize;

    /// Returns the authentication tag length in bytes.
    fn tag_length(&self) -> usize;
}

/// Trait for AEAD encryption.
///
/// Exposes the algorithm identifier and key ID so that callers can construct
/// JWE headers or bundle metadata without needing a separate key description.
pub trait AeadEncryptor: AeadKey {
    /// The error type returned by encryption operations.
    type Error: crate::Error;

    /// Returns the content encryption algorithm identifier (e.g. `A256GCM`).
    fn enc_algorithm(&self) -> Cow<'_, str>;

    /// Returns the key ID for this encryptor, if any.
    fn key_id(&self) -> Option<Cow<'_, str>>;

    /// Asynchronously encrypts the given plaintext with the provided IV and associated data.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the encryption operation fails.
    fn encrypt_with_iv(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<AeadOutput, Self::Error>> + MaybeSend;
}

/// Trait for AEAD decryption.
///
/// Exposes key selection via [`cipher_match`](Self::cipher_match) so that
/// multi-key types can dispatch to the correct decryptor.
pub trait AeadDecryptor: AeadKey {
    /// The error type returned by decryption operations.
    type Error: crate::Error;

    /// Returns how well this decryptor matches the given selection criteria.
    ///
    /// Implementations must return:
    ///
    /// - `Some(ByKeyId)` — the algorithm matches **and** both the header and this decryptor
    ///   have a `kid`, and they are equal.
    /// - `Some(ByAlgorithm)` — the algorithm matches, but the `kid` could not be used for
    ///   matching: either the header has no `kid`, or this decryptor has no `kid` registered.
    /// - `None` — the algorithm is unsupported by this decryptor, **or** both the header and
    ///   this decryptor have a `kid` but they differ.
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength>;

    /// Asynchronously decrypts the given ciphertext with the provided IV, tag, and associated data.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the decryption operation fails or if the data was tampered with.
    fn decrypt_with_iv(
        &self,
        iv: &[u8],
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
    /// Encrypts `plaintext` and returns a versioned bundle: `[0x01 || IV || ciphertext || tag]`.
    fn seal(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// A decryptor that consumes self-contained bundles produced by [`AeadSealer`].
pub trait AeadUnsealer: AeadDecryptor {
    /// Decrypts a versioned bundle produced by [`AeadSealer::seal`].
    fn unseal(
        &self,
        bundle: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// An [`AeadSealer`] using the v1 bundle format: `[0x01 || IV || ciphertext || tag]`.
pub struct AeadV1Sealer<E: AeadEncryptor>(E);

impl<E: AeadEncryptor> AeadV1Sealer<E> {
    /// Creates a new sealer.
    pub fn new(encryptor: E) -> Self {
        Self(encryptor)
    }
}

impl<E: AeadEncryptor> AeadKey for AeadV1Sealer<E> {
    fn iv_length(&self) -> usize {
        self.0.iv_length()
    }

    fn tag_length(&self) -> usize {
        self.0.tag_length()
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

    async fn encrypt_with_iv(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<AeadOutput, Self::Error> {
        self.0.encrypt_with_iv(iv, plaintext, aad).await
    }
}

impl<E: AeadEncryptor> AeadSealer for AeadV1Sealer<E> {
    async fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let iv_len = self.iv_length();
        let tag_len = self.tag_length();

        let mut iv = vec![0u8; iv_len];
        rand::fill(&mut iv);

        let output = self.encrypt_with_iv(&iv, plaintext, aad).await?;

        let mut bundle = Vec::with_capacity(1 + iv_len + output.ciphertext.len() + tag_len);
        bundle.push(0x01);
        bundle.extend_from_slice(&iv);
        bundle.extend_from_slice(&output.ciphertext);
        bundle.extend_from_slice(&output.tag);

        Ok(bundle)
    }
}

/// An [`AeadUnsealer`] using the v1 bundle format: `[0x01 || IV || ciphertext || tag]`.
pub struct AeadV1Unsealer<D: AeadDecryptor>(D);

impl<D: AeadDecryptor> AeadV1Unsealer<D> {
    /// Creates a new unsealer.
    pub fn new(decryptor: D) -> Self {
        Self(decryptor)
    }
}

impl<D: AeadDecryptor> AeadKey for AeadV1Unsealer<D> {
    fn iv_length(&self) -> usize {
        self.0.iv_length()
    }

    fn tag_length(&self) -> usize {
        self.0.tag_length()
    }
}

impl<D: AeadDecryptor> AeadDecryptor for AeadV1Unsealer<D> {
    type Error = UnsealError<D::Error>;

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        self.0.cipher_match(m)
    }

    async fn decrypt_with_iv(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.0
            .decrypt_with_iv(iv, ciphertext, tag, aad)
            .await
            .map_err(Into::into)
    }
}

impl<D: AeadDecryptor> AeadUnsealer for AeadV1Unsealer<D> {
    async fn unseal(&self, bundle: &[u8], aad: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let iv_len = self.iv_length();
        let tag_len = self.tag_length();

        ensure!(
            bundle.len() >= 1 + iv_len + tag_len && bundle[0] == 0x01,
            InvalidBundleSnafu
        );

        let iv = &bundle[1..1 + iv_len];
        let tag = &bundle[bundle.len() - tag_len..];
        let ciphertext = &bundle[1 + iv_len..bundle.len() - tag_len];

        self.decrypt_with_iv(iv, ciphertext, tag, aad).await
    }
}
