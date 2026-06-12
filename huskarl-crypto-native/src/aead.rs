//! AEAD encryptor/decryptor implementations.

use std::{array::TryFromSliceError, borrow::Cow, fmt};

use aes_gcm::{AeadInOut, KeyInit, aead::Generate};
use huskarl_core::{
    Error, ErrorKind,
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadOutput, CipherMatch, DecryptError},
    },
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes},
};
use sha2::digest::array::Array;
use snafu::prelude::*;

/// The type of key to generate.
pub enum AesGcmKeyType {
    /// AES-GCM-128
    Aes128,
    /// AES-GCM-256
    Aes256,
}

enum NativeKey {
    Aes128(Box<aes_gcm::Aes128Gcm>),
    Aes256(Box<aes_gcm::Aes256Gcm>),
}

impl NativeKey {
    pub fn enc_algorithm(&self) -> &'static str {
        match self {
            NativeKey::Aes128(_) => "A128GCM",
            NativeKey::Aes256(_) => "A256GCM",
        }
    }
}

/// An AES-GCM key.
pub struct AesGcmKey {
    inner: NativeKey,
    kid: Option<String>,
}

impl fmt::Debug for AesGcmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmKey")
            .field("enc", &self.inner.enc_algorithm())
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Errors that can occur when loading a key.
#[derive(Debug, Snafu)]
pub enum LoadKeyError {
    /// There was an error fetching the secret.
    Secret {
        /// The underlying error.
        source: Error,
    },
    /// The key had the incorrect length;
    InvalidKeyLength,
}

impl AesGcmKey {
    /// Load a key from a secret.
    ///
    /// # Errors
    ///
    /// Fails if the key could not be loaded from the secret.
    pub async fn from_secret<S: Secret<Output = SecretBytes>>(
        key_type: AesGcmKeyType,
        secret: S,
        kid_from_identity: impl Fn(Option<&str>) -> Option<String>,
    ) -> Result<Self, LoadKeyError> {
        let key_source = secret.get_secret_value().await.context(SecretSnafu)?;

        let inner = match key_type {
            AesGcmKeyType::Aes128 => NativeKey::Aes128(Box::new(
                aes_gcm::Aes128Gcm::new_from_slice(key_source.value.expose_secret())
                    .map_err(|_| InvalidKeyLengthSnafu.build())?,
            )),
            AesGcmKeyType::Aes256 => NativeKey::Aes256(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(key_source.value.expose_secret())
                    .map_err(|_| InvalidKeyLengthSnafu.build())?,
            )),
        };

        Ok(AesGcmKey {
            inner,
            kid: kid_from_identity(key_source.identity.as_deref()),
        })
    }
}

/// Errors that can occur during AEAD operations.
#[derive(Debug, Snafu)]
pub enum AesGcmError {
    /// An error occurred when decrypting the ciphertext.
    Decrypt {
        /// The underlying error.
        source: aes_gcm::Error,
    },
    /// An error occurred when encrypting the plaintext.
    Encrypt {
        /// The underlying error.
        source: aes_gcm::Error,
    },
    /// The supplied nonce had an invalid length.
    InvalidNonce {
        /// The underlying error.
        source: TryFromSliceError,
    },
    /// The supplied tag had an invalid length.
    InvalidTag {
        /// The underlying error.
        source: TryFromSliceError,
    },
}

impl From<AesGcmError> for Error {
    fn from(value: AesGcmError) -> Self {
        Error::new(ErrorKind::Crypto, value)
    }
}

impl From<AesGcmError> for DecryptError {
    fn from(value: AesGcmError) -> Self {
        Error::from(value).into()
    }
}

impl AeadEncryptor for AesGcmKey {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.inner.enc_algorithm())
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.kid.as_deref().map(Cow::Borrowed)
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        Box::pin(async move {
            let nonce = Array::generate();
            let mut ciphertext = plaintext.to_vec();

            let tag = match &self.inner {
                NativeKey::Aes128(aes_gcm) => {
                    aes_gcm.encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
                }
                NativeKey::Aes256(aes_gcm) => {
                    aes_gcm.encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
                }
            }
            .context(EncryptSnafu)?;

            Ok(AeadOutput {
                nonce: nonce.into(),
                ciphertext,
                tag: tag.into(),
            })
        })
    }
}

impl AeadDecryptor for AesGcmKey {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        m.strength_for(self.inner.enc_algorithm(), self.kid.as_deref())
    }

    fn decrypt<'a>(
        &'a self,
        _cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            let nonce = nonce.try_into().context(InvalidNonceSnafu)?;
            let tag = tag.try_into().context(InvalidTagSnafu)?;
            let mut plaintext = ciphertext.to_vec();

            match &self.inner {
                NativeKey::Aes128(aes_gcm) => aes_gcm.decrypt_inout_detached(
                    &nonce,
                    aad,
                    plaintext.as_mut_slice().into(),
                    &tag,
                ),
                NativeKey::Aes256(aes_gcm) => aes_gcm.decrypt_inout_detached(
                    &nonce,
                    aad,
                    plaintext.as_mut_slice().into(),
                    &tag,
                ),
            }
            .context(DecryptSnafu)?;

            Ok(plaintext)
        })
    }
}
