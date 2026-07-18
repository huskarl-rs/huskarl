//! AEAD ciphers, backed by `RustCrypto`.
//!
//! Both implement huskarl-core's
//! [`AeadCipher`](huskarl_core::crypto::cipher::AeadCipher)
//! ([`AeadEncryptorSelector`] + [`AeadDecryptor`]) and are built from a JWK
//! (`from_jwk`) or a secret store (`from_secret`):
//!
//! - [`AesGcmKey`] — `A128GCM`/`A192GCM`/`A256GCM`, chosen by key length;
//!   bounded encryptions per key (see its docs). Mirrored by the `WebCrypto`
//!   backend.
//! - [`XChaChaKey`] — `XC20P`, 256-bit key, 192-bit nonce, no per-key
//!   encryption bound. Native-only: `WebCrypto` has no `ChaCha` primitive.

use std::{array::TryFromSliceError, borrow::Cow, fmt, sync::Arc};

use aes_gcm::{AeadInOut, KeyInit, aead::Generate};
use chacha20poly1305::XChaCha20Poly1305;
use huskarl_core::{
    Error, ErrorKind,
    crypto::{
        KeyMatchStrength,
        cipher::{
            AeadDecryptor, AeadEncryptor, AeadEncryptorSelector, AeadOutput, CipherMatch,
            DecryptError,
        },
    },
    jwk,
    platform::MaybeSendBoxFuture,
    secrets::Secret,
};
use sha2::digest::array::Array;
use snafu::prelude::*;

// aes-gcm ships `Aes128Gcm`/`Aes256Gcm` aliases but not 192; spell it out from
// the re-exported `aes` building blocks (96-bit nonce, like the other two).
type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, aes_gcm::aes::cipher::consts::U12>;

enum NativeKey {
    Aes128(Box<aes_gcm::Aes128Gcm>),
    Aes192(Box<Aes192Gcm>),
    Aes256(Box<aes_gcm::Aes256Gcm>),
}

impl NativeKey {
    pub fn enc_algorithm(&self) -> &'static str {
        match self {
            NativeKey::Aes128(_) => "A128GCM",
            NativeKey::Aes192(_) => "A192GCM",
            NativeKey::Aes256(_) => "A256GCM",
        }
    }
}

/// An AES-GCM AEAD cipher (`RustCrypto`), doing both encryption and decryption.
///
/// Build one with [`from_jwk`](Self::from_jwk) or
/// [`from_secret`](Self::from_secret); the AES-128/192/256 variant follows
/// from the key length. Implements huskarl-core's [`AeadEncryptorSelector`]
/// and [`AeadDecryptor`] — together, an
/// [`AeadCipher`](huskarl_core::crypto::cipher::AeadCipher).
///
/// # Usage bound (NIST SP 800-38D §8.3)
///
/// Each [`encrypt`](AeadEncryptor::encrypt) call draws a fresh random 96-bit
/// nonce, so a single key must perform at most **2^32 encryptions**. The
/// limit keeps the probability of ever repeating a nonce below 2^-32 — a
/// deliberately negligible budget, because even one repeat under GCM is
/// catastrophic (keystream reuse and recovery of the authentication subkey,
/// enabling forgeries on later messages). The bound is cumulative per
/// key material, across restarts and every process sharing the key, so
/// enforce it with a rotation schedule rather than a counter — at a sustained
/// 1,000 encryptions per second, 2^32 is reached in about 50 days. Decryption
/// is not bounded. Rotate by introducing a new key and keeping old ones
/// decrypt-only via
/// [`MultiKeyCipher`](huskarl_core::crypto::cipher::MultiKeyCipher) /
/// [`MultiKeyDecryptor`](huskarl_core::crypto::cipher::MultiKeyDecryptor).
#[derive(Debug, Clone)]
pub struct AesGcmKey {
    inner: Arc<AesGcmKeyInner>,
}

/// The shared key material behind an `AesGcmKey` — the encryptor snapshot
/// `select_encryptor` hands out.
struct AesGcmKeyInner {
    key: NativeKey,
    kid: Option<String>,
}

impl fmt::Debug for AesGcmKeyInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmKeyInner")
            .field("enc", &self.key.enc_algorithm())
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl AesGcmKey {
    /// Constructs a cipher from a [`jwk::SymmetricJwk`].
    ///
    /// The AES-128/192/256 variant follows from the key length (16/24/32
    /// bytes) — unlike an HMAC key, an AES key needs no `alg` to
    /// self-identify. If the JWK does carry an `alg`, it must agree with the
    /// length-selected variant (`A128GCM`/`A192GCM`/`A256GCM`). The `kid`
    /// field, if present, is used as the key ID. Holding a
    /// [`jwk::PrivateJwk`], convert with `try_into()` — the conversion
    /// rejects asymmetric keys.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the key material is not 16, 24, or 32
    /// bytes, or if the JWK's `alg` disagrees with the key length.
    pub fn from_jwk(jwk: jwk::SymmetricJwk) -> Result<Self, Error> {
        // `new_from_slice` cannot fail inside the matched arms, but mapping the
        // error (rather than unwrapping) keeps this panic-free.
        let bad_len = |len: usize| {
            Error::from(ErrorKind::Config).with_context(format!(
                "AES-GCM key material must be 16, 24, or 32 bytes, got {len}"
            ))
        };
        let len = jwk.key.k.len();
        let key = match len {
            16 => NativeKey::Aes128(Box::new(
                aes_gcm::Aes128Gcm::new_from_slice(&jwk.key.k).map_err(|_| bad_len(len))?,
            )),
            24 => NativeKey::Aes192(Box::new(
                Aes192Gcm::new_from_slice(&jwk.key.k).map_err(|_| bad_len(len))?,
            )),
            32 => NativeKey::Aes256(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(&jwk.key.k).map_err(|_| bad_len(len))?,
            )),
            len => return Err(bad_len(len)),
        };

        if let Some(alg) = jwk.algorithm.as_deref()
            && alg != key.enc_algorithm()
        {
            return Err(Error::from(ErrorKind::Config).with_context(format!(
                "JWK algorithm {alg} disagrees with the key length, which selects {}",
                key.enc_algorithm()
            )));
        }

        Ok(AesGcmKey {
            inner: Arc::new(AesGcmKeyInner { key, kid: jwk.kid }),
        })
    }

    /// Finalizes a cipher from a secret that yields a [`jwk::PrivateJwk`].
    ///
    /// The single loading funnel, shared with the signing keys: compose a
    /// decoder onto your secret to reach a `Secret<Output = PrivateJwk>` —
    /// [`jwk::JwkJson`] for a JWK-JSON secret, or [`jwk::OctBytes`] for raw
    /// key bytes — and this resolves it into a usable cipher.
    ///
    /// The key ID follows a clear precedence: an explicit `kid` in the JWK
    /// wins; otherwise the secret's `identity` (e.g. a secret-manager version
    /// name) fills it; otherwise there is none.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the secret cannot be fetched or
    /// decoded, if the JWK is asymmetric rather than symmetric (`oct`), or if
    /// it is not a valid AES-GCM key.
    ///
    /// # Examples
    ///
    /// Load the key from a [`Secret`] source rather than embedding it — here an
    /// environment variable holding base64 key material:
    ///
    /// ```
    /// use huskarl_core::prelude::*; // brings `Secret::mapped` into scope
    /// use huskarl_core::{
    ///     jwk::OctBytes,
    ///     secrets::{EnvVarSecret, encodings::Base64Encoding},
    /// };
    /// use huskarl_crypto_native::aead::AesGcmKey;
    ///
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// // 32 decoded bytes select AES-256-GCM (16 → AES-128, 24 → AES-192).
    /// let key_source = EnvVarSecret::new("AEAD_KEY", &Base64Encoding)?;
    /// let cipher = AesGcmKey::from_secret(key_source.mapped(OctBytes::new("A256GCM"))).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_secret<S: Secret<Output = jwk::PrivateJwk>>(
        secret: S,
    ) -> Result<Self, Error> {
        let output = secret.get_secret_value().await?;
        // Explicit JWK kid > secret identity > none.
        let jwk = output.value.with_kid_fallback(output.identity);
        Self::from_jwk(jwk.try_into()?)
    }
}

/// Errors that can occur during AEAD operations, shared by both native
/// ciphers (`aes-gcm` and `chacha20poly1305` report the same [`aead::Error`]).
#[derive(Debug, Snafu)]
pub enum AeadError {
    /// An error occurred when decrypting the ciphertext.
    Decrypt {
        /// The underlying error.
        source: aead::Error,
    },
    /// An error occurred when encrypting the plaintext.
    Encrypt {
        /// The underlying error.
        source: aead::Error,
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

impl From<AeadError> for Error {
    fn from(value: AeadError) -> Self {
        Error::new(ErrorKind::Crypto, value)
    }
}

impl From<AeadError> for DecryptError {
    fn from(value: AeadError) -> Self {
        Error::from(value).into()
    }
}

impl AeadEncryptorSelector for AesGcmKey {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
        Box::pin(async move { snapshot })
    }
}

impl AeadDecryptor for AesGcmKey {
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
}

impl AeadEncryptor for AesGcmKeyInner {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.key.enc_algorithm())
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

            let tag = match &self.key {
                NativeKey::Aes128(aes_gcm) => {
                    aes_gcm.encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
                }
                NativeKey::Aes192(aes_gcm) => {
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

impl AeadDecryptor for AesGcmKeyInner {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        m.strength_for(self.key.enc_algorithm(), self.kid.as_deref())
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

            match &self.key {
                NativeKey::Aes128(aes_gcm) => aes_gcm.decrypt_inout_detached(
                    &nonce,
                    aad,
                    plaintext.as_mut_slice().into(),
                    &tag,
                ),
                NativeKey::Aes192(aes_gcm) => aes_gcm.decrypt_inout_detached(
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

/// The huskarl `enc` identifier for XChaCha20-Poly1305, taken from the JOSE
/// draft `draft-amringer-jose-chacha`. Not a registered JWE `enc` value — it
/// names the algorithm in huskarl's own sealed-bundle framing only; do not
/// route it through a JWE path.
const XC20P: &str = "XC20P";

/// An XChaCha20-Poly1305 AEAD cipher (`RustCrypto`), doing both encryption and
/// decryption.
///
/// Build one with [`from_jwk`](Self::from_jwk) or
/// [`from_secret`](Self::from_secret); the key is always 256-bit. Implements
/// huskarl-core's [`AeadEncryptorSelector`] and [`AeadDecryptor`] — together,
/// an [`AeadCipher`](huskarl_core::crypto::cipher::AeadCipher).
///
/// # No rotation-for-nonce-safety bound
///
/// Each [`encrypt`](AeadEncryptor::encrypt) call draws a fresh random 192-bit
/// nonce — wide enough to permit ~2^80 encryptions per key at the same 2^-32
/// repeat budget behind [`AesGcmKey`]'s 2^32 bound. Rotate for key-lifetime
/// policy, not nonce budget.
#[derive(Debug, Clone)]
pub struct XChaChaKey {
    inner: Arc<XChaChaKeyInner>,
}

/// The shared key material behind an `XChaChaKey` — the encryptor snapshot
/// `select_encryptor` hands out.
struct XChaChaKeyInner {
    key: XChaCha20Poly1305,
    kid: Option<String>,
}

impl fmt::Debug for XChaChaKeyInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XChaChaKeyInner")
            .field("enc", &XC20P)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl XChaChaKey {
    /// Constructs a cipher from a [`jwk::SymmetricJwk`].
    ///
    /// The key material must be exactly 32 bytes. If the JWK carries an `alg`,
    /// it must equal `XC20P`. The `kid` field, if present, is used as the key
    /// ID. Holding a [`jwk::PrivateJwk`], convert with `try_into()` — the
    /// conversion rejects asymmetric keys.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the key material is not 32 bytes, or if
    /// the JWK's `alg` is present and is not `XC20P`.
    pub fn from_jwk(jwk: jwk::SymmetricJwk) -> Result<Self, Error> {
        if let Some(alg) = jwk.algorithm.as_deref()
            && alg != XC20P
        {
            return Err(Error::from(ErrorKind::Config)
                .with_context(format!("JWK algorithm {alg} is not {XC20P}")));
        }

        let key = XChaCha20Poly1305::new_from_slice(&jwk.key.k).map_err(|_| {
            Error::from(ErrorKind::Config).with_context(format!(
                "XChaCha20-Poly1305 key material must be 32 bytes, got {}",
                jwk.key.k.len()
            ))
        })?;

        Ok(XChaChaKey {
            inner: Arc::new(XChaChaKeyInner { key, kid: jwk.kid }),
        })
    }

    /// Finalizes a cipher from a secret that yields a [`jwk::PrivateJwk`].
    ///
    /// The same loading funnel and key-ID precedence (explicit JWK `kid` >
    /// secret `identity` > none) as [`AesGcmKey::from_secret`]; pair with
    /// [`jwk::OctBytes::new`]`("XC20P")` for raw key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`] if the secret cannot be fetched or
    /// decoded, if the JWK is asymmetric rather than symmetric (`oct`), or if
    /// it is not a valid 32-byte key.
    pub async fn from_secret<S: Secret<Output = jwk::PrivateJwk>>(
        secret: S,
    ) -> Result<Self, Error> {
        let output = secret.get_secret_value().await?;
        // Explicit JWK kid > secret identity > none.
        let jwk = output.value.with_kid_fallback(output.identity);
        Self::from_jwk(jwk.try_into()?)
    }
}

impl AeadEncryptorSelector for XChaChaKey {
    fn select_encryptor(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AeadEncryptor>> {
        let snapshot: Arc<dyn AeadEncryptor> = self.inner.clone();
        Box::pin(async move { snapshot })
    }
}

impl AeadDecryptor for XChaChaKey {
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
}

impl AeadEncryptor for XChaChaKeyInner {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(XC20P)
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
            // 24-byte XNonce; the length is inferred from the cipher below.
            let nonce = Array::generate();
            let mut ciphertext = plaintext.to_vec();

            let tag = self
                .key
                .encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
                .context(EncryptSnafu)?;

            Ok(AeadOutput {
                nonce: nonce.into(),
                ciphertext,
                tag: tag.into(),
            })
        })
    }
}

impl AeadDecryptor for XChaChaKeyInner {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        m.strength_for(XC20P, self.kid.as_deref())
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

            self.key
                .decrypt_inout_detached(&nonce, aad, plaintext.as_mut_slice().into(), &tag)
                .context(DecryptSnafu)?;

            Ok(plaintext)
        })
    }
}

#[cfg(test)]
mod tests {
    use huskarl_core::{
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput},
    };

    use super::*;

    #[derive(Clone)]
    struct TestSecret {
        bytes: Vec<u8>,
        identity: Option<String>,
    }

    impl Secret for TestSecret {
        type Output = SecretBytes;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<SecretBytes>, Error>> {
            let out = SecretOutput {
                value: SecretBytes::new(self.bytes.clone()),
                identity: self.identity.clone(),
            };
            Box::pin(async move { Ok(out) })
        }
    }

    fn oct_jwk(bytes: Vec<u8>) -> jwk::SymmetricJwk {
        jwk::SymmetricJwk::builder()
            .key(jwk::OctKey::builder().k(bytes).build())
            .build()
    }

    fn key_from(bytes: Vec<u8>, kid: Option<&str>) -> AesGcmKey {
        let mut jwk = oct_jwk(bytes);
        jwk.kid = kid.map(str::to_owned);
        AesGcmKey::from_jwk(jwk).unwrap()
    }

    /// Decode an ASCII hex string into bytes (for the NIST known-answer test).
    fn hex(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string must have even length"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    async fn roundtrip(key_bytes: Vec<u8>, expected_enc: &str) {
        let key = key_from(key_bytes, None);
        let encryptor = key.select_encryptor().await;
        assert_eq!(encryptor.enc_algorithm().as_ref(), expected_enc);

        let pt = b"the quick brown fox jumps over the lazy dog";
        let aad = b"session-context";
        let out = encryptor.encrypt(pt, aad).await.unwrap();

        assert_eq!(out.nonce.len(), 12, "96-bit nonce");
        assert_eq!(out.tag.len(), 16, "128-bit tag");
        assert_eq!(out.ciphertext.len(), pt.len(), "GCM is length-preserving");
        assert_ne!(out.ciphertext, pt, "ciphertext must not equal plaintext");

        let recovered = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(recovered, pt);
    }

    #[tokio::test]
    async fn roundtrip_a128gcm() {
        roundtrip(vec![1u8; 16], "A128GCM").await;
    }

    #[tokio::test]
    async fn roundtrip_a192gcm() {
        roundtrip(vec![2u8; 24], "A192GCM").await;
    }

    #[tokio::test]
    async fn roundtrip_a256gcm() {
        roundtrip(vec![3u8; 32], "A256GCM").await;
    }

    #[test]
    fn invalid_key_length_rejected() {
        for len in [0usize, 15, 17, 31, 33, 64] {
            let err = AesGcmKey::from_jwk(oct_jwk(vec![0u8; len])).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Config,
                "{len}-byte key must be rejected"
            );
        }
    }

    #[test]
    fn alg_must_agree_with_key_length() {
        let mut jwk = oct_jwk(vec![0u8; 32]);
        jwk.algorithm = Some("A128GCM".into());
        let err = AesGcmKey::from_jwk(jwk).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);

        // A matching alg — and no alg at all — are both fine.
        let mut jwk = oct_jwk(vec![0u8; 32]);
        jwk.algorithm = Some("A256GCM".into());
        assert!(AesGcmKey::from_jwk(jwk).is_ok());
    }

    #[tokio::test]
    async fn kid_derived_from_identity() {
        // The funnel's fallback: no kid in the JWK, so the secret source's
        // identity fills it.
        let key = AesGcmKey::from_secret(
            TestSecret {
                bytes: vec![4u8; 32],
                identity: Some("cookie-key-2026".into()),
            }
            .mapped(huskarl_core::jwk::OctBytes::new("A256GCM")),
        )
        .await
        .unwrap();
        let encryptor = key.select_encryptor().await;
        assert_eq!(encryptor.key_id().as_deref(), Some("cookie-key-2026"));
    }

    #[tokio::test]
    async fn jwk_kid_beats_identity() {
        let key = AesGcmKey::from_secret(
            TestSecret {
                bytes: vec![4u8; 32],
                identity: Some("version-7".into()),
            }
            .mapped(huskarl_core::jwk::OctBytes::new("A256GCM").with_kid("explicit")),
        )
        .await
        .unwrap();
        let encryptor = key.select_encryptor().await;
        assert_eq!(encryptor.key_id().as_deref(), Some("explicit"));
    }

    /// Mirror of the webcrypto backend's `kid_drives_cipher_match`: both
    /// backends must wire their own alg/kid into the shared
    /// `CipherMatch::strength_for` contract identically — the kid is what
    /// lets a `MultiKeyDecryptor` route, and a refresh-on-miss distinguish
    /// "wrong key" from "tampered".
    #[tokio::test]
    async fn kid_drives_cipher_match() {
        use huskarl_core::crypto::KeyMatchStrength;

        let key = key_from(vec![1u8; 32], Some("v1"));

        assert!(matches!(
            key.cipher_match(&CipherMatch::builder().kid("v1").build()),
            Some(KeyMatchStrength::ByKeyId),
        ));
        assert!(
            key.cipher_match(&CipherMatch::builder().kid("v2").build())
                .is_none(),
            "a kid mismatch must return None, not ByAlgorithm",
        );
        assert!(matches!(
            key.cipher_match(&CipherMatch::builder().build()),
            Some(KeyMatchStrength::ByAlgorithm),
        ));
        assert!(
            key.cipher_match(&CipherMatch::builder().enc("A128GCM").build())
                .is_none(),
            "an enc-algorithm mismatch must not match (key is A256GCM)",
        );
    }

    #[tokio::test]
    async fn wrong_aad_fails_to_open() {
        let key = key_from(vec![5u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let out = encryptor.encrypt(b"payload", b"session").await.unwrap();
        let res = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"other")
            .await;
        assert!(res.is_err(), "AAD must bind: a different AAD must not open");
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_to_open() {
        let key = key_from(vec![6u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let out = encryptor.encrypt(b"payload", b"session").await.unwrap();
        let mut ct = out.ciphertext.clone();
        ct[0] ^= 0x01;
        let res = key
            .decrypt(None, &out.nonce, &ct, &out.tag, b"session")
            .await;
        assert!(
            res.is_err(),
            "a flipped ciphertext bit must fail the tag check"
        );
    }

    #[tokio::test]
    async fn wrong_length_nonce_and_tag_rejected() {
        let key = key_from(vec![7u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let out = encryptor.encrypt(b"payload", b"session").await.unwrap();

        // Nonce too short (11 bytes instead of 12).
        let res = key
            .decrypt(
                None,
                &out.nonce[..11],
                &out.ciphertext,
                &out.tag,
                b"session",
            )
            .await;
        assert!(res.is_err(), "a wrong-length nonce must be rejected");

        // Tag too short (15 bytes instead of 16).
        let res = key
            .decrypt(
                None,
                &out.nonce,
                &out.ciphertext,
                &out.tag[..15],
                b"session",
            )
            .await;
        assert!(res.is_err(), "a wrong-length tag must be rejected");
    }

    /// NIST GCM spec (`McGrew` & Viega) Test Case 4 — AES-128-GCM with AAD.
    /// Exercises the detached-tag decrypt path against a known-answer vector.
    #[tokio::test]
    async fn aes128_nist_test_case_4_decrypt() {
        let key_bytes = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ciphertext = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let tag = hex("5bc94fbc3221a5db94fae95ae7121a47");
        let expected_pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );

        let key = key_from(key_bytes, None);
        let pt = key
            .decrypt(None, &nonce, &ciphertext, &tag, &aad)
            .await
            .unwrap();
        assert_eq!(pt, expected_pt);
    }

    /// A fresh random nonce per `encrypt` is the safety premise of the 2^32
    /// bound — two seals of the same plaintext must not reuse a nonce.
    #[tokio::test]
    async fn aes_gcm_nonces_differ_across_seals() {
        let key = key_from(vec![8u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let a = encryptor.encrypt(b"payload", b"aad").await.unwrap();
        let b = encryptor.encrypt(b"payload", b"aad").await.unwrap();
        assert_ne!(a.nonce, b.nonce, "each seal must draw a fresh nonce");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "distinct nonces must yield distinct ciphertext"
        );
    }

    fn xchacha_key_from(bytes: Vec<u8>, kid: Option<&str>) -> XChaChaKey {
        let mut jwk = oct_jwk(bytes);
        jwk.kid = kid.map(str::to_owned);
        XChaChaKey::from_jwk(jwk).unwrap()
    }

    #[tokio::test]
    async fn roundtrip_xc20p() {
        let key = xchacha_key_from(vec![9u8; 32], None);
        let encryptor = key.select_encryptor().await;
        assert_eq!(encryptor.enc_algorithm().as_ref(), "XC20P");

        let pt = b"the quick brown fox jumps over the lazy dog";
        let aad = b"session-context";
        let out = encryptor.encrypt(pt, aad).await.unwrap();

        assert_eq!(out.nonce.len(), 24, "192-bit nonce");
        assert_eq!(out.tag.len(), 16, "128-bit tag");
        assert_eq!(
            out.ciphertext.len(),
            pt.len(),
            "ChaCha is length-preserving"
        );
        assert_ne!(out.ciphertext, pt, "ciphertext must not equal plaintext");

        let recovered = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn xchacha_only_32_byte_keys() {
        for len in [0usize, 16, 24, 31, 33, 64] {
            let err = XChaChaKey::from_jwk(oct_jwk(vec![0u8; len])).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Config,
                "{len}-byte key must be rejected (XChaCha needs exactly 32)"
            );
        }
        assert!(XChaChaKey::from_jwk(oct_jwk(vec![0u8; 32])).is_ok());
    }

    #[test]
    fn xchacha_alg_must_be_xc20p() {
        let mut jwk = oct_jwk(vec![0u8; 32]);
        jwk.algorithm = Some("A256GCM".into());
        let err = XChaChaKey::from_jwk(jwk).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);

        // A matching alg — and no alg at all — are both fine.
        let mut jwk = oct_jwk(vec![0u8; 32]);
        jwk.algorithm = Some("XC20P".into());
        assert!(XChaChaKey::from_jwk(jwk).is_ok());
    }

    #[tokio::test]
    async fn xchacha_kid_drives_cipher_match() {
        use huskarl_core::crypto::KeyMatchStrength;

        let key = xchacha_key_from(vec![1u8; 32], Some("v1"));

        assert!(matches!(
            key.cipher_match(&CipherMatch::builder().kid("v1").build()),
            Some(KeyMatchStrength::ByKeyId),
        ));
        assert!(
            key.cipher_match(&CipherMatch::builder().kid("v2").build())
                .is_none(),
            "a kid mismatch must return None, not ByAlgorithm",
        );
        assert!(matches!(
            key.cipher_match(&CipherMatch::builder().build()),
            Some(KeyMatchStrength::ByAlgorithm),
        ));
        assert!(
            key.cipher_match(&CipherMatch::builder().enc("A256GCM").build())
                .is_none(),
            "an enc-algorithm mismatch must not match (key is XC20P)",
        );
    }

    #[tokio::test]
    async fn xchacha_wrong_aad_fails_to_open() {
        let key = xchacha_key_from(vec![5u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let out = encryptor.encrypt(b"payload", b"session").await.unwrap();
        let res = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"other")
            .await;
        assert!(res.is_err(), "AAD must bind: a different AAD must not open");
    }

    #[tokio::test]
    async fn xchacha_wrong_length_nonce_rejected() {
        let key = xchacha_key_from(vec![7u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let out = encryptor.encrypt(b"payload", b"session").await.unwrap();
        // A 12-byte (AES-GCM-sized) nonce must not be accepted by XChaCha.
        let res = key
            .decrypt(
                None,
                &out.nonce[..12],
                &out.ciphertext,
                &out.tag,
                b"session",
            )
            .await;
        assert!(res.is_err(), "a wrong-length nonce must be rejected");
    }

    #[tokio::test]
    async fn xchacha_wrong_length_tag_rejected() {
        let key = xchacha_key_from(vec![7u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let out = encryptor.encrypt(b"payload", b"session").await.unwrap();
        // Tag too short (15 bytes instead of 16).
        let res = key
            .decrypt(
                None,
                &out.nonce,
                &out.ciphertext,
                &out.tag[..15],
                b"session",
            )
            .await;
        assert!(res.is_err(), "a wrong-length tag must be rejected");
    }

    #[tokio::test]
    async fn xchacha_tampered_ciphertext_fails_to_open() {
        let key = xchacha_key_from(vec![6u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let out = encryptor.encrypt(b"payload", b"session").await.unwrap();
        let mut ct = out.ciphertext.clone();
        ct[0] ^= 0x01;
        let res = key
            .decrypt(None, &out.nonce, &ct, &out.tag, b"session")
            .await;
        assert!(
            res.is_err(),
            "a flipped ciphertext bit must fail the tag check"
        );
    }

    /// The 192-bit nonce is what removes the rotation-for-nonce-safety schedule;
    /// confirm it is actually drawn fresh per seal.
    #[tokio::test]
    async fn xchacha_nonces_differ_across_seals() {
        let key = xchacha_key_from(vec![8u8; 32], None);
        let encryptor = key.select_encryptor().await;
        let a = encryptor.encrypt(b"payload", b"aad").await.unwrap();
        let b = encryptor.encrypt(b"payload", b"aad").await.unwrap();
        assert_ne!(a.nonce, b.nonce, "each seal must draw a fresh nonce");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "distinct nonces must yield distinct ciphertext"
        );
    }

    /// Known-answer test from `draft-irtf-cfrg-xchacha-03` §A.3.1 — exercises
    /// the detached-tag decrypt path against the canonical AEAD vector.
    #[tokio::test]
    async fn xchacha_draft_a3_decrypt() {
        let key_bytes = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let ciphertext = hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e",
        );
        let tag = hex("c0875924c1c7987947deafd8780acf49");
        let expected_pt = hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        );

        let key = xchacha_key_from(key_bytes, None);
        let pt = key
            .decrypt(None, &nonce, &ciphertext, &tag, &aad)
            .await
            .unwrap();
        assert_eq!(pt, expected_pt);
    }
}
