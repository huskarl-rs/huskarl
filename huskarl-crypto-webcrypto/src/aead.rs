//! AES-GCM AEAD over the WebCrypto/Subtle API.

use std::{borrow::Cow, sync::Arc};

use huskarl_core::{
    Error, ErrorKind,
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadOutput, CipherMatch, DecryptError},
    },
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes},
};
use snafu::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CryptoKey,
    js_sys::{Object, Reflect, Uint8Array},
};

use crate::{
    JsError, KeyUsage,
    helpers::{GetCryptoError, get_crypto},
};

/// AES-GCM nonce length, in bytes (96-bit — the JWA-recommended IV size, and
/// what `WebCrypto` expects for an efficient single-block counter).
const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length, in bytes (128-bit).
const TAG_LEN: usize = 16;

struct Inner {
    crypto_key: CryptoKey,
    enc_algorithm: &'static str,
    kid: Option<String>,
}

/// A non-extractable AES-GCM key backed by the `WebCrypto`/Subtle API.
///
/// Implements [`AeadEncryptor`] + [`AeadDecryptor`] — and therefore
/// [`AeadCipher`](huskarl_core::crypto::cipher::AeadCipher) by blanket impl — so
/// it can seal `huskarl-login`'s session and login-state cookies on platforms
/// whose only available crypto is `WebCrypto`: Cloudflare Workers, browsers,
/// Deno Deploy. It is the symmetric counterpart to [`crate::asymmetric`]'s
/// signer/verifier.
///
/// Wrap it the same way as any other [`AeadCipher`]:
/// `AeadV1Cipher::new(key)` for the bundle envelope, and the reload wrappers
/// ([`RetryingDecryptor`](huskarl_core::crypto::cipher::RetryingDecryptor),
/// [`MultiKeyCipher`](huskarl_core::crypto::cipher::MultiKeyCipher)) compose
/// over it for hot key rotation.
///
/// All operations are `async` because `SubtleCrypto` is async-only; the nonce
/// is drawn from the platform CSPRNG (`crypto.getRandomValues`), so this type
/// itself pulls in no `getrandom` backend. (The wider crate graph may still
/// need one for other `rand` uses — e.g. OAuth PKCE/state generation.)
#[derive(Clone)]
pub struct AesGcmKey {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for AesGcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmKey")
            .field("enc", &self.inner.enc_algorithm)
            .field("kid", &self.inner.kid)
            .finish_non_exhaustive()
    }
}

/// Errors that can occur when loading an AES-GCM key.
#[derive(Debug, Snafu)]
pub enum LoadKeyError {
    /// The key secret could not be fetched from its source.
    #[snafu(display("failed to fetch AES key secret"))]
    Secret {
        /// The underlying error.
        source: Error,
    },
    /// The key material was not 16, 24, or 32 bytes (AES-128/192/256).
    #[snafu(display("AES key must be 16, 24, or 32 bytes"))]
    InvalidKeyLength,
    /// `WebCrypto` was not available in the environment.
    #[snafu(display("WebCrypto unavailable"))]
    LoadCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// The key-usage list could not be serialized.
    #[snafu(display("failed to serialize key usages"))]
    Usages {
        /// The underlying error.
        source: serde_wasm_bindgen::Error,
    },
    /// `SubtleCrypto.importKey` rejected the key material.
    #[snafu(display("importKey failed"))]
    Import {
        /// The underlying error.
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    /// Awaiting the `importKey` promise failed.
    #[snafu(display("awaiting importKey failed"))]
    ImportAwait {
        /// The underlying error.
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
}

/// Errors that can occur during an encrypt/decrypt operation.
#[derive(Debug, Snafu)]
enum OpError {
    #[snafu(display("WebCrypto unavailable"))]
    OpCrypto { source: GetCryptoError },
    #[snafu(display("failed to generate nonce"))]
    Random {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    #[snafu(display("failed to build AES-GCM parameters"))]
    Params {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    #[snafu(display("AES-GCM operation failed"))]
    Op {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    #[snafu(display("awaiting AES-GCM operation failed"))]
    Await {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    #[snafu(display("ciphertext shorter than the authentication tag"))]
    ShortCiphertext,
}

impl From<OpError> for Error {
    fn from(value: OpError) -> Self {
        Error::new(ErrorKind::Crypto, value)
    }
}

// An AEAD authentication failure surfaces here as `Op`/`Await` (a rejected
// `SubtleCrypto` promise), which maps to `DecryptError::Other` — *not*
// `NoMatchingKey`. That matches the native cipher: a bad tag is a hard failure,
// indistinguishable from tampering, and must not trigger a `RetryingDecryptor`
// refresh. Only a true "no key for this kid" miss (handled a layer up by
// `MultiKeyDecryptor`) yields `NoMatchingKey`.
impl From<OpError> for DecryptError {
    fn from(value: OpError) -> Self {
        Error::from(value).into()
    }
}

impl AesGcmKey {
    /// Imports a non-extractable AES-GCM key from a [`Secret`], inferring
    /// AES-128/192/256 from the key length.
    ///
    /// `kid_from_identity` maps the secret source's identity (e.g. a secret
    /// manager version, a KMS key id) to the `kid` reported by
    /// [`key_id`](AeadEncryptor::key_id) — which `huskarl-login` writes into the
    /// kid sidecar cookie so rotation/refresh-on-miss can target the right key.
    ///
    /// # Errors
    ///
    /// Returns [`LoadKeyError`] if the secret cannot be fetched, the key
    /// length is invalid, or `WebCrypto` rejects the import.
    pub async fn from_secret<S: Secret<Output = SecretBytes>>(
        secret: S,
        kid_from_identity: impl Fn(Option<&str>) -> Option<String>,
    ) -> Result<Self, LoadKeyError> {
        let key_source = secret.get_secret_value().await.context(SecretSnafu)?;
        let bytes = key_source.value.expose_secret();
        let enc_algorithm = enc_algorithm_for_len(bytes.len()).context(InvalidKeyLengthSnafu)?;

        let crypto = get_crypto().context(LoadCryptoSnafu)?;
        let usages = serde_wasm_bindgen::to_value(&[KeyUsage::Encrypt, KeyUsage::Decrypt])
            .context(UsagesSnafu)?;

        // Algorithm for a raw AES-GCM import is just `{ name: "AES-GCM" }`.
        let algorithm = Object::new();
        Reflect::set(
            &algorithm,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .context(ImportSnafu)?;

        let key_data = to_uint8(bytes);
        let crypto_key: CryptoKey = JsFuture::from(
            crypto
                .subtle()
                // Non-extractable: JS can never read the key back out.
                .import_key_with_object("raw", &key_data, &algorithm, false, &usages)
                .context(ImportSnafu)?,
        )
        .await
        .context(ImportAwaitSnafu)?
        .into();

        Ok(Self {
            inner: Arc::new(Inner {
                crypto_key,
                enc_algorithm,
                kid: kid_from_identity(key_source.identity.as_deref()),
            }),
        })
    }

    /// Builds a key from an already-imported [`CryptoKey`] (e.g. one provisioned
    /// once at startup, or a non-extractable key never present as raw bytes).
    ///
    /// `key_bits` selects the reported `enc` algorithm (128/192/256 →
    /// `A128GCM`/`A192GCM`/`A256GCM`; any other value is treated as 256).
    #[must_use]
    pub fn from_crypto_key(crypto_key: CryptoKey, key_bits: u32, kid: Option<String>) -> Self {
        let enc_algorithm = match key_bits {
            128 => "A128GCM",
            192 => "A192GCM",
            _ => "A256GCM",
        };
        Self {
            inner: Arc::new(Inner {
                crypto_key,
                enc_algorithm,
                kid,
            }),
        }
    }
}

impl AeadEncryptor for AesGcmKey {
    fn enc_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.inner.enc_algorithm)
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.kid.as_deref().map(Cow::Borrowed)
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        Box::pin(async move {
            let crypto = get_crypto().context(OpCryptoSnafu)?;

            // Fresh 96-bit nonce from the platform CSPRNG, per seal.
            let mut nonce = [0u8; NONCE_LEN];
            crypto
                .get_random_values_with_u8_array(&mut nonce)
                .context(RandomSnafu)?;

            let params = aes_gcm_params(&nonce, aad).context(ParamsSnafu)?;
            let result = JsFuture::from(
                crypto
                    .subtle()
                    .encrypt_with_object_and_u8_array(&params, &self.inner.crypto_key, plaintext)
                    .context(OpSnafu)?,
            )
            .await
            .context(AwaitSnafu)?;

            // WebCrypto returns ciphertext || tag; split the trailing tag off so
            // the bundle layer (`AeadV1Cipher`) can frame nonce/ciphertext/tag.
            let combined = Uint8Array::new(&result).to_vec();
            if combined.len() < TAG_LEN {
                return Err(OpError::ShortCiphertext.into());
            }
            let split = combined.len() - TAG_LEN;
            Ok(AeadOutput {
                nonce: nonce.to_vec(),
                ciphertext: combined[..split].to_vec(),
                tag: combined[split..].to_vec(),
            })
        })
    }
}

impl AeadDecryptor for AesGcmKey {
    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        m.strength_for(self.inner.enc_algorithm, self.inner.kid.as_deref())
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
            let crypto = get_crypto().context(OpCryptoSnafu)?;
            let params = aes_gcm_params(nonce, aad).context(ParamsSnafu)?;

            // WebCrypto's open expects ciphertext || tag; re-join the detached tag.
            let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
            combined.extend_from_slice(ciphertext);
            combined.extend_from_slice(tag);

            let result = JsFuture::from(
                crypto
                    .subtle()
                    .decrypt_with_object_and_u8_array(&params, &self.inner.crypto_key, &combined)
                    .context(OpSnafu)?,
            )
            .await
            .context(AwaitSnafu)?;

            Ok(Uint8Array::new(&result).to_vec())
        })
    }
}

/// Maps an AES key byte length to its JWA `enc` algorithm identifier.
fn enc_algorithm_for_len(len: usize) -> Option<&'static str> {
    match len {
        16 => Some("A128GCM"),
        24 => Some("A192GCM"),
        32 => Some("A256GCM"),
        _ => None,
    }
}

/// Copies a Rust byte slice into a JS `Uint8Array`.
fn to_uint8(bytes: &[u8]) -> Uint8Array {
    let arr = Uint8Array::new_with_length(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    arr.copy_from(bytes);
    arr
}

/// Builds the `AesGcmParams` dictionary `WebCrypto` expects for encrypt/decrypt.
/// Built imperatively (rather than via `serde_wasm_bindgen`) so the binary
/// `iv`/`additionalData` become `Uint8Array`s rather than JS number arrays.
fn aes_gcm_params(nonce: &[u8], aad: &[u8]) -> Result<Object, JsValue> {
    let params = Object::new();
    Reflect::set(
        &params,
        &JsValue::from_str("name"),
        &JsValue::from_str("AES-GCM"),
    )?;
    Reflect::set(
        &params,
        &JsValue::from_str("iv"),
        &JsValue::from(to_uint8(nonce)),
    )?;
    Reflect::set(
        &params,
        &JsValue::from_str("additionalData"),
        &JsValue::from(to_uint8(aad)),
    )?;
    // 128-bit authentication tag (TAG_LEN * 8).
    Reflect::set(
        &params,
        &JsValue::from_str("tagLength"),
        &JsValue::from_f64(128.0),
    )?;
    Ok(params)
}

#[cfg(test)]
mod tests {
    //! Runs in a real `WebCrypto` environment (browser or Node ≥20). Execute
    //! with `wasm-pack test --headless --firefox` or `wasm-pack test --node`
    //! from the crate directory.

    use huskarl_core::{
        Error,
        crypto::{
            KeyMatchStrength,
            cipher::{AeadDecryptor as _, AeadEncryptor as _, CipherMatch},
        },
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput},
    };
    use huskarl_crypto_native::aead::AesGcmKey as NativeAesGcmKey;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::AesGcmKey;

    #[derive(Clone)]
    struct TestSecret {
        bytes: SecretBytes,
        identity: Option<String>,
    }

    impl Secret for TestSecret {
        type Output = SecretBytes;
        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<SecretBytes>, Error>> {
            let out = SecretOutput {
                value: self.bytes.clone(),
                identity: self.identity.clone(),
            };
            Box::pin(async move { Ok(out) })
        }
    }

    async fn key_from(bytes: Vec<u8>, identity: Option<&str>) -> AesGcmKey {
        let identity = identity.map(str::to_owned);
        AesGcmKey::from_secret(
            TestSecret {
                bytes: SecretBytes::new(bytes),
                identity,
            },
            |id| id.map(str::to_owned),
        )
        .await
        .unwrap()
    }

    async fn key_256() -> AesGcmKey {
        key_from(vec![7u8; 32], None).await
    }

    #[wasm_bindgen_test]
    async fn seal_then_open_roundtrips() {
        let key = key_256().await;
        let aad = b"session";
        let pt = b"the quick brown fox jumps over the lazy dog";

        let out = key.encrypt(pt, aad).await.unwrap();
        assert_eq!(out.nonce.len(), 12, "96-bit nonce");
        assert_eq!(out.tag.len(), 16, "128-bit tag");
        assert_ne!(
            out.ciphertext,
            pt.to_vec(),
            "ciphertext must not equal plaintext"
        );

        let recovered = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(recovered, pt.to_vec());
    }

    #[wasm_bindgen_test]
    async fn nonces_differ_across_seals() {
        let key = key_256().await;
        let a = key.encrypt(b"x", b"aad").await.unwrap();
        let b = key.encrypt(b"x", b"aad").await.unwrap();
        assert_ne!(a.nonce, b.nonce, "each seal must draw a fresh CSPRNG nonce");
    }

    #[wasm_bindgen_test]
    async fn wrong_aad_fails_to_open() {
        // The AAD binding is what domain-separates session vs login-state cookies.
        let key = key_256().await;
        let out = key.encrypt(b"payload", b"session").await.unwrap();
        let res = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"session_ptr")
            .await;
        assert!(res.is_err(), "an AAD mismatch must fail authentication");
    }

    #[wasm_bindgen_test]
    async fn tampered_ciphertext_fails_to_open() {
        let key = key_256().await;
        let mut out = key.encrypt(b"payload data here", b"aad").await.unwrap();
        out.ciphertext[0] ^= 0xff;
        let res = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"aad")
            .await;
        assert!(
            res.is_err(),
            "a flipped ciphertext byte must fail the tag check"
        );
    }

    #[wasm_bindgen_test]
    async fn other_key_cannot_open() {
        let a = key_from(vec![7u8; 32], None).await;
        let b = key_from(vec![9u8; 32], None).await;
        let out = a.encrypt(b"secret", b"aad").await.unwrap();
        let res = b
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"aad")
            .await;
        assert!(
            res.is_err(),
            "a foreign key must not authenticate the bundle"
        );
    }

    #[wasm_bindgen_test]
    async fn aes_128_and_192_roundtrip() {
        for len in [16usize, 24] {
            let key = key_from(vec![3u8; len], None).await;
            let out = key.encrypt(b"data", b"aad").await.unwrap();
            let recovered = key
                .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"aad")
                .await
                .unwrap();
            assert_eq!(recovered, b"data".to_vec(), "AES key length {len}");
        }
    }

    #[wasm_bindgen_test]
    async fn enc_algorithm_reflects_key_size() {
        // The reported `enc` is what `AeadV1Cipher` writes into the envelope and
        // what `cipher_match` keys on, so each AES size must label itself.
        for (len, enc) in [(16usize, "A128GCM"), (24, "A192GCM"), (32, "A256GCM")] {
            let key = key_from(vec![3u8; len], None).await;
            assert_eq!(key.enc_algorithm().as_ref(), enc, "AES key length {len}");
        }
    }

    #[wasm_bindgen_test]
    async fn invalid_key_length_is_rejected() {
        let res = AesGcmKey::from_secret(
            TestSecret {
                bytes: SecretBytes::new(vec![0u8; 20]),
                identity: None,
            },
            |_| None,
        )
        .await;
        assert!(res.is_err(), "a 20-byte key is not a valid AES key size");
    }

    #[wasm_bindgen_test]
    async fn kid_drives_cipher_match() {
        // The kid is what lets a MultiKeyDecryptor route — and a refresh-on-miss
        // distinguish "wrong key" from "tampered". Exercise the match contract.
        let key = key_from(vec![1u8; 32], Some("v1")).await;
        assert_eq!(key.key_id().as_deref(), Some("v1"));

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
    }

    /// Imports raw AES bytes into a non-extractable `CryptoKey`, mirroring what
    /// `from_secret` does internally — the only way to obtain a `CryptoKey` to
    /// feed [`AesGcmKey::from_crypto_key`] in a test.
    async fn import_raw_aes_crypto_key(bytes: &[u8]) -> web_sys::CryptoKey {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        use web_sys::js_sys::{Object, Reflect};

        use crate::{KeyUsage, helpers::get_crypto};

        let crypto = get_crypto().unwrap();
        let usages = serde_wasm_bindgen::to_value(&[KeyUsage::Encrypt, KeyUsage::Decrypt]).unwrap();
        let algorithm = Object::new();
        Reflect::set(
            &algorithm,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .unwrap();
        let key_data = super::to_uint8(bytes);

        JsFuture::from(
            crypto
                .subtle()
                .import_key_with_object("raw", &key_data, &algorithm, false, &usages)
                .unwrap(),
        )
        .await
        .unwrap()
        .into()
    }

    #[wasm_bindgen_test]
    async fn from_crypto_key_wraps_an_imported_key() {
        // The alternate constructor: wrap an already-imported (e.g. provisioned
        // at startup, never present as raw bytes) CryptoKey rather than a secret.
        let bytes = vec![4u8; 32];
        let crypto_key = import_raw_aes_crypto_key(&bytes).await;
        let key = AesGcmKey::from_crypto_key(crypto_key, 256, Some("startup".to_string()));

        assert_eq!(key.enc_algorithm().as_ref(), "A256GCM");
        assert_eq!(key.key_id().as_deref(), Some("startup"));

        // It seals and opens like any other key.
        let aad = b"session";
        let out = key.encrypt(b"provisioned payload", aad).await.unwrap();
        let recovered = key
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(recovered, b"provisioned payload".to_vec());

        // And it shares the wire format with a from_secret key over the same
        // material — i.e. from_crypto_key really imported the same key.
        let twin = key_from(bytes, None).await;
        let opened = twin
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(
            opened,
            b"provisioned payload".to_vec(),
            "the same key material must interop",
        );
    }

    #[wasm_bindgen_test]
    async fn from_crypto_key_maps_key_bits_to_enc_label() {
        // `key_bits` only drives the reported `enc` label; any unrecognized value
        // falls back to A256GCM. (The actual key size comes from the CryptoKey.)
        let crypto_key = import_raw_aes_crypto_key(&[8u8; 32]).await;
        for (bits, enc) in [
            (128u32, "A128GCM"),
            (192, "A192GCM"),
            (256, "A256GCM"),
            (9999, "A256GCM"),
        ] {
            let key = AesGcmKey::from_crypto_key(crypto_key.clone(), bits, None);
            assert_eq!(key.enc_algorithm().as_ref(), enc, "key_bits {bits}");
        }
    }

    // ── Interop with the pure-Rust `aes-gcm` cipher ───────────────────────
    //
    // Confirms both implementations agree on the AES-256-GCM wire format
    // (96-bit nonce, ciphertext, 128-bit *detached* tag, AAD), so a cookie
    // sealed on one runtime opens on the other — e.g. a deployment migrating
    // between the native and WebCrypto cipher, or running both side by side.

    async fn native_key(bytes: Vec<u8>) -> NativeAesGcmKey {
        NativeAesGcmKey::from_secret(
            TestSecret {
                bytes: SecretBytes::new(bytes),
                identity: None,
            },
            |_| None,
        )
        .await
        .unwrap()
    }

    #[wasm_bindgen_test]
    async fn webcrypto_seal_opens_under_native() {
        let bytes = vec![5u8; 32];
        let web = key_from(bytes.clone(), None).await;
        let native = native_key(bytes).await;
        let aad = b"session";

        let out = web.encrypt(b"interop payload", aad).await.unwrap();
        let recovered = native
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(
            recovered,
            b"interop payload".to_vec(),
            "a WebCrypto-sealed bundle must open under the native cipher",
        );
    }

    #[wasm_bindgen_test]
    async fn native_seal_opens_under_webcrypto() {
        let bytes = vec![5u8; 32];
        let web = key_from(bytes.clone(), None).await;
        let native = native_key(bytes).await;
        let aad = b"session";

        // Native sealing draws its nonce from getrandom — needs the wasm_js
        // backend cfg at build time (see the dev-dependency comment).
        let out = native.encrypt(b"interop payload", aad).await.unwrap();
        let recovered = web
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(
            recovered,
            b"interop payload".to_vec(),
            "a native-sealed bundle must open under the WebCrypto cipher",
        );
    }

    #[wasm_bindgen_test]
    async fn cross_impl_aad_still_binds() {
        let bytes = vec![5u8; 32];
        let web = key_from(bytes.clone(), None).await;
        let native = native_key(bytes).await;

        let out = web.encrypt(b"payload", b"session").await.unwrap();
        let res = native
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, b"session_ptr")
            .await;
        assert!(res.is_err(), "AAD must bind across implementations too");
    }

    /// AES-192 interop in both directions. Native gained 192 with the inferred
    /// `from_secret`, so this is the only coverage of native's `Aes192` arm.
    #[wasm_bindgen_test]
    async fn aes192_interops_across_impls() {
        let bytes = vec![6u8; 24];
        let web = key_from(bytes.clone(), None).await;
        let native = native_key(bytes).await;
        let aad = b"session";

        assert_eq!(web.enc_algorithm().as_ref(), "A192GCM");
        assert_eq!(native.enc_algorithm().as_ref(), "A192GCM");

        // WebCrypto seals → native opens.
        let out = web.encrypt(b"aes192 payload", aad).await.unwrap();
        let recovered = native
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(recovered, b"aes192 payload".to_vec());

        // Native seals → WebCrypto opens.
        let out = native.encrypt(b"aes192 payload", aad).await.unwrap();
        let recovered = web
            .decrypt(None, &out.nonce, &out.ciphertext, &out.tag, aad)
            .await
            .unwrap();
        assert_eq!(recovered, b"aes192 payload".to_vec());
    }
}
