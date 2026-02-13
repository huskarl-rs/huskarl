use serde::Serialize;
use snafu::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::js_sys::Object;
use web_sys::{CryptoKeyPair, SubtleCrypto};

use crate::crypto::signer::webcrypto::JsError;

use super::serialize::{serialize_ed25519, serialize_x25519};

#[derive(Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum AsymmetricKeyGenParams<'a> {
    RsaHashed {
        name: &'a str,
        modulus_length: u32,
        #[serde(with = "serde_bytes")]
        public_exponent: &'a [u8],
        hash: &'a str,
    },
    Ec {
        name: &'a str,
        named_curve: &'a str,
    },
    #[serde(serialize_with = "serialize_ed25519")]
    Ed25519,
    #[serde(serialize_with = "serialize_x25519")]
    X25519,
}

/// Indicates the possible uses of a key.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyUsage {
    /// The key may be used to encrypt messages.
    Encrypt,
    /// The key may be used to decrypt messages.
    Decrypt,
    /// The key may be used to sign messages.
    Sign,
    /// The key may be used to verify signatures.
    Verify,
    /// The key may be used in deriving a new key.
    DeriveKey,
    /// The key may be used in deriving bits.
    DeriveBits,
    /// The key may be used to wrap a key.
    WrapKey,
    /// The key may be used to unwrap a key.
    UnwrapKey,
}

#[derive(Debug, Snafu)]
pub enum GenerateKeyError {
    Generate {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    Serialize {
        source: serde_wasm_bindgen::Error,
    },
    Await {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
}

#[must_use]
pub async fn generate_asymmetric_key(
    crypto: &SubtleCrypto,
    key_gen_params: AsymmetricKeyGenParams<'_>,
    key_usages: &[KeyUsage],
) -> Result<CryptoKeyPair, GenerateKeyError> {
    let key_gen_params_js =
        Object::from(serde_wasm_bindgen::to_value(&key_gen_params).context(SerializeSnafu)?);

    let key_usages_js = serde_wasm_bindgen::to_value(&key_usages).context(SerializeSnafu)?;

    Ok(JsFuture::from(
        crypto
            .generate_key_with_object(&key_gen_params_js, false, &key_usages_js)
            .context(GenerateSnafu)?,
    )
    .await
    .context(AwaitSnafu)?
    .into())
}
