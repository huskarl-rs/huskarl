use serde::Serialize;
use snafu::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKeyPair, SubtleCrypto};

use super::serialize::{serialize_ed25519, serialize_x25519};
use crate::{JsError, KeyUsage};

#[derive(Serialize)]
#[serde(untagged)]
pub enum AsymmetricKeyGenParams<'a> {
    RsaHashed {
        name: &'a str,
        #[serde(rename = "modulusLength")]
        modulus_length: u32,
        #[serde(rename = "publicExponent", with = "serde_bytes")]
        public_exponent: &'a [u8],
        hash: &'a str,
    },
    Ec {
        name: &'a str,
        #[serde(rename = "namedCurve")]
        named_curve: &'a str,
    },
    #[serde(serialize_with = "serialize_ed25519")]
    Ed25519,
    #[serde(serialize_with = "serialize_x25519")]
    #[allow(dead_code)]
    X25519,
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

pub async fn generate_asymmetric_key(
    crypto: &SubtleCrypto,
    key_gen_params: AsymmetricKeyGenParams<'_>,
    key_usages: &[KeyUsage],
) -> Result<CryptoKeyPair, GenerateKeyError> {
    let key_gen_params_js =
        serde_wasm_bindgen::to_value(&key_gen_params).context(SerializeSnafu)?;
    let key_usages_js = serde_wasm_bindgen::to_value(&key_usages).context(SerializeSnafu)?;

    Ok(JsFuture::from(
        crypto
            .generate_key_with_object(&key_gen_params_js.into(), false, &key_usages_js)
            .context(GenerateSnafu)?,
    )
    .await
    .context(AwaitSnafu)?
    .into())
}
