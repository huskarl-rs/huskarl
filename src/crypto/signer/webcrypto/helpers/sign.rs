use serde::Serialize;
use snafu::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CryptoKey, SubtleCrypto,
    js_sys::{Object, Uint8Array},
};

use crate::crypto::signer::webcrypto::JsError;

use super::serialize::{serialize_ed25519, serialize_hmac, serialize_rsa_pkcs1};

#[derive(Debug, Snafu)]
pub enum SignError {
    SerializeAlgorithm {
        source: serde_wasm_bindgen::Error,
    },
    Sign {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    Await {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum SignAlgorithm<'a> {
    #[serde(serialize_with = "serialize_rsa_pkcs1")]
    RsaPkcs1,
    RsaPss {
        name: &'a str,
        salt_length: u32,
    },
    EcDsa {
        name: &'a str,
        hash: &'a str,
    },
    #[serde(serialize_with = "serialize_hmac")]
    Hmac,
    #[serde(serialize_with = "serialize_ed25519")]
    Ed25519,
}

pub async fn sign_with_key(
    crypto: &SubtleCrypto,
    sign_algorithm: SignAlgorithm<'_>,
    key: &CryptoKey,
    data: &[u8],
) -> Result<Vec<u8>, SignError> {
    let sign_algorithm_js = Object::from(
        serde_wasm_bindgen::to_value(&sign_algorithm).context(SerializeAlgorithmSnafu)?,
    );

    Ok(Uint8Array::new(
            &JsFuture::from(
                crypto
                    .sign_with_object_and_u8_array(&sign_algorithm_js, key, data)
                    .context(SignSnafu)?,
            )
            .await
            .context(AwaitSnafu)?,
        )
        .to_vec())
}
