use snafu::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CryptoKey, SubtleCrypto,
    js_sys::{Object, Uint8Array},
};

use crate::{JsError, helpers::SignAlgorithm};

#[derive(Debug, Snafu)]
pub enum JsSignError {
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

pub async fn sign_with_key(
    crypto: &SubtleCrypto,
    sign_algorithm: SignAlgorithm<'_>,
    key: &CryptoKey,
    data: &[u8],
) -> Result<Vec<u8>, JsSignError> {
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
