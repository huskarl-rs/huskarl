use snafu::{ResultExt as _, Snafu};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::{JsError, helpers::SignAlgorithm};

#[derive(Debug, Snafu)]
pub enum JsVerifyError {
    SerializeAlgorithm {
        source: serde_wasm_bindgen::Error,
    },
    Verify {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    Await {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
}

pub async fn verify_with_key(
    crypto: &SubtleCrypto,
    sign_algorithm: SignAlgorithm<'_>,
    key: &CryptoKey,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, JsVerifyError> {
    let sign_algorithm_js =
        serde_wasm_bindgen::to_value(&sign_algorithm).context(SerializeAlgorithmSnafu)?;

    Ok(JsFuture::from(
        crypto
            .verify_with_object_and_u8_array_and_u8_array(
                &sign_algorithm_js.into(),
                key,
                signature,
                data,
            )
            .context(VerifySnafu)?,
    )
    .await
    .context(AwaitSnafu)?
    .as_bool()
    .unwrap_or(false))
}
