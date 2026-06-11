use huskarl_core::jwk;
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

#[wasm_bindgen]
extern "C" {
    /// Binding to `JSON.parse`, used for correct JWK serialization.
    /// `serde_wasm_bindgen::to_value` drops `kty` when the type uses
    /// `#[serde(flatten)]` + `#[serde(tag)]`, so we round-trip via JSON.
    #[wasm_bindgen(js_namespace = JSON, js_name = parse, catch)]
    fn json_parse(s: &str) -> Result<JsValue, JsValue>;
}

use super::serialize::{serialize_ed25519, serialize_x25519};
use crate::{JsError, KeyUsage};

#[derive(Serialize)]
#[serde(untagged)]
pub enum ImportParams<'a> {
    RsaHashed {
        name: &'a str,
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
pub enum ImportKeyError {
    Import {
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

pub async fn import_key(
    crypto: &SubtleCrypto,
    key_data: &jwk::PublicJwk,
    params: ImportParams<'_>,
    key_usages: &[KeyUsage],
) -> Result<CryptoKey, ImportKeyError> {
    // serde_wasm_bindgen doesn't handle #[serde(flatten)] + #[serde(tag)] correctly,
    // causing the `kty` field to be dropped. Serialize via JSON as a workaround.
    let key_json = serde_json::to_string(key_data)
        .map_err(|e| serde_wasm_bindgen::Error::from(JsValue::from_str(&e.to_string())))
        .context(SerializeSnafu)?;
    let key_data_js = json_parse(&key_json).context(ImportSnafu)?;
    let params_js = serde_wasm_bindgen::to_value(&params).context(SerializeSnafu)?;
    let key_usages_js = serde_wasm_bindgen::to_value(&key_usages).context(SerializeSnafu)?;

    Ok(JsFuture::from(
        crypto
            .import_key_with_object(
                "jwk",
                &key_data_js.into(),
                &params_js.into(),
                true,
                &key_usages_js,
            )
            .context(ImportSnafu)?,
    )
    .await
    .context(AwaitSnafu)?
    .into())
}
