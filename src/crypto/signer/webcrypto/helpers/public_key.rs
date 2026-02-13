use snafu::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::{crypto::signer::webcrypto::JsError, jwk::PublicJwk};

#[derive(Debug, Snafu)]
pub enum GetPublicJwkError {
    ExportKey {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    SerializeJwk {
        source: serde_wasm_bindgen::Error,
    },
    AwaitJwk {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
}

#[must_use]
pub async fn get_public_jwk(
    crypto: &SubtleCrypto,
    public_key: &CryptoKey,
) -> Result<PublicJwk, GetPublicJwkError> {
    let jwk = JsFuture::from(
        crypto
            .export_key("jwk", public_key)
            .context(ExportKeySnafu)?,
    )
    .await
    .context(AwaitJwkSnafu)?;

    serde_wasm_bindgen::from_value(jwk).context(SerializeJwkSnafu)
}
