mod generate_key;
mod import_key;
mod public_key;
mod serialize;
mod sign;
mod verify;

pub use generate_key::{AsymmetricKeyGenParams, GenerateKeyError, generate_asymmetric_key};
pub use import_key::{ImportParams, import_key};
pub use public_key::{GetPublicJwkError, get_public_jwk};
use serde::Serialize;
use serialize::{serialize_ed25519, serialize_hmac, serialize_rsa_pkcs1};
pub use sign::{JsSignError, sign_with_key};
use snafu::prelude::*;
pub use verify::{JsVerifyError, verify_with_key};
use wasm_bindgen::{JsValue, convert::TryFromJsValue};
use web_sys::{Crypto, js_sys::Reflect};

use crate::JsError;

#[derive(Debug, Snafu)]
pub enum GetCryptoError {
    NoGlobal {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
    InvalidCryptoObject {
        #[snafu(source(from(JsValue, JsError::new)))]
        source: JsError,
    },
}

pub fn get_crypto() -> Result<Crypto, GetCryptoError> {
    let global = web_sys::js_sys::global();
    Crypto::try_from_js_value(Reflect::get(&global, &"crypto".into()).context(NoGlobalSnafu)?)
        .context(InvalidCryptoObjectSnafu)
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SignAlgorithm<'a> {
    #[serde(serialize_with = "serialize_rsa_pkcs1")]
    RsaPkcs1,
    RsaPss {
        name: &'a str,
        #[serde(rename = "saltLength")]
        salt_length: u32,
    },
    EcDsa {
        name: &'a str,
        hash: &'a str,
    },
    #[serde(serialize_with = "serialize_hmac")]
    #[allow(dead_code)]
    Hmac,
    #[serde(serialize_with = "serialize_ed25519")]
    Ed25519,
}
