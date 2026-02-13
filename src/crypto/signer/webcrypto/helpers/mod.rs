mod generate_key;
mod public_key;
mod serialize;
mod sign;

pub use generate_key::{
    AsymmetricKeyGenParams, GenerateKeyError, KeyUsage, generate_asymmetric_key,
};
use js_sys::Reflect;
pub use public_key::{GetPublicJwkError, get_public_jwk};
pub use sign::{SignAlgorithm, SignError, sign_with_key};
use snafu::prelude::*;
use wasm_bindgen::{JsValue, convert::TryFromJsValue};
use web_sys::Crypto;

use crate::crypto::signer::webcrypto::JsError;

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
