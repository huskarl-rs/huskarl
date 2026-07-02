use snafu::Snafu;
use wasm_bindgen::{JsCast as _, JsValue};

/// A JavaScript error surfaced from a `JsValue` (e.g. a rejected `WebCrypto` promise).
#[derive(Debug, Snafu)]
#[snafu(display("{}", js_error_message(error)))]
pub struct JsError {
    error: JsValue,
}

impl JsError {
    /// Create a new `JsError` from a `JsValue`.
    pub(crate) fn new(error: JsValue) -> Self {
        Self { error }
    }
}

/// Human-readable text for a JS error value: string values as-is; `Error` and
/// `DOMException` objects — what `SubtleCrypto` rejects with — via their
/// `message`; anything else via its `Debug` form. Never the empty string that
/// `as_string()` alone produced for every object.
fn js_error_message(error: &JsValue) -> String {
    if let Some(s) = error.as_string() {
        return s;
    }
    if let Some(e) = error.dyn_ref::<web_sys::js_sys::Error>() {
        return String::from(e.message());
    }
    format!("{error:?}")
}
