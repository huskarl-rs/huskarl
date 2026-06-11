use snafu::Snafu;
use wasm_bindgen::JsValue;

/// Represents JavaScript errors.
#[derive(Debug, Snafu)]
#[snafu(display("{}", error.as_string().unwrap_or_default()))]
pub struct JsError {
    error: JsValue,
}

impl JsError {
    /// Create a new `JsError` from a `JsValue`.
    pub(crate) fn new(error: JsValue) -> Self {
        Self { error }
    }
}
