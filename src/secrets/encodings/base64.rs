use base64::prelude::*;
use snafu::prelude::*;

use crate::secrets::{
    DecodingError, SecretBytes, SecretDecoder,
    encodings::{InvalidBase64Snafu, InvalidUtf8Snafu},
};

/// Decodes base64-encoded text into `SecretBytes`.
///
/// Trims whitespace before decoding. Expects the bytes to be valid base64
/// with padding.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64Encoding;

impl SecretDecoder for Base64Encoding {
    type Output = SecretBytes;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        let decoded = BASE64_STANDARD
            .decode(s.trim())
            .context(InvalidBase64Snafu)?;
        Ok(SecretBytes::new(decoded))
    }
}
