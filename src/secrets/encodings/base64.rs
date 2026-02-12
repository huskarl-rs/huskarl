use base64::prelude::*;
use snafu::prelude::*;

use crate::{
    secrecy::SecretBox,
    secrets::{
        DecodingError, SecretDecoder,
        encodings::{InvalidBase64Snafu, InvalidUtf8Snafu},
    },
};

/// Decodes base64-encoded text into `SecretBox<[u8]`.
///
/// Trims whitespace before decoding. Expects the bytes to be valid base64
/// with padding.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64Encoding;

impl SecretDecoder for Base64Encoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        let decoded = BASE64_STANDARD
            .decode(s.trim())
            .context(InvalidBase64Snafu)?;
        Ok(SecretBox::new(decoded.into_boxed_slice()))
    }
}
