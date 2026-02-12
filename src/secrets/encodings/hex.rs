use snafu::prelude::*;

use crate::{
    secrecy::SecretBox,
    secrets::{
        DecodingError, SecretDecoder,
        encodings::{InvalidHexSnafu, InvalidUtf8Snafu},
    },
};

/// Decodes hex-encoded text into `SecretBox<[u8]>`.
///
/// Trims whitespace before decoding. Expects the bytes to be valid UTF-8
/// containing hexadecimal characters (0-9, a-f, A-F).
#[derive(Debug, Clone, Copy, Default)]
pub struct HexEncoding;

impl SecretDecoder for HexEncoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        let decoded = hex::decode(s.trim()).context(InvalidHexSnafu)?;
        Ok(SecretBox::new(decoded.into_boxed_slice()))
    }
}
