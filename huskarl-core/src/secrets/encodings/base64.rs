use base64::prelude::*;

use crate::{
    error::{Error, ErrorKind},
    secrets::{SecretBytes, SecretDecoder},
};

/// Decodes base64-encoded text into `SecretBytes`.
///
/// Trims leading and trailing whitespace before decoding (interior whitespace
/// is not allowed). Expects the bytes to be valid base64 with padding.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64Encoding;

impl SecretDecoder for Base64Encoding {
    type Output = SecretBytes;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, Error> {
        let s =
            std::str::from_utf8(bytes).map_err(|source| Error::new(ErrorKind::Config, source))?;
        let decoded = BASE64_STANDARD
            .decode(s.trim())
            .map_err(|source| Error::new(ErrorKind::Config, source))?;
        Ok(SecretBytes::new(decoded))
    }
}
