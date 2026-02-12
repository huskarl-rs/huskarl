use snafu::prelude::*;

use crate::secrets::{DecodingError, SecretDecoder, SecretString, encodings::InvalidUtf8Snafu};

/// Interprets bytes as UTF-8 text, returning a `SecretString`.
///
/// Trims leading/trailing whitespace from the decoded string.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringEncoding;

impl SecretDecoder for StringEncoding {
    type Output = SecretString;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        let s = std::str::from_utf8(bytes).context(InvalidUtf8Snafu)?;
        Ok(SecretString::new(s.trim().to_string()))
    }
}
