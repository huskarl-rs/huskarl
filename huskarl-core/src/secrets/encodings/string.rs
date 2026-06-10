use crate::{
    error::{Error, ErrorKind},
    secrets::{SecretDecoder, SecretString},
};

/// Interprets bytes as UTF-8 text, returning a `SecretString`.
///
/// Trims leading/trailing whitespace from the decoded string.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringEncoding;

impl SecretDecoder for StringEncoding {
    type Output = SecretString;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, Error> {
        let s =
            std::str::from_utf8(bytes).map_err(|source| Error::new(ErrorKind::Config, source))?;
        Ok(SecretString::new(s.trim()))
    }
}
