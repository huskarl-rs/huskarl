use crate::{
    error::{Error, ErrorKind},
    secrets::{SecretBytes, SecretDecoder},
};

/// Decodes hex-encoded text into `SecretBytes`.
///
/// Trims leading and trailing whitespace before decoding (interior whitespace
/// is not allowed). Expects the bytes to be valid UTF-8 containing hexadecimal
/// characters (0-9, a-f, A-F).
#[derive(Debug, Clone, Copy, Default)]
pub struct HexEncoding;

impl SecretDecoder for HexEncoding {
    type Output = SecretBytes;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, Error> {
        let s =
            std::str::from_utf8(bytes).map_err(|source| Error::new(ErrorKind::Config, source))?;
        let decoded =
            hex::decode(s.trim()).map_err(|source| Error::new(ErrorKind::Config, source))?;
        Ok(SecretBytes::new(decoded))
    }
}
