use crate::secrets::{DecodingError, SecretBytes, SecretDecoder};

/// Uses raw bytes directly, returning `SecretBytes`.
///
/// No transformation is applied - bytes pass through as-is.
#[derive(Debug, Clone, Copy, Default)]
pub struct BinaryEncoding;

impl SecretDecoder for BinaryEncoding {
    type Output = SecretBytes;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        Ok(SecretBytes::new(bytes.to_vec()))
    }
}
