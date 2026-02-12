use crate::{
    secrecy::SecretBox,
    secrets::{DecodingError, SecretDecoder},
};

/// Uses raw bytes directly, returning `SecretBox<[u8]>`.
///
/// No transformation is applied - bytes pass through as-is.
#[derive(Debug, Clone, Copy, Default)]
pub struct BinaryEncoding;

impl SecretDecoder for BinaryEncoding {
    type Output = SecretBox<[u8]>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError> {
        Ok(SecretBox::new(bytes.to_vec().into_boxed_slice()))
    }
}
