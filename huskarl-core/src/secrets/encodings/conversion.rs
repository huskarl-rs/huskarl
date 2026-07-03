use crate::{
    error::Error,
    secrets::{SecretBytes, SecretMap, SecretString},
};

/// Views a `SecretString` as its UTF-8 bytes: the `SecretString` → `SecretBytes`
/// conversion.
///
/// The inverse of [`StringEncoding`](super::StringEncoding). Useful to bridge a
/// string-yielding source into a byte-input decoder — e.g. an AWS Secrets
/// Manager string whose contents are themselves base64:
/// `aws_string.mapped(StringToBytes).mapped(Base64Encoding)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringToBytes;

impl SecretMap for StringToBytes {
    type In = SecretString;
    type Out = SecretBytes;

    fn apply(&self, input: SecretString) -> Result<SecretBytes, Error> {
        Ok(SecretBytes::new(input.expose_secret().as_bytes().to_vec()))
    }
}
