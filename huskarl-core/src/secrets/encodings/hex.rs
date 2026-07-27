use snafu::ResultExt as _;

use crate::{
    error::Error,
    secrets::{
        SecretBytes, SecretMap,
        encodings::{HexSnafu, strip_ascii_whitespace},
    },
};

/// Decodes hex-encoded bytes into `SecretBytes`.
///
/// All ASCII whitespace is stripped before decoding, so space-separated dumps
/// and multi-line copy/pasted secrets are accepted. The remaining bytes must be
/// hexadecimal characters (0-9, a-f, A-F) in even count.
#[derive(Debug, Clone, Copy, Default)]
pub struct HexEncoding;

impl SecretMap for HexEncoding {
    type In = SecretBytes;
    type Out = SecretBytes;

    fn apply(&self, input: SecretBytes) -> Result<SecretBytes, Error> {
        let stripped = strip_ascii_whitespace(input.expose_secret(), |b| b);
        let decoded = hex::decode(&*stripped).context(HexSnafu)?;
        Ok(SecretBytes::new(decoded))
    }
}
