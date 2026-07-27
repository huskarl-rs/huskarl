use snafu::ResultExt as _;

use crate::{
    error::Error,
    secrets::{SecretBytes, SecretMap, SecretString, encodings::NotUtf8Snafu},
};

/// Interprets bytes as UTF-8 text: the `SecretBytes` → `SecretString` conversion.
///
/// Trims leading/trailing whitespace from the decoded string — this strips the
/// trailing newline you get from `echo secret > file`, env vars, and similar,
/// which is almost never part of the secret. Interior whitespace is preserved
/// (it can be significant, e.g. a passphrase). If your secret has *significant*
/// leading/trailing whitespace, keep it as the raw [`SecretBytes`] (don't apply
/// this conversion) to preserve the exact bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringEncoding;

impl SecretMap for StringEncoding {
    type In = SecretBytes;
    type Out = SecretString;

    fn apply(&self, input: SecretBytes) -> Result<SecretString, Error> {
        let s = std::str::from_utf8(input.expose_secret()).context(NotUtf8Snafu)?;
        Ok(SecretString::new(s.trim()))
    }
}
