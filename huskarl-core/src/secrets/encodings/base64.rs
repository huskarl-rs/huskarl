use base64::{
    Engine,
    alphabet::STANDARD,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

use crate::{
    error::{Error, ErrorKind},
    secrets::{SecretBytes, SecretMap, encodings::strip_ascii_whitespace},
};

/// A forgiving base64 decoder: standard alphabet with padding treated as
/// optional. Url-safe input (`-_`) is normalized to the standard alphabet
/// (`+/`) before decoding, so all four standard/url-safe × padded/unpadded
/// combinations are accepted. Trailing-bit canonicality is still enforced.
const FORGIVING: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Decodes base64-encoded bytes into `SecretBytes`.
///
/// Accepts both the standard (`+/`) and url-safe (`-_`) alphabets, with padding
/// optional, and strips all ASCII whitespace first — so MIME/PEM-wrapped,
/// multi-line, and JWK-style (base64url, unpadded) secrets all decode. The
/// non-whitespace bytes must otherwise be valid base64.
#[derive(Debug, Clone, Copy, Default)]
pub struct Base64Encoding;

impl SecretMap for Base64Encoding {
    type In = SecretBytes;
    type Out = SecretBytes;

    fn apply(&self, input: SecretBytes) -> Result<SecretBytes, Error> {
        // Fold url-safe → standard alphabet normalization into the same pass
        // that strips whitespace, so `FORGIVING` (standard alphabet) handles
        // both alphabets without a second copy of the secret.
        let stripped = strip_ascii_whitespace(input.expose_secret(), |b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        });
        let decoded = FORGIVING
            .decode(&*stripped)
            .map_err(|source| Error::new(ErrorKind::Config, source))?;
        Ok(SecretBytes::new(decoded))
    }
}
