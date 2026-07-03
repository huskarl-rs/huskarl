//! Named mappings between secret types: decoders, conversions, and transforms.

mod base64;
mod conversion;
mod hex;
mod string;

use std::sync::Arc;

pub use base64::Base64Encoding;
pub use conversion::StringToBytes;
pub use hex::HexEncoding;
pub use string::StringEncoding;
use zeroize::Zeroizing;

use crate::{error::Error, platform::MaybeSendSync};

/// Copies `bytes` with all ASCII whitespace removed, applying `map` to each
/// retained byte.
///
/// The result is held in a [`Zeroizing`] buffer so the whitespace-stripped
/// (still effectively cleartext) secret is wiped on drop, including on the
/// decode error path. The buffer is pre-sized to `bytes.len()` so the fill
/// never reallocates — a growth realloc would memcpy the secret to a fresh
/// allocation and free the old one without zeroing it.
///
/// `map` lets a caller fold a per-byte transform (e.g. base64 url-safe → standard
/// alphabet normalization) into the same single pass, avoiding a second copy.
fn strip_ascii_whitespace(bytes: &[u8], map: impl Fn(u8) -> u8) -> Zeroizing<Vec<u8>> {
    let mut stripped = Zeroizing::new(Vec::with_capacity(bytes.len()));
    stripped.extend(
        bytes
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .map(map),
    );
    stripped
}

/// A named, reusable mapping from one secret type to another.
///
/// This is the unifying abstraction over what used to be separate ideas:
/// decoders (`SecretBytes` → `SecretBytes`, e.g. [`Base64Encoding`]), the UTF-8
/// view ([`StringEncoding`]: `SecretBytes` → [`SecretString`](crate::secrets::SecretString)),
/// the reverse conversion ([`StringToBytes`]), and value transforms like
/// JSON-field extraction. The wrapper types are the objects; a `SecretMap` is an
/// arrow between them.
///
/// Implemented by *named* (usually zero-size) types rather than closures, so a
/// mapping can be stored in a provider field, selected from configuration behind
/// `dyn`, and carry its own configuration. For a one-off closure at a call site,
/// prefer [`Secret::map`](crate::secrets::Secret::map) /
/// [`try_map`](crate::secrets::Secret::try_map) instead — they trade nameability
/// for convenience.
pub trait SecretMap: MaybeSendSync {
    /// The secret type this mapping consumes.
    type In;
    /// The secret type this mapping produces.
    type Out: Clone + MaybeSendSync;

    /// Applies the mapping, consuming `input`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`](crate::error::ErrorKind::Config) if `input`
    /// cannot be mapped (e.g. invalid base64, non-UTF-8 bytes).
    fn apply(&self, input: Self::In) -> Result<Self::Out, Error>;
}

impl<T: SecretMap + ?Sized> SecretMap for &T {
    type In = T::In;
    type Out = T::Out;

    fn apply(&self, input: Self::In) -> Result<Self::Out, Error> {
        (**self).apply(input)
    }
}

impl<T: SecretMap + ?Sized> SecretMap for Box<T> {
    type In = T::In;
    type Out = T::Out;

    fn apply(&self, input: Self::In) -> Result<Self::Out, Error> {
        (**self).apply(input)
    }
}

impl<T: SecretMap + ?Sized> SecretMap for Arc<T> {
    type In = T::In;
    type Out = T::Out;

    fn apply(&self, input: Self::In) -> Result<Self::Out, Error> {
        (**self).apply(input)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::{
        error::ErrorKind,
        secrets::{SecretBytes, SecretString},
    };

    /// Wraps raw bytes for feeding into a byte-input mapping.
    fn bytes(raw: &[u8]) -> SecretBytes {
        SecretBytes::new(raw.to_vec())
    }

    // ── StringEncoding (SecretBytes → SecretString) ───────────────────────
    #[test]
    fn string_decodes_utf8_and_trims_surrounding_whitespace() {
        let out = StringEncoding.apply(bytes(b"  hunter2\n")).unwrap();
        assert_eq!(out.expose_secret(), "hunter2");
    }

    /// Sharp edge worth pinning: only the *ends* are trimmed — interior
    /// whitespace is part of the secret.
    #[test]
    fn string_preserves_interior_whitespace() {
        let out = StringEncoding.apply(bytes(b"a b\tc")).unwrap();
        assert_eq!(out.expose_secret(), "a b\tc");
    }

    #[test]
    fn string_rejects_invalid_utf8() {
        let err = StringEncoding.apply(bytes(b"\xff\xfe")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    // ── StringToBytes (SecretString → SecretBytes) ────────────────────────
    #[test]
    fn string_to_bytes_exposes_utf8_bytes() {
        let out = StringToBytes.apply(SecretString::new("hello")).unwrap();
        assert_eq!(out.expose_secret(), b"hello");
    }

    // ── HexEncoding (SecretBytes → SecretBytes) ───────────────────────────
    /// All ASCII whitespace is stripped, so surrounding, interior, multi-line,
    /// and CRLF-wrapped forms all decode to the same bytes.
    #[rstest]
    #[case::surrounding_whitespace(b"  DeadBeef\n")]
    #[case::interior_spaces(b"de ad be ef")]
    #[case::multi_line(b"dead\nbeef")]
    #[case::crlf_wrapped(b"de\r\nad\r\nbe\r\nef")]
    fn hex_decodes_mixed_case_stripping_all_whitespace(#[case] input: &[u8]) {
        let out = HexEncoding.apply(bytes(input)).unwrap();
        assert_eq!(out.expose_secret(), b"\xde\xad\xbe\xef");
    }

    #[rstest]
    #[case::odd_length(b"abc")]
    #[case::non_hex_character(b"zz")]
    #[case::non_hex_byte(b"\xff")]
    fn hex_rejects_invalid_input(#[case] input: &[u8]) {
        let err = HexEncoding.apply(bytes(input)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    // ── Base64Encoding (SecretBytes → SecretBytes) ────────────────────────
    /// Forgiving: both alphabets, padding optional, all ASCII whitespace
    /// stripped. base64("hello") == "aGVsbG8=" (standard) == "aGVsbG8" (no pad).
    /// The bytes `fb ff be` encode using index 62/63: `+/++` (standard) and
    /// `-_--` (url-safe) — the pair that exercises alphabet normalization.
    #[rstest]
    #[case::standard_padded(b"aGVsbG8=", b"hello")]
    #[case::standard_no_pad(b"aGVsbG8", b"hello")]
    #[case::surrounding_whitespace(b"  aGVsbG8=\n", b"hello")]
    #[case::interior_newline(b"aGVs\nbG8=", b"hello")]
    #[case::crlf_wrapped(b"aGVs\r\nbG8=", b"hello")]
    #[case::standard_alphabet(b"+/++", b"\xfb\xff\xbe")]
    #[case::url_safe_alphabet(b"-_--", b"\xfb\xff\xbe")]
    fn base64_decodes_forgivingly(#[case] input: &[u8], #[case] expected: &[u8]) {
        let out = Base64Encoding.apply(bytes(input)).unwrap();
        assert_eq!(out.expose_secret(), expected);
    }

    #[rstest]
    #[case::not_base64(b"not_valid_base64!!")]
    #[case::non_base64_bytes(b"\xff\xff")]
    fn base64_rejects_invalid_input(#[case] input: &[u8]) {
        let err = Base64Encoding.apply(bytes(input)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    // ── Blanket impls (&T / Box / Arc) ────────────────────────────────────
    #[test]
    fn blanket_impls_delegate_to_inner() {
        let input = || bytes(b"deadbeef");
        let expected = b"\xde\xad\xbe\xef";

        assert_eq!(
            HexEncoding.apply(input()).unwrap().expose_secret(),
            expected
        );

        let boxed: Box<dyn SecretMap<In = SecretBytes, Out = SecretBytes>> = Box::new(HexEncoding);
        assert_eq!(boxed.apply(input()).unwrap().expose_secret(), expected);

        let arced: Arc<dyn SecretMap<In = SecretBytes, Out = SecretBytes>> = Arc::new(HexEncoding);
        assert_eq!(arced.apply(input()).unwrap().expose_secret(), expected);
    }
}
