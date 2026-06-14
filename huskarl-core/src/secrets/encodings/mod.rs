//! Encodings for binary secrets.

mod base64;
mod binary;
mod hex;
mod string;

use std::sync::Arc;

pub use base64::Base64Encoding;
pub use binary::BinaryEncoding;
pub use hex::HexEncoding;
pub use string::StringEncoding;

use crate::{error::Error, platform::MaybeSendSync};

/// Trait for decoding raw bytes into a typed secret.
pub trait SecretDecoder: MaybeSendSync {
    /// The type of secret this encoding produces.
    type Output: Clone + MaybeSendSync;

    /// Decodes raw bytes into the secret type.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Config`](crate::error::ErrorKind::Config) if the
    /// bytes cannot be decoded (e.g., invalid UTF-8, invalid hex characters).
    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, Error>;
}

impl<T: SecretDecoder + ?Sized> SecretDecoder for &T {
    type Output = T::Output;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, Error> {
        (**self).decode(bytes)
    }
}

impl<T: SecretDecoder + ?Sized> SecretDecoder for Box<T> {
    type Output = T::Output;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, Error> {
        (**self).decode(bytes)
    }
}

impl<T: SecretDecoder + ?Sized> SecretDecoder for Arc<T> {
    type Output = T::Output;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, Error> {
        (**self).decode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::{error::ErrorKind, secrets::SecretBytes};

    use super::*;

    // ── BinaryEncoding ────────────────────────────────────────────────────
    #[test]
    fn binary_passes_bytes_through_untouched() {
        // Includes whitespace and invalid UTF-8 — none of it is altered.
        let raw = b"\x00\xff \n\x80";
        let out = BinaryEncoding.decode(raw).unwrap();
        assert_eq!(out.expose_secret(), raw);
    }

    // ── StringEncoding ────────────────────────────────────────────────────
    #[test]
    fn string_decodes_utf8_and_trims_surrounding_whitespace() {
        let out = StringEncoding.decode(b"  hunter2\n").unwrap();
        assert_eq!(out.expose_secret(), "hunter2");
    }

    /// Sharp edge worth pinning: only the *ends* are trimmed — interior
    /// whitespace is part of the secret.
    #[test]
    fn string_preserves_interior_whitespace() {
        let out = StringEncoding.decode(b"a b\tc").unwrap();
        assert_eq!(out.expose_secret(), "a b\tc");
    }

    #[test]
    fn string_rejects_invalid_utf8() {
        let err = StringEncoding.decode(b"\xff\xfe").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    // ── HexEncoding ───────────────────────────────────────────────────────
    #[test]
    fn hex_decodes_mixed_case_and_trims() {
        let out = HexEncoding.decode(b"  DeadBeef\n").unwrap();
        assert_eq!(out.expose_secret(), b"\xde\xad\xbe\xef");
    }

    #[rstest]
    #[case::odd_length(b"abc")]
    #[case::non_hex_character(b"zz")]
    #[case::invalid_utf8(b"\xff")]
    fn hex_rejects_invalid_input(#[case] input: &[u8]) {
        let err = HexEncoding.decode(input).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    // ── Base64Encoding ────────────────────────────────────────────────────
    #[test]
    fn base64_decodes_standard_with_padding_and_trims_ends() {
        // base64("hello") == "aGVsbG8="
        let out = Base64Encoding.decode(b"  aGVsbG8=\n").unwrap();
        assert_eq!(out.expose_secret(), b"hello");
    }

    /// `interior_newline` pins a sharp edge: `trim()` only strips the ends, so a
    /// multi-line (PEM-style) base64 body is rejected by the standard alphabet —
    /// despite the "trims whitespace" doc comment.
    #[rstest]
    #[case::not_base64(b"not_valid_base64!!")]
    #[case::invalid_utf8(b"\xff\xff")]
    #[case::interior_newline(b"aGVs\nbG8=")]
    fn base64_rejects_invalid_input(#[case] input: &[u8]) {
        let err = Base64Encoding.decode(input).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    // ── Blanket impls (&T / Box / Arc) ────────────────────────────────────
    #[test]
    fn blanket_impls_delegate_to_inner() {
        let raw = b"abc";

        assert_eq!(BinaryEncoding.decode(raw).unwrap().expose_secret(), raw);

        let boxed: Box<dyn SecretDecoder<Output = SecretBytes>> = Box::new(BinaryEncoding);
        assert_eq!(boxed.decode(raw).unwrap().expose_secret(), raw);

        let arced: Arc<dyn SecretDecoder<Output = SecretBytes>> = Arc::new(BinaryEncoding);
        assert_eq!(arced.decode(raw).unwrap().expose_secret(), raw);
    }
}
