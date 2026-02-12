//! Encodings for binary secrets.

mod base64;
mod binary;
mod hex;
mod string;

use std::str::Utf8Error;

use snafu::Snafu;

use crate::platform::MaybeSendSync;

pub use base64::Base64Encoding;
pub use binary::BinaryEncoding;
pub use hex::HexEncoding;
pub use string::StringEncoding;

/// Trait for decoding raw bytes into a typed secret.
pub trait SecretDecoder: MaybeSendSync {
    /// The type of secret this encoding produces.
    type Output: MaybeSendSync;

    /// Decodes raw bytes into the secret type.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be decoded (e.g., invalid UTF-8,
    /// invalid hex characters).
    fn decode(&self, bytes: &[u8]) -> Result<Self::Output, DecodingError>;
}

/// Errors that can occur when decoding a secret.
#[derive(Debug, Snafu)]
pub enum DecodingError {
    /// The bytes are not valid UTF-8.
    #[snafu(display("Invalid UTF-8"))]
    InvalidUtf8 {
        /// The underlying error.
        source: Utf8Error,
    },
    /// The string is not valid hexadecimal.
    #[snafu(display("Invalid hex"))]
    InvalidHex {
        /// The underlying error.
        source: ::hex::FromHexError,
    },
    /// The string is not valid base64.
    #[snafu(display("Invalid base64"))]
    InvalidBase64 {
        /// The underlying error.
        source: ::base64::DecodeError,
    },
}
