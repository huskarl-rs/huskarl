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
