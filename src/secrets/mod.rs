//! Async secret access.
//!
//! This module provides the ability to access string and binary
//! secrets, including decoding some basic encodings like Base64
//! and hex.

pub mod encodings;
mod providers;

use crate::platform::{MaybeSend, MaybeSendSync};

pub use encodings::{DecodingError, SecretDecoder};
pub use providers::EnvVarSecret;

/// Trait for secret retrieval.
pub trait Secret: MaybeSendSync {
    /// The error type returned by this secret source's operations.
    type Error: crate::Error;

    /// The type of secret this source provides.
    type Output: MaybeSendSync;

    /// Retrieves the secret value.
    fn get_secret_value(
        &self,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + MaybeSend;
}
