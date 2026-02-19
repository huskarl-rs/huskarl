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

/// Secrets output the underlying secret value
#[derive(Debug)]
pub struct SecretOutput<T> {
    /// The secret value.
    pub value: T,
    /// An identity that may be used to derive a key ID when used as key material.
    pub identity: Option<String>,
}

/// Trait for secret retrieval.
pub trait Secret: MaybeSendSync {
    /// The error type returned by this secret source's operations.
    type Error: crate::Error;

    /// The type of secret this source provides.
    type Output: MaybeSendSync;

    /// Retrieves the secret value.
    fn get_secret_value(
        &self,
    ) -> impl Future<Output = Result<SecretOutput<Self::Output>, Self::Error>> + MaybeSend;
}
