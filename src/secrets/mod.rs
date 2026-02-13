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
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

/// A secret string value that avoids accidental exposure in logs and debug output.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretString(secrecy::SecretString);

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl SecretString {
    /// Creates a new `SecretString`.
    #[must_use] 
    pub fn new(secret: String) -> Self {
        SecretString(secret.into())
    }

    /// Exposes the secret string value.
    #[must_use] 
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// A secret byte buffer that avoids accidental exposure in logs and debug output.
#[derive(Debug, Clone)]
pub struct SecretBytes(secrecy::SecretBox<[u8]>);

impl SecretBytes {
    /// Creates a new `SecretBytes`.
    #[must_use] 
    pub fn new(secret: Vec<u8>) -> Self {
        SecretBytes(secrecy::SecretBox::new(secret.into_boxed_slice()))
    }

    /// Exposes the secret byte slice.
    #[must_use] 
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

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
