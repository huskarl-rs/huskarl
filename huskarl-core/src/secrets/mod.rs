//! Async secret access.
//!
//! This module provides the ability to access string and binary
//! secrets, including decoding some basic encodings like Base64
//! and hex.

mod cached;
mod providers;

pub mod encodings;

pub use cached::CachedSecret;
pub use encodings::{DecodingError, SecretDecoder};
pub use providers::EnvVarSecret;
#[cfg(feature = "fs")]
pub use providers::{FileSecret, FileSecretError};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use crate::platform::{MaybeSend, MaybeSendSync};

/// A secret string value that avoids accidental exposure in logs and debug output.
#[derive(Debug, Clone)]
pub struct SecretString(secrecy::SecretString);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

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
    pub fn new(secret: impl AsRef<str>) -> Self {
        SecretString(secret.as_ref().into())
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
#[derive(Debug, Clone)]
pub struct SecretOutput<T: Clone> {
    /// The secret value.
    pub value: T,
    /// An identity that may be used to derive a key ID when used as key material.
    pub identity: Option<String>,
}

/// Trait for secret retrieval.
pub trait Secret: Clone + MaybeSendSync {
    /// The error type returned by this secret source's operations.
    type Error: crate::Error;

    /// The type of secret this source provides.
    type Output: Clone + MaybeSendSync;

    /// Retrieves the secret value.
    fn get_secret_value(
        &self,
    ) -> impl Future<Output = Result<SecretOutput<Self::Output>, Self::Error>> + MaybeSend;
}

/// A wrapper that adds an identity to an existing secret.
#[derive(Debug, Clone)]
pub struct WithIdentity<S: Secret> {
    inner: S,
    identity: String,
}

impl<S: Secret> WithIdentity<S> {
    /// Creates a new wrapper that adds the given identity to the secret.
    pub fn new(inner: S, identity: impl Into<String>) -> Self {
        Self {
            inner,
            identity: identity.into(),
        }
    }
}

impl<S: Secret> Secret for WithIdentity<S> {
    type Output = S::Output;
    type Error = S::Error;

    async fn get_secret_value(&self) -> Result<SecretOutput<Self::Output>, Self::Error> {
        let mut output = self.inner.get_secret_value().await?;
        output.identity = Some(self.identity.clone());
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    #[derive(Clone)]
    struct MockSecret(SecretString);

    impl Secret for MockSecret {
        type Output = SecretString;
        type Error = Infallible;

        async fn get_secret_value(&self) -> Result<SecretOutput<Self::Output>, Self::Error> {
            Ok(SecretOutput {
                value: self.0.clone(),
                identity: None,
            })
        }
    }

    #[tokio::test]
    async fn test_with_identity() {
        let secret = MockSecret(SecretString::new("secret"));
        let with_id = WithIdentity::new(secret, "my-id");

        let output = with_id.get_secret_value().await.unwrap();
        assert_eq!(output.value.expose_secret(), "secret");
        assert_eq!(output.identity.unwrap(), "my-id");
    }
}
