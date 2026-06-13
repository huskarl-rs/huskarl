//! Async secret access.
//!
//! This module provides the ability to access string and binary
//! secrets, including decoding some basic encodings like Base64
//! and hex.

mod cached;
mod providers;

pub mod encodings;

use std::sync::Arc;

pub use cached::CachedSecret;
pub use encodings::SecretDecoder;
pub use providers::EnvVarSecret;
#[cfg(feature = "fs")]
pub use providers::FileSecret;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

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

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
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
///
/// This trait is dyn-capable (per output type): consumers store it as
/// `Arc<dyn Secret<Output = SecretString>>` and the like.
///
/// # Implementing
///
/// Write the method body as `Box::pin(async move { ... })`. Transient fetch
/// failures (a vault timeout, `WouldBlock`) classify as
/// [`ErrorKind::Transport`](crate::error::ErrorKind::Transport) with
/// `retryable: true`; persistent ones (missing file, bad permissions, bad
/// data) as [`ErrorKind::Config`](crate::error::ErrorKind::Config).
pub trait Secret: MaybeSendSync {
    /// The type of secret this source provides.
    type Output: Clone + MaybeSendSync;

    /// Retrieves the secret value.
    fn get_secret_value(&self)
    -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>>;
}

impl<T: Secret + ?Sized> Secret for &T {
    type Output = T::Output;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        (**self).get_secret_value()
    }
}

impl<T: Secret + ?Sized> Secret for Box<T> {
    type Output = T::Output;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        (**self).get_secret_value()
    }
}

impl<T: Secret + ?Sized> Secret for Arc<T> {
    type Output = T::Output;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        (**self).get_secret_value()
    }
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

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        Box::pin(async move {
            let mut output = self.inner.get_secret_value().await?;
            output.identity = Some(self.identity.clone());
            Ok(output)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSecret(SecretString);

    impl Secret for MockSecret {
        type Output = SecretString;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                Ok(SecretOutput {
                    value: self.0.clone(),
                    identity: None,
                })
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

    #[tokio::test]
    async fn erased_secret_dispatches() {
        let secret: Arc<dyn Secret<Output = SecretString>> =
            Arc::new(MockSecret(SecretString::new("erased")));
        let output = secret.get_secret_value().await.unwrap();
        assert_eq!(output.value.expose_secret(), "erased");
    }
}
