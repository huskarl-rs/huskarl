//! Async secret access.
//!
//! Retrieves string and binary secrets — from environment variables, files, or
//! your own provider — behind the [`Secret`] trait, handing them back in the
//! redacted [`SecretString`]/[`SecretBytes`] wrappers. A [`SecretMap`] (see
//! [`encodings`]) maps between secret types — decoding (Base64, hex), the UTF-8
//! conversion, and value transforms are all instances.
//!
//! Sources compose via decorators: [`MappedSecret`] applies a [`SecretMap`] to
//! any [`Secret`] whose output matches the map's input (so a mapping is
//! orthogonal to its source), and [`CachedSecret`] memoizes a value with a TTL.
//! [`Secret`] is thus a functor over its output — [`Secret::mapped`] takes a
//! named map that can be stored and selected behind `dyn`, while
//! [`Secret::map`]/[`Secret::try_map`] take a closure for one-off transforms at
//! a call site.
//!
//! See [providing secrets](crate::_docs::guide::providing_secrets) for a
//! task-oriented guide.

mod cached;
mod mapped;
mod providers;

pub mod encodings;

use std::sync::Arc;

pub use cached::CachedSecret;
pub use encodings::SecretMap;
pub use mapped::{FnMap, MappedSecret, TryFnMap};
pub use providers::EnvVarSecret;
#[cfg(feature = "fs")]
pub use providers::{FileBytes, FileSecret};
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

    /// Applies a named [`SecretMap`] to this source, returning a
    /// [`MappedSecret`].
    ///
    /// Convenience for [`MappedSecret::new`]; available on any source whose
    /// output matches the map's input (e.g. a byte source + a decoder, or a
    /// string source + [`StringToBytes`](encodings::StringToBytes)). The map runs
    /// on every fetch — wrap the result in [`CachedSecret`] to memoize. Use this
    /// over [`map`](Secret::map)/[`try_map`](Secret::try_map) when the result must
    /// be stored in a struct field, since a named map's type can be written.
    fn mapped<M>(self, map: M) -> MappedSecret<Self, M>
    where
        Self: Sized,
        M: SecretMap<In = Self::Output>,
    {
        MappedSecret::new(self, map)
    }

    /// Transforms the produced value with `f`.
    ///
    /// The transform is infallible and the source's `identity` is preserved.
    /// For example, view a string source as bytes with
    /// `s.map(|t| SecretBytes::new(...))`. Use [`try_map`](Secret::try_map)
    /// when the transform can fail, or [`mapped`](Secret::mapped) with a named
    /// [`SecretMap`] when the result must be stored in a struct field.
    fn map<F, B>(self, f: F) -> MappedSecret<Self, FnMap<F, Self::Output>>
    where
        Self: Sized,
        F: Fn(Self::Output) -> B + MaybeSendSync,
        B: Clone + MaybeSendSync,
    {
        MappedSecret::new(self, FnMap::new(f))
    }

    /// Transforms the produced value with the fallible `f`.
    ///
    /// The fallible version of [`map`](Secret::map): a function error
    /// propagates as the fetch error, and the source's `identity` is preserved.
    /// [`mapped`](Secret::mapped) is this with a *named* [`SecretMap`] instead
    /// of a closure; reach for that when the result must be stored in a struct
    /// field, since a closure's type can't be named there.
    fn try_map<F, B>(self, f: F) -> MappedSecret<Self, TryFnMap<F, Self::Output>>
    where
        Self: Sized,
        F: Fn(Self::Output) -> Result<B, Error> + MaybeSendSync,
        B: Clone + MaybeSendSync,
    {
        MappedSecret::new(self, TryFnMap::new(f))
    }
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
