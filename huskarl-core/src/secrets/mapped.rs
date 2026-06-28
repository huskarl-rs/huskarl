//! `Secret` as a functor over its output: [`MappedSecret`] transforms the
//! value an inner source produces while leaving the source untouched.
//!
//! One decorator covers every transform. A named [`SecretMap`] (via
//! [`Secret::mapped`]) can be stored in a provider field and selected behind
//! `dyn`; a closure (via [`Secret::map`]/[`Secret::try_map`]) is the
//! convenient form at a call site where you consume the secret — [`FnMap`]
//! and [`TryFnMap`] adapt it into a [`SecretMap`] under the hood.

use std::marker::PhantomData;

use crate::{
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
    secrets::{Secret, SecretMap, SecretOutput},
};

/// A [`Secret`] decorator that transforms an inner source's value through a
/// [`SecretMap`].
///
/// This makes the *mapping* orthogonal to *where the secret comes from*: wrap
/// any [`Secret`] whose output is the map's input — a file, your own vault
/// client, anything — and a [`SecretMap`]
/// ([`Base64Encoding`](super::encodings::Base64Encoding),
/// [`HexEncoding`](super::encodings::HexEncoding),
/// [`StringEncoding`](super::encodings::StringEncoding), …) produces the typed
/// value. The inner source's `identity` is passed through unchanged.
///
/// Created via [`Secret::mapped`] with a named map, or [`Secret::map`]/
/// [`Secret::try_map`] with a closure (adapted through [`FnMap`]/[`TryFnMap`]).
/// With a named map `M` the whole decorator's type can be written, so it can be
/// stored in a struct field (a closure's type cannot). The map runs on every
/// [`get_secret_value`](Secret::get_secret_value), so a rotating source is
/// re-mapped each fetch; wrap the result in [`CachedSecret`](super::CachedSecret)
/// to memoize.
#[derive(Clone)]
pub struct MappedSecret<S, M> {
    inner: S,
    map: M,
    /// Context prefixed onto mapping failures (e.g. the source's file path).
    /// Defaults to a generic description when unset.
    context: Option<String>,
}

impl<S, M> MappedSecret<S, M> {
    /// Wraps `inner`, applying `map` to its value on each fetch.
    pub fn new(inner: S, map: M) -> Self {
        Self {
            inner,
            map,
            context: None,
        }
    }

    /// Sets the context prefixed onto mapping failures, identifying the source
    /// (for example `"decoding secret file /run/secret"`). Without it, errors
    /// carry a generic `"mapping secret value"` prefix.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

impl<S, M> std::fmt::Debug for MappedSecret<S, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappedSecret").finish_non_exhaustive()
    }
}

impl<S, M> Secret for MappedSecret<S, M>
where
    S: Secret,
    M: SecretMap<In = S::Output>,
{
    type Output = M::Out;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
        Box::pin(async move {
            let input = self.inner.get_secret_value().await?;
            let value = self.map.apply(input.value).map_err(|err| {
                err.with_context(
                    self.context
                        .clone()
                        .unwrap_or_else(|| "mapping secret value".to_owned()),
                )
            })?;
            Ok(SecretOutput {
                value,
                identity: input.identity,
            })
        })
    }
}

/// An infallible closure adapted into a [`SecretMap`]. Created by
/// [`Secret::map`].
///
/// The `In` parameter pins the closure's argument type (a bare `F` would leave
/// it undetermined for the `impl`); it is phantom, so `FnMap` is exactly the
/// closure at runtime.
pub struct FnMap<F, In> {
    f: F,
    _in: PhantomData<fn(In)>,
}

impl<F, In> FnMap<F, In> {
    /// Adapts `f` into a [`SecretMap`].
    pub fn new(f: F) -> Self {
        Self {
            f,
            _in: PhantomData,
        }
    }
}

impl<F: Clone, In> Clone for FnMap<F, In> {
    fn clone(&self) -> Self {
        Self::new(self.f.clone())
    }
}

impl<F, In> std::fmt::Debug for FnMap<F, In> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnMap").finish_non_exhaustive()
    }
}

impl<F, In, Out> SecretMap for FnMap<F, In>
where
    F: Fn(In) -> Out + MaybeSendSync,
    Out: Clone + MaybeSendSync,
{
    type In = In;
    type Out = Out;

    fn apply(&self, input: In) -> Result<Out, Error> {
        Ok((self.f)(input))
    }
}

/// A fallible closure adapted into a [`SecretMap`]. Created by
/// [`Secret::try_map`].
///
/// The `In` parameter pins the closure's argument type (a bare `F` would leave
/// it undetermined for the `impl`); it is phantom, so `TryFnMap` is exactly the
/// closure at runtime.
pub struct TryFnMap<F, In> {
    f: F,
    _in: PhantomData<fn(In)>,
}

impl<F, In> TryFnMap<F, In> {
    /// Adapts the fallible `f` into a [`SecretMap`].
    pub fn new(f: F) -> Self {
        Self {
            f,
            _in: PhantomData,
        }
    }
}

impl<F: Clone, In> Clone for TryFnMap<F, In> {
    fn clone(&self) -> Self {
        Self::new(self.f.clone())
    }
}

impl<F, In> std::fmt::Debug for TryFnMap<F, In> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TryFnMap").finish_non_exhaustive()
    }
}

impl<F, In, Out> SecretMap for TryFnMap<F, In>
where
    F: Fn(In) -> Result<Out, Error> + MaybeSendSync,
    Out: Clone + MaybeSendSync,
{
    type In = In;
    type Out = Out;

    fn apply(&self, input: In) -> Result<Out, Error> {
        (self.f)(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::ErrorKind,
        secrets::{
            SecretBytes, SecretString, WithIdentity,
            encodings::{Base64Encoding, StringToBytes},
        },
    };

    /// A source that hands back fixed encoded bytes (here, base64 of "hello").
    #[derive(Clone)]
    struct BytesSource(&'static [u8]);

    impl Secret for BytesSource {
        type Output = SecretBytes;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                Ok(SecretOutput {
                    value: SecretBytes::new(self.0.to_vec()),
                    identity: None,
                })
            })
        }
    }

    /// A fixed `SecretString` source.
    #[derive(Clone)]
    struct StringSource(&'static str);

    impl Secret for StringSource {
        type Output = SecretString;

        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, Error>> {
            Box::pin(async move {
                Ok(SecretOutput {
                    value: SecretString::new(self.0),
                    identity: None,
                })
            })
        }
    }

    // ── Named maps ────────────────────────────────────────────────────────
    #[tokio::test]
    async fn maps_inner_bytes_through_named_map() {
        let secret = MappedSecret::new(BytesSource(b"aGVsbG8="), Base64Encoding);
        let out = secret.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), b"hello");
    }

    #[tokio::test]
    async fn preserves_identity_from_inner() {
        // Identity is set on the inner source and must survive the mapping.
        let inner = WithIdentity::new(BytesSource(b"aGVsbG8="), "kid-1");
        let secret = MappedSecret::new(inner, Base64Encoding);
        let out = secret.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), b"hello");
        assert_eq!(out.identity.as_deref(), Some("kid-1"));
    }

    #[tokio::test]
    async fn surfaces_map_error_as_config_with_default_context() {
        let secret = MappedSecret::new(BytesSource(b"not base64 !!"), Base64Encoding);
        let err = secret.get_secret_value().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(
            err.to_string().contains("mapping secret value"),
            "expected default context in: {err}"
        );
    }

    #[tokio::test]
    async fn context_prefixes_errors() {
        let secret = MappedSecret::new(BytesSource(b"not base64 !!"), Base64Encoding)
            .with_context("decoding the widget key");
        let err = secret.get_secret_value().await.unwrap_err();
        assert!(
            err.to_string().contains("decoding the widget key"),
            "expected custom context in: {err}"
        );
    }

    /// A string-yielding source chained through two maps: `StringToBytes` then
    /// `Base64Encoding`. This is the AWS-string-contains-base64 shape, and it
    /// exercises the generalization beyond byte-only inputs.
    #[tokio::test]
    async fn chains_string_to_bytes_then_decode() {
        let secret = StringSource("aGVsbG8=")
            .mapped(StringToBytes)
            .mapped(Base64Encoding);
        let out = secret.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), b"hello");
    }

    // ── Closure maps (FnMap / TryFnMap via Secret::map / try_map) ─────────
    /// `map` is the AWS-style string → bytes view: an infallible value transform.
    #[tokio::test]
    async fn map_transforms_value_and_keeps_identity() {
        let secret = WithIdentity::new(StringSource("hello"), "kid-1")
            .map(|s: SecretString| SecretBytes::new(s.expose_secret().as_bytes().to_vec()));
        let out = secret.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), b"hello");
        assert_eq!(out.identity.as_deref(), Some("kid-1"));
    }

    #[tokio::test]
    async fn try_map_propagates_function_error() {
        let secret = StringSource("hello")
            .try_map(|_s| Err::<SecretBytes, _>(Error::from(ErrorKind::Config)));
        let err = secret.get_secret_value().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Config);
    }

    #[tokio::test]
    async fn try_map_passes_through_on_success() {
        let secret = StringSource("42")
            .try_map(|s: SecretString| Ok(SecretString::new(s.expose_secret().repeat(2))));
        let out = secret.get_secret_value().await.unwrap();
        assert_eq!(out.value.expose_secret(), "4242");
    }

    /// Closure transforms get the same error-context hook as named maps —
    /// the payoff of the unified decorator.
    #[tokio::test]
    async fn try_map_error_carries_context() {
        let secret = StringSource("hello")
            .try_map(|_s| Err::<SecretBytes, _>(Error::from(ErrorKind::Config)))
            .with_context("parsing the vault payload");
        let err = secret.get_secret_value().await.unwrap_err();
        assert!(
            err.to_string().contains("parsing the vault payload"),
            "expected custom context in: {err}"
        );
    }
}
