//! JWS Verification traits.

use std::{pin::Pin, sync::Arc};

use crate::{
    BoxedError, EndpointUrl,
    crypto::{
        KeyMatchStrength,
        verifier::error::{CreateVerifierError, VerifyError},
    },
    jwk::PublicJwk,
    platform::{MaybeSend, MaybeSendFuture, MaybeSendSync},
};

/// Boxed JWS verifier.
#[derive(Debug, Clone)]
pub struct BoxedJwsVerifier {
    inner: Arc<dyn DynJwsVerifier>,
}

impl BoxedJwsVerifier {
    /// Create a boxed JWS verifier from a non-boxed.
    pub fn new<V: JwsVerifier + std::fmt::Debug + 'static>(verifier: V) -> Self {
        Self {
            inner: Arc::new(verifier),
        }
    }
}

impl JwsVerifier for BoxedJwsVerifier {
    type Error = BoxedError;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.key_match(key_match)
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<BoxedError>> {
        self.inner.verify(input, signature, key_match).await
    }

    async fn try_refresh(&self) -> bool {
        self.inner.try_refresh().await
    }
}

trait DynJwsVerifier: std::fmt::Debug + MaybeSendSync {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength>;

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<(), VerifyError<BoxedError>>> + 'a>>;

    fn try_refresh(&self) -> Pin<Box<dyn MaybeSendFuture<Output = bool> + '_>>;
}

impl<V: JwsVerifier + std::fmt::Debug> DynJwsVerifier for V {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        JwsVerifier::key_match(self, key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<(), VerifyError<BoxedError>>> + 'a>> {
        Box::pin(async move {
            JwsVerifier::verify(self, input, signature, key_match)
                .await
                .map_err(|err| match err {
                    VerifyError::NoMatchingKey => VerifyError::NoMatchingKey,
                    VerifyError::AmbiguousKeyMatch => VerifyError::AmbiguousKeyMatch,
                    VerifyError::SignatureMismatch => VerifyError::SignatureMismatch,
                    VerifyError::Other { source } => VerifyError::Other {
                        source: BoxedError::from_err(source),
                    },
                })
        })
    }

    fn try_refresh(&self) -> Pin<Box<dyn MaybeSendFuture<Output = bool> + '_>> {
        Box::pin(JwsVerifier::try_refresh(self))
    }
}

/// The set of JWS header parameters used to select a verification key.
#[derive(Debug, Clone, Copy)]
pub struct KeyMatch<'a> {
    /// The algorithm (`alg`) from the JWS header.
    pub alg: &'a str,
    /// The key ID (`kid`) from the JWS header.
    pub kid: Option<&'a str>,
}

/// Trait for verifying RFC 7515 (JWS) / RFC 7518 (JWA) compatible signatures.
///
/// Implementations may represent a single verification key, or a set of keys
/// (e.g. a JWKS endpoint).
pub trait JwsVerifier: MaybeSendSync {
    /// The error type returned by this signer's operations.
    type Error: crate::Error;

    /// Returns how well this verifier matches the given key selection criteria.
    ///
    /// Implementations must return:
    ///
    /// - `Some(ByKeyId)` — the algorithm matches **and** both the JWT and this verifier have
    ///   a `kid`, and they are equal.
    /// - `Some(ByAlgorithm)` — the algorithm matches, but the `kid` could not be used for
    ///   matching: either the JWT has no `kid`, or this verifier has no `kid` registered.
    /// - `None` — the algorithm is unsupported by this verifier, **or** both the JWT and this
    ///   verifier have a `kid` but they differ. A `kid` mismatch must return `None`, not
    ///   `Some(ByAlgorithm)` — returning `ByAlgorithm` on a mismatch would cause
    ///   [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier) to attempt verification
    ///   with the wrong key.
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength>;

    /// Verify the input against the provided signature.
    fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> impl Future<Output = Result<(), VerifyError<Self::Error>>> + MaybeSend;

    /// Attempts to refresh the verifier's key material if warranted.
    ///
    /// Called by [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier) when no key
    /// matches an incoming token, giving refreshable verifiers a chance to reload before
    /// verification is retried.
    ///
    /// Returns `true` if new key material was loaded (or was concurrently loaded by another
    /// task). Returns `false` if no refresh was needed, attempted, or successful. The default
    /// implementation always returns `false`.
    fn try_refresh(&self) -> impl Future<Output = bool> + MaybeSend {
        async { false }
    }
}

/// Platform for creating [`JwsVerifier`]s, given public key material.
pub trait JwsVerifierPlatform: std::fmt::Debug + MaybeSendSync {
    /// Creates a verifier for the given public JWK.
    fn create_verifier_from_jwk(
        &self,
        jwk: PublicJwk,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<BoxedJwsVerifier, CreateVerifierError>>>>;
}

/// Factory for constructing a [`BoxedJwsVerifier`] from a JWKS URI and a verifier platform.
pub trait JwsVerifierFactory: MaybeSendSync {
    /// Build a verifier using the given JWKS URI and platform.
    fn build(
        &self,
        jwks_uri: Option<&EndpointUrl>,
        factory: Arc<dyn JwsVerifierPlatform>,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<BoxedJwsVerifier, BoxedError>>>>;
}

impl<F> JwsVerifierFactory for F
where
    F: Fn(
            Option<&EndpointUrl>,
            Arc<dyn JwsVerifierPlatform>,
        ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<BoxedJwsVerifier, BoxedError>>>>
        + MaybeSendSync,
{
    fn build(
        &self,
        jwks_uri: Option<&EndpointUrl>,
        factory: Arc<dyn JwsVerifierPlatform>,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<BoxedJwsVerifier, BoxedError>>>> {
        self(jwks_uri, factory)
    }
}
