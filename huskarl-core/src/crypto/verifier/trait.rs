//! JWS Verification traits.

use std::sync::Arc;

use crate::{
    EndpointUrl,
    crypto::{
        KeyMatchStrength,
        verifier::error::{CreateVerifierError, VerifyError},
    },
    error::Error,
    jwk::PublicJwk,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

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
///
/// This trait is dyn-capable: consumers store it as `Arc<dyn JwsVerifier>`.
/// Write async method bodies as `Box::pin(async move { ... })`.
pub trait JwsVerifier: std::fmt::Debug + MaybeSendSync {
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
    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>>;

    /// Attempts to refresh the verifier's key material if warranted.
    ///
    /// This can be called manually to force a key reload, or automatically by
    /// [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier) when no key
    /// matches an incoming token.
    ///
    /// Returns `true` if new key material was loaded (or was concurrently loaded by another
    /// task). Returns `false` if no refresh was needed, attempted, or successful. The default
    /// implementation always returns `false`.
    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async { false })
    }
}

impl<T: JwsVerifier + ?Sized> JwsVerifier for &T {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        (**self).key_match(key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        (**self).verify(input, signature, key_match)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        (**self).try_refresh()
    }
}

impl<T: JwsVerifier + ?Sized> JwsVerifier for Box<T> {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        (**self).key_match(key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        (**self).verify(input, signature, key_match)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        (**self).try_refresh()
    }
}

impl<T: JwsVerifier + ?Sized> JwsVerifier for Arc<T> {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        (**self).key_match(key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        (**self).verify(input, signature, key_match)
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        (**self).try_refresh()
    }
}

/// Platform for creating [`JwsVerifier`]s, given public key material.
pub trait JwsVerifierPlatform: std::fmt::Debug + MaybeSendSync {
    /// Creates a verifier for the given public JWK.
    fn create_verifier_from_jwk(
        &self,
        jwk: PublicJwk,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, CreateVerifierError>>;
}

/// Factory for constructing a [`JwsVerifier`] from a JWKS URI and a verifier platform.
pub trait JwsVerifierFactory: MaybeSendSync {
    /// Build a verifier using the given JWKS URI and platform.
    fn build(
        &self,
        jwks_uri: Option<&EndpointUrl>,
        platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>>;
}

impl<F> JwsVerifierFactory for F
where
    F: Fn(
            Option<&EndpointUrl>,
            Arc<dyn JwsVerifierPlatform>,
        ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>>
        + MaybeSendSync,
{
    fn build(
        &self,
        jwks_uri: Option<&EndpointUrl>,
        platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        self(jwks_uri, platform)
    }
}
