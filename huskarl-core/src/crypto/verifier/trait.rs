//! JWS Verification traits.

use std::sync::Arc;

use bon::Builder;

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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Builder)]
pub struct KeyMatch<'a> {
    /// The algorithm (`alg`) from the JWS header.
    pub alg: &'a str,
    /// The key ID (`kid`) from the JWS header.
    pub kid: Option<&'a str>,
}

impl KeyMatch<'_> {
    /// Computes the match strength for a single key, applying the standard
    /// rules documented on [`JwsVerifier::key_match`].
    ///
    /// `supported_algorithms` are the JWS algorithm identifiers the key can
    /// verify; `registered_kid` is the key ID registered for the key, if any.
    ///
    /// Single-key [`JwsVerifier`] implementations should delegate to this
    /// from [`key_match`](JwsVerifier::key_match) rather than re-implementing
    /// the rules — in particular the requirement that a `kid` mismatch
    /// returns `None` rather than `Some(ByAlgorithm)`.
    #[must_use]
    pub fn strength_for(
        &self,
        supported_algorithms: &[&str],
        registered_kid: Option<&str>,
    ) -> Option<KeyMatchStrength> {
        if !supported_algorithms.contains(&self.alg) {
            return None;
        }

        crate::crypto::kid_match_strength(self.kid, registered_kid)
    }
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
    ///
    /// Single-key implementations should delegate to
    /// [`KeyMatch::strength_for`], which implements these rules.
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength>;

    /// Verify the input against the provided signature.
    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>>;

    /// Requests a best-effort refresh of the verifier's key material.
    ///
    /// Called automatically by
    /// [`RetryingVerifier`](crate::crypto::verifier::RetryingVerifier) when no key
    /// matches an incoming token, and may also be called manually. A wrapping
    /// policy layer may rate-limit or decline the request, so it can return
    /// `false` without reloading; for a guaranteed reload, use a refreshable
    /// wrapper's inherent `refresh`.
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

/// The platform's verification backend: turns public key material into
/// [`JwsVerifier`]s.
///
/// Implemented by a platform crate (e.g. native `RustCrypto` or `WebCrypto`); the
/// JOSE layer calls [`create_verifier_from_jwk`](Self::create_verifier_from_jwk)
/// to obtain a verifier for a given JWK.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key_match<'a>(alg: &'a str, kid: Option<&'a str>) -> KeyMatch<'a> {
        KeyMatch { alg, kid }
    }

    #[test]
    fn strength_for_unsupported_algorithm() {
        let m = key_match("RS256", Some("kid-1"));
        assert_eq!(m.strength_for(&["ES256"], Some("kid-1")), None);
    }

    #[test]
    fn strength_for_matching_kid() {
        let m = key_match("ES256", Some("kid-1"));
        assert_eq!(
            m.strength_for(&["ES256"], Some("kid-1")),
            Some(KeyMatchStrength::ByKeyId)
        );
    }

    #[test]
    fn strength_for_kid_mismatch_is_none_not_by_algorithm() {
        let m = key_match("ES256", Some("kid-1"));
        assert_eq!(m.strength_for(&["ES256"], Some("kid-2")), None);
    }

    #[test]
    fn strength_for_no_requested_kid() {
        let m = key_match("ES256", None);
        assert_eq!(
            m.strength_for(&["ES256"], Some("kid-1")),
            Some(KeyMatchStrength::ByAlgorithm)
        );
    }

    #[test]
    fn strength_for_no_registered_kid() {
        let m = key_match("ES256", Some("kid-1"));
        assert_eq!(
            m.strength_for(&["ES256"], None),
            Some(KeyMatchStrength::ByAlgorithm)
        );
    }

    #[test]
    fn strength_for_multiple_supported_algorithms() {
        let m = key_match("PS384", None);
        assert_eq!(
            m.strength_for(
                &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
                None
            ),
            Some(KeyMatchStrength::ByAlgorithm)
        );
    }
}
