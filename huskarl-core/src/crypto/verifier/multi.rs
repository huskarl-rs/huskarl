use std::sync::Arc;

use futures_util::future::join_all;
use snafu::prelude::*;

use crate::{
    crypto::{
        KeyMatchStrength,
        verifier::{CreateVerifierError, JwsVerifier, JwsVerifierPlatform, KeyMatch, VerifyError},
    },
    error::Error,
    jwk::PublicJwks,
    platform::MaybeSendBoxFuture,
};

/// The cause of a multi-key verifier construction failure.
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum MultiVerifierError {
    /// A JWK could not be turned into a verifier.
    #[snafu(display("creating verifier from JWK"))]
    #[classify(with = MultiVerifierError::origin_from_the_factory)]
    CreatingVerifier {
        /// The underlying error.
        source: CreateVerifierError,
    },
}

impl MultiVerifierError {
    /// Propagates classifications nested inside [`CreateVerifierError`].
    fn origin_from_the_factory(
        source: &CreateVerifierError,
    ) -> crate::error::propagation::Origin<'_> {
        use crate::error::propagation::Origin;

        match source {
            CreateVerifierError::UnsupportedKey { source: verdict }
            | CreateVerifierError::Other { source: verdict } => Origin::Propagates(verdict),
            // This leaf establishes a terminal configuration failure.
            CreateVerifierError::MissingJwksUri => {
                Origin::Establishes(crate::error::RetryAdvice::No.into())
            }
        }
    }
}

/// A [`JwsVerifier`] that holds multiple keys and applies RFC 7517 key selection semantics.
///
/// Key selection follows [`KeyMatchStrength`] priority:
/// - A [`ByKeyId`](KeyMatchStrength::ByKeyId) match (algorithm + kid) is definitive — that
///   key is used exclusively.
/// - Multiple [`ByAlgorithm`](KeyMatchStrength::ByAlgorithm) matches are ambiguous; returns
///   [`AmbiguousKeyMatch`](VerifyError::AmbiguousKeyMatch) unless
///   [`try_all_on_ambiguous_match`](Self::try_all_on_ambiguous_match) is set, in which case
///   each candidate is tried in order.
/// - A single `ByAlgorithm` match is used directly.
///
/// For a JWKS-backed verifier with automatic refresh and retry wrapped around
/// this type, use [`JwksSource`](crate::jwk::JwksSource); construct
/// `MultiKeyVerifier` directly only for a custom stack.
#[derive(Debug)]
pub struct MultiKeyVerifier {
    verifiers: Vec<Arc<dyn JwsVerifier>>,
    try_all_on_ambiguous_match: bool,
}

enum GetVerifierResult {
    ByKeyId(Arc<dyn JwsVerifier>),
    ByAlgorithm(Vec<Arc<dyn JwsVerifier>>),
    None,
}

impl GetVerifierResult {
    fn key_match_strength(&self) -> Option<KeyMatchStrength> {
        match self {
            Self::ByKeyId(_) => Some(KeyMatchStrength::ByKeyId),
            Self::ByAlgorithm(_) => Some(KeyMatchStrength::ByAlgorithm),
            Self::None => None,
        }
    }
}

impl MultiKeyVerifier {
    /// Creates a `MultiKeyVerifier` from an explicit list of verifiers.
    #[must_use]
    pub fn new(verifiers: Vec<Arc<dyn JwsVerifier>>) -> Self {
        Self {
            verifiers,
            try_all_on_ambiguous_match: false,
        }
    }

    /// Builds a `MultiKeyVerifier` from a JWKS document.
    ///
    /// Keys with unsupported algorithms are silently skipped.
    ///
    /// This is a general-purpose constructor with no key-count limit: it may be
    /// fed from a trusted source (a KMS, an enclave, a local file) as well as a
    /// remote JWKS. Bounding the key count of an untrusted, remotely-fetched
    /// document is the fetcher's job — see [`JwksSource`](crate::jwk::JwksSource).
    ///
    /// # Errors
    ///
    /// Returns an error if a supported key fails to construct a verifier.
    pub async fn from_jwks(
        jwks: &PublicJwks,
        platform: &dyn JwsVerifierPlatform,
    ) -> Result<Self, Error> {
        let verifiers: Vec<Arc<dyn JwsVerifier>> = join_all(
            jwks.keys
                .iter()
                .map(|jwk| platform.create_verifier_from_jwk(jwk.clone())),
        )
        .await
        .into_iter()
        .filter_map(|result| match result {
            Ok(v) => Some(Ok(v)),
            Err(CreateVerifierError::UnsupportedKey { .. }) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<_, _>>()
        .context(CreatingVerifierSnafu)?;

        Ok(Self {
            verifiers,
            try_all_on_ambiguous_match: false,
        })
    }

    /// Configures whether to try all matching keys when no `kid` is present and multiple
    /// keys match by algorithm.
    ///
    /// When `false` (the default), multiple algorithm matches without a `kid` return
    /// [`AmbiguousKeyMatch`](VerifyError::AmbiguousKeyMatch). When `true`, each candidate
    /// is tried in order and the first success is accepted.
    #[must_use]
    pub fn try_all_on_ambiguous_match(mut self, value: bool) -> Self {
        self.try_all_on_ambiguous_match = value;
        self
    }

    async fn dispatch_verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError> {
        let by_algorithm_verifiers = match self.get_verifier(key_match) {
            GetVerifierResult::ByKeyId(verifier) => {
                return verifier.verify(input, signature, key_match).await;
            }
            GetVerifierResult::ByAlgorithm(verifiers) => verifiers,
            GetVerifierResult::None => return Err(VerifyError::NoMatchingKey),
        };

        if by_algorithm_verifiers.len() > 1 && !self.try_all_on_ambiguous_match {
            return Err(VerifyError::AmbiguousKeyMatch);
        }

        let mut last_retryable = None;
        let mut last_non_retryable = None;
        for verifier in by_algorithm_verifiers {
            match verifier.verify(input, signature, key_match).await {
                Ok(()) => return Ok(()),
                // NoMatchingKey means the verifier didn't attempt verification —
                // it is the implicit fallback, not a result to prefer over others.
                Err(VerifyError::NoMatchingKey) => {}
                Err(e) => {
                    if e.is_retryable() {
                        last_retryable = Some(e);
                    } else {
                        last_non_retryable = Some(e);
                    }
                }
            }
        }

        // Prefer a definitive result from a verifier that checked the signature
        // over a retryable failure from one that could not. This also prevents
        // untrusted tokens from turning a partial cold-keyset failure into a 500.
        Err(last_non_retryable
            .or(last_retryable)
            .unwrap_or(VerifyError::NoMatchingKey))
    }

    fn get_verifier(&self, key_match: &KeyMatch) -> GetVerifierResult {
        let mut by_algorithm_verifiers: Vec<Arc<dyn JwsVerifier>> = Vec::new();

        for verifier in &self.verifiers {
            match verifier.key_match(key_match) {
                Some(KeyMatchStrength::ByKeyId) => {
                    return GetVerifierResult::ByKeyId(verifier.clone());
                }
                Some(KeyMatchStrength::ByAlgorithm) => {
                    by_algorithm_verifiers.push(verifier.clone());
                }
                None => {}
            }
        }

        if by_algorithm_verifiers.is_empty() {
            GetVerifierResult::None
        } else {
            GetVerifierResult::ByAlgorithm(by_algorithm_verifiers)
        }
    }
}

impl JwsVerifier for MultiKeyVerifier {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.get_verifier(key_match).key_match_strength()
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(self.dispatch_verify(input, signature, key_match))
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async move {
            join_all(self.verifiers.iter().map(JwsVerifier::try_refresh))
                .await
                .into_iter()
                .any(|b| b)
        })
    }
}

#[cfg(test)]
mod verdict_propagation {
    use super::*;
    use crate::error::RetryAdvice;

    // Verifier construction must preserve a factory's classification.
    #[test]
    fn a_factory_verdict_survives_verifier_construction() {
        let upstream = Error::propagate(
            crate::error::propagation::Classification::judged(
                RetryAdvice::retry_after(crate::platform::Duration::from_secs(5)),
                crate::oauth_error::OAuthError::new("temporarily_unavailable"),
            ),
            "verifier factory failed",
        );
        let expected = upstream.classification();

        let err = Error::from(MultiVerifierError::CreatingVerifier {
            source: CreateVerifierError::Other { source: upstream },
        });

        assert_eq!(err.classification(), expected);
    }

    // Preserve the classification even on the normally filtered variant.
    #[test]
    fn an_unsupported_key_propagates_instead_of_reclassifying() {
        let upstream = Error::new(RetryAdvice::RETRY, "unsupported by the backend");

        let err = Error::from(MultiVerifierError::CreatingVerifier {
            source: CreateVerifierError::UnsupportedKey { source: upstream },
        });

        assert_eq!(err.retry_advice(), RetryAdvice::RETRY);
    }

    // A missing URI is a terminal configuration failure.
    #[test]
    fn a_missing_jwks_uri_is_configuration() {
        let err = Error::from(MultiVerifierError::CreatingVerifier {
            source: CreateVerifierError::MissingJwksUri,
        });
        assert_eq!(err.retry_advice(), RetryAdvice::No);
    }
}
