use futures_util::future::join_all;
use snafu::prelude::*;

use crate::{
    BoxedError, Error as _,
    crypto::{
        KeyMatchStrength,
        verifier::{
            BoxedJwsVerifier, CreateVerifierError, JwsVerifier, JwsVerifierPlatform, KeyMatch,
            VerifyError,
        },
    },
    jwk::PublicJwks,
};

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
#[derive(Debug)]
pub struct MultiKeyVerifier {
    verifiers: Vec<BoxedJwsVerifier>,
    try_all_on_ambiguous_match: bool,
}

/// Errors that can occur when building a [`MultiKeyVerifier`] from a JWKS.
#[derive(Debug, Snafu)]
pub enum MultiKeyVerifierError {
    /// A supported key failed to construct a verifier.
    #[snafu(display("Failed to create verifier from JWK"))]
    CreateVerifier {
        /// The underlying error.
        source: CreateVerifierError,
    },
}

impl crate::Error for MultiKeyVerifierError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::CreateVerifier { source } => source.is_retryable(),
        }
    }
}

enum GetVerifierResult {
    ByKeyId(BoxedJwsVerifier),
    ByAlgorithm(Vec<BoxedJwsVerifier>),
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
    pub fn new(verifiers: Vec<BoxedJwsVerifier>) -> Self {
        Self {
            verifiers,
            try_all_on_ambiguous_match: false,
        }
    }

    /// Builds a `MultiKeyVerifier` from a JWKS document.
    ///
    /// Keys with unsupported algorithms are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if a supported key fails to construct a verifier.
    pub async fn from_jwks(
        jwks: &PublicJwks,
        platform: &dyn JwsVerifierPlatform,
    ) -> Result<Self, MultiKeyVerifierError> {
        let verifiers: Vec<BoxedJwsVerifier> = join_all(
            jwks.keys
                .iter()
                .map(|jwk| platform.create_verifier_from_jwk(jwk.clone())),
        )
        .await
        .into_iter()
        .filter_map(|result| match result {
            Ok(v) => Some(Ok(v)),
            Err(CreateVerifierError::UnsupportedKey) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<_, _>>()
        .context(CreateVerifierSnafu)?;

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
    ) -> Result<(), VerifyError<BoxedError>> {
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

        Err(last_non_retryable
            .or(last_retryable)
            .unwrap_or(VerifyError::NoMatchingKey))
    }

    fn get_verifier(&self, key_match: &KeyMatch) -> GetVerifierResult {
        let mut by_algorithm_verifiers: Vec<BoxedJwsVerifier> = Vec::new();

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
    type Error = BoxedError;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.get_verifier(key_match).key_match_strength()
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<Self::Error>> {
        self.dispatch_verify(input, signature, key_match).await
    }

    async fn try_refresh(&self) -> bool {
        join_all(self.verifiers.iter().map(JwsVerifier::try_refresh))
            .await
            .into_iter()
            .any(|b| b)
    }
}
