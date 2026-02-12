use crate::{
    crypto::verifier::{JwsVerifier, KeyMatch, KeyMatchStrength, VerifyError},
    platform::MaybeSendSync,
};

/// A [`JwsVerifier`] that retries once after a [`NoMatchingKey`](VerifyError::NoMatchingKey)
/// error by calling [`try_refresh`](JwsVerifier::try_refresh) on the inner verifier.
///
/// This is the single place in the verifier hierarchy where the refresh-and-retry loop lives.
/// Wrap the root verifier with this type so that any composition underneath — a single
/// [`RefreshingVerifier`](crate::crypto::verifier::RefreshingVerifier), a
/// [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier), or arbitrary nesting —
/// gets one retry attempt without any component needing to implement it themselves.
#[derive(Debug, Clone)]
pub struct RetryingVerifier<V> {
    inner: V,
}

impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync> RetryingVerifier<V> {
    /// Wraps a verifier so that a `NoMatchingKey` result triggers a refresh and one retry.
    pub fn new(inner: V) -> Self {
        Self { inner }
    }
}

impl<V: JwsVerifier + std::fmt::Debug + MaybeSendSync> JwsVerifier for RetryingVerifier<V> {
    type Error = V::Error;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.key_match(key_match)
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<Self::Error>> {
        match self.inner.verify(input, signature, key_match).await {
            Err(VerifyError::NoMatchingKey) => {
                if self.inner.try_refresh().await {
                    self.inner.verify(input, signature, key_match).await
                } else {
                    Err(VerifyError::NoMatchingKey)
                }
            }
            other => other,
        }
    }

    async fn try_refresh(&self) -> bool {
        self.inner.try_refresh().await
    }
}
