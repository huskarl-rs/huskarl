use crate::{
    crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    platform::MaybeSendBoxFuture,
};

/// A [`JwsVerifier`] that retries once after a [`NoMatchingKey`](VerifyError::NoMatchingKey)
/// error by calling [`try_refresh`](JwsVerifier::try_refresh) on the inner verifier.
///
/// This is the single place in the verifier hierarchy where the refresh-and-retry loop lives.
/// Wrap the root verifier with this type so that any composition underneath — a single
/// [`ScheduledRefreshVerifier`](crate::crypto::verifier::ScheduledRefreshVerifier), a
/// [`MultiKeyVerifier`](crate::crypto::verifier::MultiKeyVerifier), or arbitrary nesting —
/// gets one retry attempt without any component needing to implement it themselves.
#[derive(Debug, Clone)]
pub struct RetryingVerifier<V> {
    inner: V,
}

impl<V: JwsVerifier> RetryingVerifier<V> {
    /// Wraps a verifier so that a `NoMatchingKey` result triggers a refresh and one retry.
    pub fn new(inner: V) -> Self {
        Self { inner }
    }
}

impl<V: JwsVerifier> JwsVerifier for RetryingVerifier<V> {
    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.key_match(key_match)
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key_match: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async move {
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
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        self.inner.try_refresh()
    }
}
