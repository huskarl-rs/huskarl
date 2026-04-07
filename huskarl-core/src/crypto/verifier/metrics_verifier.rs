use crate::crypto::{
    KeyMatchStrength,
    verifier::{JwsVerifier, KeyMatch, VerifyError},
};

/// A [`JwsVerifier`] wrapper that records a `huskarl.jws.verify` counter for each
/// verification attempt.
///
/// Wrap your verifier with this type to instrument JWS signature verifications.
/// The `name` parameter is included as a label on every counter, allowing metrics
/// from multiple wrapped verifiers to be distinguished — typically set to the
/// issuer URL or JWKS URI of the authorization server.
///
/// # Labels
///
/// | Label     | Values                                                                       | Description                              |
/// |-----------|------------------------------------------------------------------------------|------------------------------------------|
/// | `name`    | user-provided                                                                | Identifies this verifier instance        |
/// | `alg`     | `RS256`, `ES256`, etc.                                                       | Algorithm from the JWS header            |
/// | `outcome` | `success`, `no_matching_key`, `ambiguous_key`, `signature_mismatch`, `error` | Verification result                      |
///
/// `no_matching_key` and `signature_mismatch` are particularly useful for security
/// monitoring — elevated rates may indicate key rotation in progress or an attack.
///
/// # Example
///
/// ```rust,ignore
/// let verifier = MetricsJwsVerifier::builder()
///     .inner(my_verifier)
///     .name("https://auth.example.com")
///     .build();
/// ```
#[derive(Debug)]
pub struct MetricsJwsVerifier<V> {
    inner: V,
    name: String,
}

#[bon::bon]
impl<V> MetricsJwsVerifier<V> {
    /// Creates a new [`MetricsJwsVerifier`].
    ///
    /// `name` is included as a label on every counter to distinguish this verifier
    /// from others. Typically set to the issuer URL or JWKS URI.
    #[builder]
    pub fn new(inner: V, #[builder(into)] name: String) -> Self {
        Self { inner, name }
    }
}

impl<V> MetricsJwsVerifier<V> {
    /// Returns a reference to the inner verifier.
    pub fn inner(&self) -> &V {
        &self.inner
    }

    /// Unwraps the inner verifier.
    pub fn into_inner(self) -> V {
        self.inner
    }
}

impl<V: JwsVerifier> JwsVerifier for MetricsJwsVerifier<V> {
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
        let alg = key_match.alg.to_owned();
        let result = self.inner.verify(input, signature, key_match).await;

        let outcome = match &result {
            Ok(()) => "success",
            Err(VerifyError::NoMatchingKey) => "no_matching_key",
            Err(VerifyError::AmbiguousKeyMatch) => "ambiguous_key",
            Err(VerifyError::SignatureMismatch) => "signature_mismatch",
            Err(VerifyError::Other { .. }) => "error",
        };

        ::metrics::counter!(
            "huskarl.jws.verify",
            "name" => self.name.clone(),
            "alg" => alg,
            "outcome" => outcome,
        )
        .increment(1);

        result
    }

    async fn try_refresh(&self) -> bool {
        self.inner.try_refresh().await
    }
}
