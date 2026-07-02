use crate::{
    crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    platform::MaybeSendBoxFuture,
};

/// The registered JWS `alg` identifiers (RFC 7518 §3.1, plus `EdDSA` from
/// RFC 8037 and `ES256K` from RFC 8812), used to bound the cardinality of the
/// `alg` metrics label.
const KNOWN_JWS_ALGORITHMS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES256K",
    "PS256", "PS384", "PS512", "EdDSA", "none",
];

/// Maps a JWS header `alg` to a bounded metrics label: a recognised algorithm
/// passes through unchanged, anything else is bucketed as `"other"`.
///
/// The `alg` on a verification comes straight from the (attacker-controlled)
/// JWS header and is recorded even on a miss, so an unbounded label would let a
/// caller supplying arbitrary `alg` values inflate label cardinality and
/// degrade the metrics backend — the same concern that keeps
/// [`enc`/`kid` off the decryptor's labels](crate::crypto::cipher::MetricsAeadDecryptor).
fn alg_label(alg: &str) -> &'static str {
    KNOWN_JWS_ALGORITHMS
        .iter()
        .copied()
        .find(|known| *known == alg)
        .unwrap_or("other")
}

/// A [`JwsVerifier`] wrapper that records a `huskarl.jws.verify` counter for
/// each verification attempt and a `huskarl.jws.refresh` counter for each
/// refresh attempt.
///
/// Wrap your verifier with this type to instrument JWS signature verifications.
/// The `name` parameter is included as a label on every counter, allowing metrics
/// from multiple wrapped verifiers to be distinguished — typically set to the
/// issuer URL or JWKS URI of the authorization server.
///
/// # Labels
///
/// `huskarl.jws.verify`:
///
/// | Label     | Values                                                                       | Description                              |
/// |-----------|------------------------------------------------------------------------------|------------------------------------------|
/// | `name`    | user-provided                                                                | Identifies this verifier instance        |
/// | `alg`     | registered JWS alg (`RS256`, `ES256`, …) or `other`                          | Algorithm from the JWS header            |
/// | `outcome` | `success`, `no_matching_key`, `ambiguous_key`, `signature_mismatch`, `error` | Verification result                      |
///
/// `huskarl.jws.refresh`:
///
/// | Label     | Values                       | Description                       |
/// |-----------|------------------------------|-----------------------------------|
/// | `name`    | user-provided                | Identifies this verifier instance |
/// | `outcome` | `refreshed`, `not_refreshed` | Refresh result                    |
///
/// `no_matching_key` and `signature_mismatch` are particularly useful for security
/// monitoring — elevated rates may indicate key rotation in progress or an attack.
/// The `alg` label is restricted to the registered JWS algorithm identifiers; any
/// other value (an unrecognised or attacker-supplied `alg`) is bucketed as `other`
/// so that arbitrary header values cannot inflate label cardinality — a spike in
/// `other` is itself a signal worth alerting on.
///
/// Note that `not_refreshed` covers "no refresh warranted", "blocked by
/// policy", and "refresh failed" alike — the
/// [`try_refresh`](JwsVerifier::try_refresh) contract does not distinguish
/// them.
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
            let alg = alg_label(key_match.alg);
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
        })
    }

    fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
        Box::pin(async move {
            let refreshed = self.inner.try_refresh().await;

            let outcome = if refreshed {
                "refreshed"
            } else {
                "not_refreshed"
            };

            ::metrics::counter!(
                "huskarl.jws.refresh",
                "name" => self.name.clone(),
                "outcome" => outcome,
            )
            .increment(1);

            refreshed
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_algorithms_pass_through() {
        for alg in [
            "HS256", "RS256", "ES256", "ES256K", "PS512", "EdDSA", "none",
        ] {
            assert_eq!(alg_label(alg), alg);
        }
    }

    #[test]
    fn unknown_algorithms_bucket_to_other() {
        // Unrecognised, empty, and wrong-case values all collapse to a single
        // bounded label so an attacker-supplied `alg` cannot blow up cardinality.
        assert_eq!(alg_label("RS999"), "other");
        assert_eq!(alg_label(""), "other");
        assert_eq!(alg_label("rs256"), "other");
        assert_eq!(alg_label("' OR 1=1--"), "other");
    }
}
