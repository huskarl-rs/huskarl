//! Claim normalization adapter for [`MultiIssuerValidator`](super::MultiIssuerValidator).

use crate::{
    AccessTokenValidator, ValidatedRequest,
    core::platform::{MaybeSendBoxFuture, MaybeSendSync},
    validator::{
        ValidationResult,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
    },
};

/// Wraps a validator, normalizing its source-specific claims into a common type `C`.
///
/// The mapping is an ordinary `Fn(SourceClaims) -> C`; the library attaches no
/// semantics to it. Use this to give several per-issuer validators a single
/// claims type so they can be combined in a
/// [`MultiIssuerValidator`](super::MultiIssuerValidator). The normalization
/// function is then handed to [`MapClaims::new`] alongside a validator:
///
/// ```
/// #[derive(serde::Deserialize)]
/// struct WireClaims {
///     scope: Option<String>,
/// }
/// struct Principal {
///     scopes: Vec<String>,
/// }
///
/// // `normalize` is the `Fn(SourceClaims) -> C` passed to `MapClaims::new(validator, normalize)`.
/// let normalize = |c: WireClaims| Principal {
///     scopes: c
///         .scope
///         .unwrap_or_default()
///         .split_whitespace()
///         .map(str::to_owned)
///         .collect(),
/// };
/// # let _ = normalize(WireClaims { scope: Some("a b".into()) });
/// ```
pub struct MapClaims<V, F> {
    inner: V,
    f: F,
}

impl<V, F> MapClaims<V, F> {
    /// Wraps `inner`, applying `f` to the claims of every validated request.
    pub fn new(inner: V, f: F) -> Self {
        Self { inner, f }
    }

    /// Returns a reference to the wrapped validator.
    pub fn inner(&self) -> &V {
        &self.inner
    }
}

impl<V, F, C> AccessTokenValidator for MapClaims<V, F>
where
    V: AccessTokenValidator,
    F: Fn(V::Claims) -> C + MaybeSendSync,
    C: MaybeSendSync,
{
    type Claims = C;
    type Error = V::Error;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<C, V::Error>> {
        Box::pin(async move {
            let result = self
                .inner
                .validate_request(headers, method, uri, client_cert_der)
                .await;

            ValidationResult {
                outcome: result.outcome.map(|opt| opt.map(|v| self.remap(v))),
                dpop_nonce: result.dpop_nonce,
            }
        })
    }
}

impl<V, F, C> MapClaims<V, F>
where
    V: AccessTokenValidator,
    F: Fn(V::Claims) -> C,
{
    /// Transforms only the extra-claims payload; the universal token fields
    /// (`iss`, `sub`, `aud`, `exp`, `cnf`, …) pass through unchanged.
    fn remap(&self, v: ValidatedRequest<V::Claims>) -> ValidatedRequest<C> {
        ValidatedRequest {
            issuer: v.issuer,
            subject: v.subject,
            audience: v.audience,
            jti: v.jti,
            issued_at: v.issued_at,
            expiration: v.expiration,
            cnf: v.cnf,
            claims: (self.f)(v.claims),
            introspection_jwt: v.introspection_jwt,
        }
    }
}

impl<V: ProvideValidatorMetadata, F> ProvideValidatorMetadata for MapClaims<V, F> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.inner.validator_metadata(resource)
    }
}
