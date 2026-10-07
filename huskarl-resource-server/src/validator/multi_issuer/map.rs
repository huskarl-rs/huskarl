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
/// For fallible normalization, use [`TryMapClaims`](super::TryMapClaims). To
/// also see or rewrite the universal token fields, use [`MapRequest`].
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
                outcome: result.outcome.map(|opt| opt.map(|v| v.map_claims(&self.f))),
                dpop_nonce: result.dpop_nonce,
            }
        })
    }
}

impl<V: ProvideValidatorMetadata, F> ProvideValidatorMetadata for MapClaims<V, F> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.inner.validator_metadata(resource)
    }
}

/// Wraps a validator, mapping each whole validated request.
///
/// Unlike [`MapClaims`], the mapping sees the universal token fields (`iss`,
/// `sub`, `aud`, `cnf`, ...), so it can, for example, namespace subjects per
/// issuer. For a fallible mapping, use [`TryMapRequest`](super::TryMapRequest).
///
/// Rewritten fields are not revalidated; see [subjects and other token
/// fields](crate::_docs::explanation::multi_issuer_routing#subjects-and-other-token-fields).
///
/// ```
/// use huskarl_resource_server::validator::{
///     AccessTokenValidator, ValidatedRequest, multi_issuer::MapRequest,
/// };
///
/// struct Principal {
///     original_sub: Option<String>,
/// }
///
/// fn namespace<V>(validator: V) -> impl AccessTokenValidator<Claims = Principal>
/// where
///     V: AccessTokenValidator<Claims = ()>,
/// {
///     MapRequest::new(validator, |request: ValidatedRequest<()>| {
///         let original_sub = request.sub.clone();
///         let mut mapped = request.map_claims(|()| Principal { original_sub });
///         mapped.sub = mapped.sub.map(|sub| format!("issuer-a|{sub}"));
///         mapped
///     })
/// }
/// ```
pub struct MapRequest<V, F> {
    inner: V,
    f: F,
}

impl<V, F> MapRequest<V, F> {
    /// Wraps `inner`, applying `f` to every validated request.
    pub fn new(inner: V, f: F) -> Self {
        Self { inner, f }
    }

    /// Returns a reference to the wrapped validator.
    pub fn inner(&self) -> &V {
        &self.inner
    }
}

impl<V, F, C> AccessTokenValidator for MapRequest<V, F>
where
    V: AccessTokenValidator,
    F: Fn(ValidatedRequest<V::Claims>) -> ValidatedRequest<C> + MaybeSendSync,
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
                outcome: result.outcome.map(|opt| opt.map(&self.f)),
                dpop_nonce: result.dpop_nonce,
            }
        })
    }
}

impl<V: ProvideValidatorMetadata, F> ProvideValidatorMetadata for MapRequest<V, F> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.inner.validator_metadata(resource)
    }
}
