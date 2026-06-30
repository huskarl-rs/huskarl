//! What a registered source is, internally: the [`SourceValidator`] trait object
//! the composite stores per issuer, and the [`FoldError`] wrapper that turns an
//! arbitrary validator into one.
//!
//! Since [`AccessTokenValidator`] is object-safe, the only adaptation a source
//! needs is (a) folding its error into [`MultiIssuerError`] so all stored sources
//! share one error type, and (b) combining [`AccessTokenValidator`] and
//! [`ProvideValidatorMetadata`] into a single trait object (a trait object can
//! name only one non-auto trait).

use crate::{
    AccessTokenValidator,
    core::platform::{MaybeSendBoxFuture, MaybeSendSync},
    validator::{
        ValidationResult,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        multi_issuer::error::MultiIssuerError,
    },
};

/// A per-issuer entry: an access token validator producing `Claims = C` with its
/// error folded to [`MultiIssuerError`], plus its RFC 9728 metadata.
///
/// Implemented for any [`FoldError`]-wrapped source; stored as
/// `Box<dyn SourceValidator<C>>`.
pub(super) trait SourceValidator<C>:
    AccessTokenValidator<Claims = C, Error = MultiIssuerError> + ProvideValidatorMetadata
{
}

impl<C, T> SourceValidator<C> for T where
    T: AccessTokenValidator<Claims = C, Error = MultiIssuerError> + ProvideValidatorMetadata
{
}

/// Wraps a validator, folding its error into [`MultiIssuerError::Validation`] so
/// heterogeneous sources present one error type to the composite.
pub(super) struct FoldError<V>(pub(super) V);

impl<V, C> AccessTokenValidator for FoldError<V>
where
    V: AccessTokenValidator<Claims = C>,
    V::Error: 'static,
    C: MaybeSendSync,
{
    type Claims = C;
    type Error = MultiIssuerError;

    fn validate_request<'a>(
        &'a self,
        headers: &'a http::HeaderMap,
        method: &'a http::Method,
        uri: &'a http::Uri,
        client_cert_der: Option<&'a [u8]>,
    ) -> MaybeSendBoxFuture<'a, ValidationResult<C, MultiIssuerError>> {
        Box::pin(async move {
            let result = self
                .0
                .validate_request(headers, method, uri, client_cert_der)
                .await;
            ValidationResult {
                outcome: result
                    .outcome
                    .map_err(|e| MultiIssuerError::Validation { error: Box::new(e) }),
                dpop_nonce: result.dpop_nonce,
            }
        })
    }
}

impl<V: ProvideValidatorMetadata> ProvideValidatorMetadata for FoldError<V> {
    fn validator_metadata(&self, resource: Option<&str>) -> ValidatorMetadata {
        self.0.validator_metadata(resource)
    }
}
