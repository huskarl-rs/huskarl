use std::{pin::Pin, sync::Arc};

use bon::Builder;
use http::HeaderMap;

use crate::{
    BoxedError, EndpointUrl,
    crypto::verifier::{
        BoxedJwsVerifier, CreateVerifierError, JwsVerifierFactory, JwsVerifierPlatform,
        MultiKeyVerifier, RetryingVerifier, ScheduledRefreshVerifier,
    },
    http::HttpClient,
    jwk::{Jwks, PublicJwks},
    platform::MaybeSendFuture,
};

/// Factory for building a JWKS-backed [`JwsVerifier`](crate::crypto::verifier::JwsVerifier)
/// with automatic periodic refresh and retry.
///
/// This is an opinionated default stack: a [`MultiKeyVerifier`] wrapped in a
/// [`ScheduledRefreshVerifier`] and a [`RetryingVerifier`] — keys are fetched from the JWKS
/// endpoint on first use, refreshed automatically after the TTL expires, and a single retry
/// is attempted when a key lookup misses after a successful refresh.
///
/// If you need a custom stack — for example to mix a JWKS source with KMS or enclave keys —
/// compose the lower-level types directly and apply [`RetryingVerifier`] once at the top.
#[derive(Builder, Debug, Clone)]
pub struct JwksSource<C: HttpClient + Clone + 'static> {
    /// The HTTP client used to fetch the JWKS.
    http_client: C,
}

impl<C: HttpClient + Clone + 'static> JwsVerifierFactory for JwksSource<C> {
    fn build(
        &self,
        jwks_uri: Option<&EndpointUrl>,
        platform: Arc<dyn JwsVerifierPlatform>,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<BoxedJwsVerifier, BoxedError>>>> {
        let client = self.http_client.clone();
        let Some(uri) = jwks_uri.cloned() else {
            return Box::pin(async {
                Err(BoxedError::from_err(CreateVerifierError::MissingJwksUri))
            });
        };

        Box::pin(async move {
            let refreshing = ScheduledRefreshVerifier::builder()
                .factory(move || {
                    let client = client.clone();
                    let uri = uri.clone();
                    let platform = platform.clone();
                    Box::pin(async move {
                        let jwks: Jwks =
                            crate::http::get(&client, uri.as_uri().clone(), HeaderMap::new())
                                .await
                                .map_err(BoxedError::from_err)?;
                        let public_jwks: PublicJwks = jwks.into();

                        MultiKeyVerifier::from_jwks(&public_jwks, platform.as_ref())
                            .await
                            .map_err(BoxedError::from_err)
                    })
                })
                .build()
                .await?;
            Ok(BoxedJwsVerifier::new(RetryingVerifier::new(refreshing)))
        })
    }
}
