use std::sync::Arc;

use bon::bon;
use http::HeaderMap;

use crate::{
    EndpointUrl,
    crypto::verifier::{
        CreateVerifierError, JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform,
        MultiKeyVerifier, RetryingVerifier, ScheduledRefreshVerifier,
    },
    error::{Error, ErrorKind},
    http::HttpClient,
    jwk::{Jwks, PublicJwks},
    platform::MaybeSendBoxFuture,
};

/// Factory for building a JWKS-backed [`JwsVerifier`] with automatic periodic refresh and retry.
///
/// This is an opinionated default stack: a [`MultiKeyVerifier`] wrapped in a
/// [`ScheduledRefreshVerifier`] and a [`RetryingVerifier`] — keys are fetched from the JWKS
/// endpoint on first use, refreshed automatically after the TTL expires, and a single retry
/// is attempted when a key lookup misses after a successful refresh.
///
/// If you need a custom stack — for example to mix a JWKS source with KMS or enclave keys —
/// compose the lower-level types directly and apply [`RetryingVerifier`] once at the top.
#[derive(Clone)]
pub struct JwksSource {
    /// The HTTP client used to fetch the JWKS.
    http_client: Arc<dyn HttpClient>,
}

#[bon]
impl JwksSource {
    /// Creates a new [`JwksSource`].
    #[builder]
    pub fn new(http_client: impl HttpClient + 'static) -> Self {
        Self {
            http_client: Arc::new(http_client),
        }
    }
}

impl std::fmt::Debug for JwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksSource").finish_non_exhaustive()
    }
}

impl JwsVerifierFactory for JwksSource {
    fn build(
        &self,
        jwks_uri: Option<&EndpointUrl>,
        platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        let client = self.http_client.clone();
        let Some(uri) = jwks_uri.cloned() else {
            return Box::pin(async {
                Err(Error::new(
                    ErrorKind::Config,
                    CreateVerifierError::MissingJwksUri,
                ))
            });
        };

        Box::pin(async move {
            let refreshing = ScheduledRefreshVerifier::builder()
                .factory(move || {
                    let client = client.clone();
                    let uri = uri.clone();
                    let platform = platform.clone();
                    Box::pin(async move {
                        let jwks: Jwks = crate::http::get(
                            client.as_ref(),
                            uri.as_uri().clone(),
                            HeaderMap::new(),
                        )
                        .await?;
                        let public_jwks: PublicJwks = jwks.into();

                        MultiKeyVerifier::from_jwks(&public_jwks, platform.as_ref()).await
                    })
                })
                .build()
                .await?;
            Ok(Arc::new(RetryingVerifier::new(refreshing)) as Arc<dyn JwsVerifier>)
        })
    }
}
