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
    platform::{Duration, MaybeSendBoxFuture},
};

/// Factory for building a JWKS-backed [`JwsVerifier`] with automatic periodic refresh and retry.
///
/// This is an opinionated default stack: a [`MultiKeyVerifier`] wrapped in a
/// [`ScheduledRefreshVerifier`] and a [`RetryingVerifier`] — keys are fetched from the JWKS
/// endpoint on first use, reloaded on the read path once older than the `ttl`,
/// and a single retry is attempted when a key lookup misses after a successful refresh.
///
/// If you need to tune beyond the TTL (failure backoff, refresh rate limiting) or
/// mix a JWKS source with KMS or enclave keys, compose the lower-level types
/// directly and apply [`RetryingVerifier`] once at the top.
///
/// See [configuring JWT verification](crate::_docs::guide::configuring_jwt_verification)
/// for wiring this into a validator and for swapping the stack.
#[derive(Clone)]
pub struct JwksSource {
    /// The HTTP client used to fetch the JWKS.
    http_client: Arc<dyn HttpClient>,
    /// Maximum number of keys accepted from a fetched JWKS document.
    max_keys: usize,
    /// How long a fetched keyset is served before it is reloaded on the read path.
    ttl: Duration,
}

#[bon]
impl JwksSource {
    /// Creates a new [`JwksSource`].
    #[builder]
    pub fn new(
        http_client: impl HttpClient + 'static,
        /// Maximum number of keys accepted from a fetched JWKS document before
        /// the fetch is rejected.
        #[builder(default = 100)]
        max_keys: usize,
        /// How long a fetched keyset is served before it is reloaded. Bounds how
        /// long a key removed from the JWKS keeps being trusted. Defaults to one
        /// hour.
        #[builder(default = Duration::from_hours(1))]
        ttl: Duration,
    ) -> Self {
        Self {
            http_client: Arc::new(http_client),
            max_keys,
            ttl,
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
        let max_keys = self.max_keys;
        let ttl = self.ttl;
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
                .ttl(ttl)
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

                        if public_jwks.keys.len() > max_keys {
                            return Err(Error::from(ErrorKind::Protocol).with_context(format!(
                                "JWKS contains {} keys, exceeding the limit of {max_keys}",
                                public_jwks.keys.len()
                            )));
                        }

                        MultiKeyVerifier::from_jwks(&public_jwks, platform.as_ref()).await
                    })
                })
                .build()
                .await?;
            Ok(Arc::new(RetryingVerifier::new(refreshing)) as Arc<dyn JwsVerifier>)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{HeaderMap, Request, StatusCode};

    use super::JwksSource;
    use crate::{
        EndpointUrl,
        crypto::verifier::{
            CreateVerifierError, JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform,
        },
        error::{Error, ErrorKind},
        http::{HttpClient, HttpResponse, Idempotency},
        jwk::PublicJwk,
        platform::MaybeSendBoxFuture,
    };

    /// Serves a fixed JWKS document, however many times it is fetched.
    struct FakeJwksClient {
        body: String,
    }

    impl HttpClient for FakeJwksClient {
        fn execute(
            &self,
            _request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            Box::pin(async move {
                Ok(HttpResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: Bytes::from(self.body.clone()),
                })
            })
        }
    }

    /// Supports no keys, so the build reaches the key-count guard without
    /// needing real key material or crypto.
    #[derive(Debug)]
    struct UnsupportedPlatform;

    impl JwsVerifierPlatform for UnsupportedPlatform {
        fn create_verifier_from_jwk(
            &self,
            _jwk: PublicJwk,
        ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, CreateVerifierError>>
        {
            Box::pin(async { Err(CreateVerifierError::UnsupportedKey) })
        }
    }

    fn jwks_with_keys(n: usize) -> String {
        let key = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
        let keys = std::iter::repeat_n(key, n).collect::<Vec<_>>().join(",");
        format!(r#"{{"keys":[{keys}]}}"#)
    }

    async fn build_source(n_keys: usize, max_keys: usize) -> Result<Arc<dyn JwsVerifier>, Error> {
        let source = JwksSource::builder()
            .http_client(FakeJwksClient {
                body: jwks_with_keys(n_keys),
            })
            .max_keys(max_keys)
            .build();
        let uri = EndpointUrl::try_from("https://as.example.com/jwks").unwrap();
        source
            .build(Some(&uri), Arc::new(UnsupportedPlatform))
            .await
    }

    #[tokio::test]
    async fn fetched_jwks_at_limit_is_accepted() {
        let limit = 100;
        let result = build_source(limit, limit).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fetched_jwks_over_default_limit_is_rejected() {
        let limit = 100;
        let error = build_source(limit + 1, limit).await.unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Protocol));
        assert!(!error.is_retryable());
    }
}
