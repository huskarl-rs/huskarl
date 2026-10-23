use std::sync::Arc;

use bon::bon;
use http::{HeaderMap, HeaderValue, header::ACCEPT};

use crate::{
    EndpointUrl,
    crypto::verifier::{
        CreateVerifierError, JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform,
        MultiKeyVerifier, RetryingVerifier, ScheduledRefreshVerifier,
    },
    error::{Error, RetryAdvice},
    http::HttpClient,
    jwk::{Jwks, PublicJwks},
    platform::{Duration, MaybeSendBoxFuture},
    time::{Clock, PlatformClock, PlatformTimer, Timer},
};

/// Factory for building a JWKS-backed [`JwsVerifier`] with automatic periodic refresh and retry.
///
/// This is an opinionated default stack: a [`MultiKeyVerifier`] wrapped in a
/// [`ScheduledRefreshVerifier`] and a [`RetryingVerifier`] — keys are fetched from the JWKS
/// endpoint when the factory builds a verifier, then refreshed on use after `ttl`,
/// and a single retry is attempted when a key lookup misses after a successful refresh.
///
/// If you need to tune beyond the TTL (failure backoff, refresh rate limiting) or
/// mix a JWKS source with KMS or enclave keys, compose the lower-level types
/// directly and apply [`RetryingVerifier`] once at the top.
///
/// Use `timer(...)` to control refresh scheduling and `clock(...)` to interpret
/// HTTP-date retry delays. A [`ManualTime`](crate::time::ManualTime) can provide
/// both; wall-clock changes do not affect refresh scheduling.
///
/// See [configuring JWT verification](crate::_docs::guide::configuring_jwt_verification)
/// for wiring this into a validator and for swapping the stack.
#[derive(Clone)]
pub struct JwksSource {
    clock: Arc<dyn Clock>,
    timer: Arc<dyn Timer>,
    /// The HTTP client used to fetch the JWKS.
    http_client: Arc<dyn HttpClient>,
    /// Maximum number of keys accepted from a fetched JWKS document.
    max_keys: usize,
    /// Age after which reads trigger refresh attempts; failed refreshes retain old keys.
    ttl: Duration,
    /// How a failed initial JWKS fetch at build time is handled.
    startup: JwksStartup,
}

/// How [`JwksSource`] handles a failed initial JWKS fetch at build time.
///
/// The fetch is always attempted eagerly; this only governs whether *failure*
/// is fatal. Neither variant accepts an unvalidated token — a cold source
/// returns [`KeysUnavailable`](crate::crypto::verifier::VerifyError::KeysUnavailable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum JwksStartup {
    /// Fail construction if the initial fetch fails — surfaces a wrong `jwks_uri`
    /// or an unreachable authorization server at boot rather than as a running
    /// cold state. The default: a config error is louder at deploy than a
    /// silently-degraded service.
    #[default]
    FailFast,
    /// Come up with an empty keyset and self-heal via cold-backoff retries. The
    /// happy-path fetch still populates keys before construction returns. Opt in
    /// when boot must not be gated on the authorization server being reachable.
    ///
    /// Note this comes up *cold*: until a live fetch lands it verifies nothing and
    /// returns [`KeysUnavailable`](crate::crypto::verifier::VerifyError::KeysUnavailable).
    /// To instead come up **warm** from a trusted local cache — verifying
    /// immediately while offline — build the verifier with a factory that falls
    /// back to that cache; see
    /// [`crate::crypto::verifier::ScheduledRefreshVerifier`].
    SeedEmpty,
}

#[bon]
impl JwksSource {
    /// Creates a new [`JwksSource`].
    #[builder]
    pub fn new(
        /// Clock used to interpret HTTP-date retry delays at response receipt.
        #[builder(
            default = Arc::new(PlatformClock),
            with = |clock: impl Clock + 'static| Arc::new(clock) as Arc<dyn Clock>
        )]
        clock: Arc<dyn Clock>,
        /// Timer used for keyset TTL, refresh rate limiting, and failure backoff.
        #[builder(
            default = Arc::<PlatformTimer>::default(),
            with = |timer: impl Timer + 'static| Arc::new(timer) as Arc<dyn Timer>
        )]
        timer: Arc<dyn Timer>,
        /// Transport used to fetch JWKS documents.
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
        /// How a failed initial fetch is handled. Defaults to
        /// [`FailFast`](JwksStartup::FailFast): a failed boot-time fetch is fatal.
        #[builder(default)]
        startup: JwksStartup,
    ) -> Self {
        Self {
            clock,
            timer,
            http_client: Arc::new(http_client),
            max_keys,
            ttl,
            startup,
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
        let clock = self.clock.clone();
        let timer = self.timer.clone();
        let max_keys = self.max_keys;
        let ttl = self.ttl;
        // SeedEmpty tolerates a failed initial fetch by seeding an empty keyset
        // (which misses on everything) and self-healing via cold-backoff retries.
        let fallback = match self.startup {
            JwksStartup::SeedEmpty => Some(MultiKeyVerifier::new(Vec::new())),
            JwksStartup::FailFast => None,
        };
        let Some(uri) = jwks_uri.cloned() else {
            return Box::pin(async {
                Err(Error::new(
                    RetryAdvice::No,
                    CreateVerifierError::MissingJwksUri,
                ))
            });
        };

        Box::pin(async move {
            let refreshing = ScheduledRefreshVerifier::builder()
                .timer(timer)
                .ttl(ttl)
                .maybe_fallback(fallback)
                .factory(move || {
                    let client = client.clone();
                    let clock = clock.clone();
                    let uri = uri.clone();
                    let platform = platform.clone();
                    Box::pin(async move {
                        let headers = HeaderMap::from_iter([(
                            ACCEPT,
                            HeaderValue::from_static("application/jwk-set+json, application/json"),
                        )]);
                        let jwks: Jwks = crate::http::get(
                            client.as_ref(),
                            uri.as_uri().clone(),
                            headers,
                            crate::http::DocumentKind::Jwks,
                            clock.as_ref(),
                        )
                        .await?;
                        let public_jwks: PublicJwks = jwks.into();

                        if public_jwks.keys.len() > max_keys {
                            return Err(crate::jwk::JwkError::TooManyKeys {
                                count: public_jwks.keys.len(),
                                max: max_keys,
                            }
                            .into());
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
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use bytes::Bytes;
    use http::{HeaderMap, Request, StatusCode};

    use super::{JwksSource, JwksStartup};
    use crate::{
        EndpointUrl,
        crypto::{
            KeyMatchStrength,
            verifier::{
                CreateVerifierError, JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform,
                KeyMatch, VerifyError,
            },
        },
        error::Error,
        http::{HttpClient, HttpResponse, Idempotency},
        jwk::PublicJwk,
        platform::{Duration, MaybeSendBoxFuture},
        time::ManualTime,
    };

    /// Serves a fixed JWKS document, however many times it is fetched.
    struct FakeJwksClient {
        body: String,
    }

    impl HttpClient for FakeJwksClient {
        fn execute(
            &self,
            request: Request<Bytes>,
            _idempotency: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            assert_eq!(
                request.headers()[http::header::ACCEPT],
                "application/jwk-set+json, application/json"
            );
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
            Box::pin(async {
                Err(CreateVerifierError::UnsupportedKey {
                    source: Error::from(crate::jwk::JwkError::NoSupportedKeys),
                })
            })
        }

        fn supported_signature_algorithms(&self) -> &[&str] {
            &[]
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
            // Assert the fetch outcome directly: SeedEmpty would tolerate a
            // rejected fetch and come up cold instead of surfacing the error.
            .startup(JwksStartup::FailFast)
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
        assert_eq!(error.retry_advice(), crate::error::RetryAdvice::No);
    }
    #[derive(Debug)]
    struct AcceptVerifier;

    impl JwsVerifier for AcceptVerifier {
        fn key_match(&self, key: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            key.strength_for(&["ES256"], None)
        }
        fn verify<'a>(
            &'a self,
            _: &'a [u8],
            _: &'a [u8],
            _: &'a KeyMatch<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Debug)]
    struct TestPlatform;

    impl JwsVerifierPlatform for TestPlatform {
        fn create_verifier_from_jwk(
            &self,
            _: PublicJwk,
        ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, CreateVerifierError>>
        {
            Box::pin(async { Ok(Arc::new(AcceptVerifier) as Arc<dyn JwsVerifier>) })
        }
        fn supported_signature_algorithms(&self) -> &[&str] {
            &["ES256"]
        }
    }

    struct SequenceClient {
        responses: Mutex<VecDeque<HttpResponse>>,
        calls: AtomicUsize,
    }

    impl SequenceClient {
        fn new(responses: impl IntoIterator<Item = (StatusCode, usize)>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(status, keys)| HttpResponse {
                            status,
                            headers: HeaderMap::new(),
                            body: Bytes::from(jwks_with_keys(keys)),
                        })
                        .collect(),
                ),
                calls: AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl HttpClient for SequenceClient {
        fn execute(
            &self,
            _: Request<Bytes>,
            _: Idempotency,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(self
                    .responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected JWKS fetch"))
            })
        }
    }

    async fn timed_source(
        client: Arc<SequenceClient>,
        time: &ManualTime,
        startup: JwksStartup,
    ) -> Arc<dyn JwsVerifier> {
        let source = JwksSource::builder()
            .http_client(client)
            .clock(time.clone())
            .timer(time.clone())
            .startup(startup)
            .ttl(Duration::from_hours(1))
            .build();
        let uri = EndpointUrl::try_from("https://as.example.com/jwks").unwrap();
        source
            .clone()
            .build(Some(&uri), Arc::new(TestPlatform))
            .await
            .unwrap()
    }

    async fn verify(verifier: &dyn JwsVerifier) -> Result<(), VerifyError> {
        verifier
            .verify(
                b"input",
                b"signature",
                &KeyMatch::builder().alg("ES256").build(),
            )
            .await
    }

    #[tokio::test]
    async fn ttl_uses_monotonic_time_and_reloads_removed_keys() {
        let time = ManualTime::new(jiff::Timestamp::UNIX_EPOCH);
        let client = SequenceClient::new([(StatusCode::OK, 1), (StatusCode::OK, 0)]);
        let verifier = timed_source(client.clone(), &time, JwksStartup::FailFast).await;
        verify(verifier.as_ref()).await.unwrap();
        crate::time::test_support::assert_wall_jumps_ignored(&time, async || {
            verify(verifier.as_ref()).await.unwrap();
            assert_eq!(client.calls(), 1);
        })
        .await;
        time.advance_monotonic(Duration::from_hours(1) - Duration::from_nanos(1))
            .unwrap();
        verify(verifier.as_ref()).await.unwrap();
        assert_eq!(client.calls(), 1);
        time.advance_monotonic(Duration::from_nanos(1)).unwrap();
        assert!(matches!(
            verify(verifier.as_ref()).await,
            Err(VerifyError::NoMatchingKey)
        ));
        assert_eq!(client.calls(), 2);
    }

    #[tokio::test]
    async fn failed_warm_refresh_retains_keys_and_waits_for_monotonic_retry_gate() {
        let time = ManualTime::new(jiff::Timestamp::UNIX_EPOCH);
        let client = SequenceClient::new([
            (StatusCode::OK, 1),
            (StatusCode::SERVICE_UNAVAILABLE, 0),
            (StatusCode::OK, 0),
        ]);
        let verifier = timed_source(client.clone(), &time, JwksStartup::FailFast).await;
        time.advance_monotonic(Duration::from_hours(1)).unwrap();
        verify(verifier.as_ref()).await.unwrap();
        assert_eq!(client.calls(), 2);
        crate::time::test_support::assert_wall_jumps_ignored(&time, async || {
            verify(verifier.as_ref()).await.unwrap();
            assert_eq!(client.calls(), 2);
        })
        .await;
        // The default 60-second rate limit outlasts the 30-second failure backoff.
        time.advance_monotonic(Duration::from_secs(60) - Duration::from_nanos(1))
            .unwrap();
        verify(verifier.as_ref()).await.unwrap();
        assert_eq!(client.calls(), 2);
        time.advance_monotonic(Duration::from_nanos(1)).unwrap();
        assert!(matches!(
            verify(verifier.as_ref()).await,
            Err(VerifyError::NoMatchingKey)
        ));
        assert_eq!(client.calls(), 3);
    }

    #[tokio::test]
    async fn cold_backoff_uses_monotonic_time_and_recovers() {
        let time = ManualTime::new(jiff::Timestamp::UNIX_EPOCH);
        let client = SequenceClient::new([
            (StatusCode::SERVICE_UNAVAILABLE, 0),
            (StatusCode::SERVICE_UNAVAILABLE, 0),
            (StatusCode::OK, 1),
        ]);
        let verifier = timed_source(client.clone(), &time, JwksStartup::SeedEmpty).await;
        for (attempt, delay) in [
            (1, Duration::from_millis(250)),
            (2, Duration::from_millis(500)),
        ] {
            crate::time::test_support::assert_wall_jumps_ignored(&time, async || {
                assert!(matches!(
                    verify(verifier.as_ref()).await,
                    Err(VerifyError::KeysUnavailable)
                ));
                assert_eq!(client.calls(), attempt);
            })
            .await;
            time.advance_monotonic(delay.checked_sub(Duration::from_nanos(1)).unwrap())
                .unwrap();
            assert!(verify(verifier.as_ref()).await.is_err());
            assert_eq!(client.calls(), attempt);
            time.advance_monotonic(Duration::from_nanos(1)).unwrap();
            let result = verify(verifier.as_ref()).await;
            assert_eq!(result.is_ok(), attempt == 2);
            assert_eq!(client.calls(), attempt + 1);
        }
    }
}
