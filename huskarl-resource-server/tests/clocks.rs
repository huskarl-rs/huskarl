#![cfg(not(target_family = "wasm"))]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use huskarl_crypto_native::{
    NativeVerifierPlatform,
    asymmetric::signer::{GenerateAlgorithm, PrivateKey},
};
use huskarl_resource_server::{
    core::{
        EndpointUrl, Error,
        client_auth::NoAuth,
        crypto::{
            KeyMatchStrength,
            signer::AsymmetricJwsSignerSelector,
            verifier::{
                JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform, KeyMatch, VerifyError,
            },
        },
        dpop::{DPoPNonceChecker, NonceCheck, hash_access_token_for_dpop},
        http::{HttpClient, HttpResponse, Idempotency},
        jwt::{
            Jwt,
            validator::{ClaimCheck, JwtValidationError},
        },
        platform::{Duration, MaybeSendBoxFuture, SystemTime},
        secrets::SecretString,
        time::{Clock, ManualTime, Timer},
    },
    introspection::{IntrospectionCallError, TokenIntrospection},
    validator::{
        AccessTokenValidator,
        custom::CustomValidator,
        dpop_proof::{DPoPProofError, DPoPProofValidator},
        error::{TokenBindingError, ValidateHeadersError},
        introspection::{IntrospectionValidateError, IntrospectionValidator},
        rfc9068::Rfc9068Validator,
    },
};
use rstest::rstest;

const NOW: u64 = 2_000_000;
const URI: &str = "https://rs.example/resource";

fn time() -> ManualTime {
    ManualTime::new(jiff::Timestamp::new(2_000_000, 0).unwrap())
}

struct NonceClock {
    clock: ManualTime,
    calls: AtomicUsize,
    expected: Option<jiff::Timestamp>,
}

impl NonceClock {
    fn new(clock: &ManualTime) -> Arc<Self> {
        Arc::new(Self {
            clock: clock.clone(),
            calls: AtomicUsize::new(0),
            expected: None,
        })
    }
}

impl DPoPNonceChecker for NonceClock {
    fn check_nonce<'a>(
        &'a self,
        _nonce: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<NonceCheck, Error>> {
        self.check_nonce_at(
            _nonce,
            huskarl_core::time::Clock::now(&huskarl_core::time::PlatformClock),
        )
    }

    fn check_nonce_at<'a>(
        &'a self,
        _nonce: Option<&'a str>,
        now: jiff::Timestamp,
    ) -> MaybeSendBoxFuture<'a, Result<NonceCheck, Error>> {
        Box::pin(async move {
            assert_eq!(
                now,
                self.expected.unwrap_or_else(|| Clock::now(&self.clock))
            );
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(NonceCheck::Valid)
        })
    }
}

fn timestamp(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn factory(verifier: Arc<dyn JwsVerifier>) -> impl JwsVerifierFactory {
    move |_: Option<&EndpointUrl>,
          _: Arc<dyn JwsVerifierPlatform>|
          -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        let verifier = verifier.clone();
        Box::pin(async move { Ok(verifier) })
    }
}

async fn sign_proof(key: &PrivateKey, token: &str, issued_at: u64) -> String {
    let signer = key.select_asymmetric_signer().await;
    Jwt::builder()
        .typ("dpop+jwt")
        .iat(timestamp(issued_at))
        .jti(Some("proof".to_owned()))
        .jwk(signer.public_key_jwk().into_owned())
        .claims(serde_json::json!({
            "htm": "GET", "htu": URI, "ath": hash_access_token_for_dpop(token)
        }))
        .build()
        .to_jws_compact(&*signer)
        .await
        .unwrap()
        .expose_secret()
        .to_owned()
}

async fn request<V: AccessTokenValidator>(
    validator: &V,
    headers: &http::HeaderMap,
) -> Result<(), V::Error> {
    let result = validator
        .validate_request(headers, &http::Method::GET, &URI.parse().unwrap(), None)
        .await
        .outcome?;
    assert!(
        result.is_some(),
        "the request must contain a validated token"
    );
    Ok(())
}

async fn check_bound_request(
    validator: impl AccessTokenValidator<Error = ValidateHeadersError>,
    clock: ManualTime,
    key: &PrivateKey,
    token: &str,
    leeway: Duration,
    advance_during_verification: bool,
) {
    let initial = Clock::now(&clock);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("DPoP {token}").parse().unwrap(),
    );
    headers.insert("dpop", sign_proof(key, token, NOW).await.parse().unwrap());
    request(&validator, &headers).await.unwrap();
    if advance_during_verification {
        assert_eq!(
            Clock::now(&clock),
            initial.checked_add(Duration::from_secs(300)).unwrap()
        );
        assert!(matches!(
            request(&validator, &headers).await,
            Err(ValidateHeadersError::InvalidJwt {
                source: JwtValidationError::Expired { .. },
                ..
            })
        ));
        return;
    }
    clock.advance_monotonic(Duration::from_hours(24)).unwrap();
    request(&validator, &headers).await.unwrap();
    let monotonic = Timer::now(&clock);

    let proof_boundary = initial
        .checked_add(Duration::from_secs(60) + leeway)
        .unwrap();
    clock.set_wall_time(proof_boundary.checked_sub(Duration::from_nanos(1)).unwrap());
    request(&validator, &headers).await.unwrap();
    clock.set_wall_time(proof_boundary);
    request(&validator, &headers).await.unwrap();
    clock.set_wall_time(proof_boundary.checked_add(Duration::from_nanos(1)).unwrap());
    assert!(matches!(
        request(&validator, &headers).await,
        Err(ValidateHeadersError::Binding {
            source: TokenBindingError::DPoPBinding { .. },
            ..
        })
    ));

    // A fresh proof lets the access token's expiry be tested independently.
    headers.insert(
        "dpop",
        sign_proof(key, token, NOW + 100).await.parse().unwrap(),
    );
    let expiry = initial
        .checked_add(Duration::from_secs(120) + leeway)
        .unwrap();
    clock.set_wall_time(expiry.checked_sub(Duration::from_nanos(1)).unwrap());
    request(&validator, &headers).await.unwrap();
    for reading in [expiry, expiry.checked_add(Duration::from_nanos(1)).unwrap()] {
        clock.set_wall_time(reading);
        assert!(matches!(
            request(&validator, &headers).await,
            Err(ValidateHeadersError::InvalidJwt {
                source: JwtValidationError::Expired { .. },
                ..
            })
        ));
    }

    clock.set_wall_time(initial);
    headers.insert("dpop", sign_proof(key, token, NOW).await.parse().unwrap());
    request(&validator, &headers).await.unwrap();
    assert_eq!(Timer::now(&clock), monotonic);
}

#[rstest]
#[case::rfc9068(false, Duration::ZERO)]
#[case::rfc9068_leeway(false, Duration::from_secs(10))]
#[case::custom(true, Duration::ZERO)]
#[case::custom_leeway(true, Duration::from_secs(10))]
#[tokio::test]
async fn access_token_proof_and_nonce_share_clock(
    #[case] custom: bool,
    #[case] leeway: Duration,
    #[values(false, true)] advance_during_verification: bool,
) {
    let clock = time();
    let nonce_checker = Arc::new(NonceClock {
        clock: clock.clone(),
        calls: AtomicUsize::new(0),
        expected: advance_during_verification.then(|| Clock::now(&clock)),
    });
    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let signer = key.select_asymmetric_signer().await;
    let jwk = signer.public_key_jwk().into_owned();
    let verifier = NativeVerifierPlatform
        .create_verifier_from_jwk(jwk.clone())
        .await
        .unwrap();
    let token = Jwt::builder()
        .typ("at+jwt")
        .iss("https://issuer.example")
        .audience("resource")
        .sub("user")
        .iat(timestamp(NOW))
        .exp(timestamp(NOW + 120))
        .jti(Some("access".to_owned()))
        .claims(serde_json::json!({"client_id": "client", "cnf": {"jkt": jwk.thumbprint()}}))
        .build()
        .to_jws_compact(&*signer)
        .await
        .unwrap();
    let token = token.expose_secret();
    let verifier = if advance_during_verification {
        Arc::new(AdvancingVerifier {
            inner: verifier,
            clock: clock.clone(),
        }) as Arc<dyn JwsVerifier>
    } else {
        verifier
    };
    if custom {
        let validator = CustomValidator::builder()
            .jws_verifier_factory(factory(verifier))
            .clock(Arc::new(clock.clone()))
            .clock_leeway(leeway)
            .max_dpop_proof_age(Duration::from_secs(60))
            .dpop_nonce_checker(nonce_checker.clone())
            .build()
            .await
            .unwrap();
        check_bound_request(
            validator,
            clock,
            &key,
            token,
            leeway,
            advance_during_verification,
        )
        .await;
    } else {
        let validator = Rfc9068Validator::builder()
            .issuer("https://issuer.example")
            .audience("resource")
            .jws_verifier_factory(factory(verifier))
            .clock(clock.clone())
            .clock_leeway(leeway)
            .max_dpop_proof_age(Duration::from_secs(60))
            .dpop_nonce_checker(nonce_checker.clone())
            .build()
            .await
            .unwrap();
        check_bound_request(
            validator,
            clock,
            &key,
            token,
            leeway,
            advance_during_verification,
        )
        .await;
    }
    assert!(nonce_checker.calls.load(Ordering::Relaxed) > 0);
}

#[rstest]
#[case(Duration::ZERO)]
#[case(Duration::from_secs(10))]
#[tokio::test]
async fn standalone_proof_future_iat_boundary(#[case] leeway: Duration) {
    let clock = time();
    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let proof = sign_proof(&key, "token", NOW).await;
    let validator = DPoPProofValidator::builder()
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .clock(clock.clone())
        .clock_leeway(leeway)
        .build();
    let boundary = Clock::now(&clock).checked_sub(leeway).unwrap();
    clock.set_wall_time(boundary.checked_sub(Duration::from_nanos(1)).unwrap());
    assert!(matches!(
        validator.validate(&proof).await,
        Err(DPoPProofError::InvalidProof {
            source: JwtValidationError::IssuedInFuture { .. }
        })
    ));
    clock.set_wall_time(boundary);
    assert!(validator.validate(&proof).await.is_ok());
    clock.advance(Duration::from_nanos(1)).unwrap();
    assert!(validator.validate(&proof).await.is_ok());
    clock.advance(Duration::from_hours(24)).unwrap();
    assert!(validator.validate(&proof).await.is_err());
    assert!(validator.validate_at(&proof, boundary).await.is_ok());
}

/// Returns a signed response without involving sockets or runtime timing.
#[derive(Clone)]
struct SignedIntrospectionResponse(String);

impl HttpClient for SignedIntrospectionResponse {
    fn execute(
        &self,
        _request: http::Request<bytes::Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/token-introspection+jwt"),
            );
            Ok(HttpResponse {
                status: http::StatusCode::OK,
                headers,
                body: bytes::Bytes::copy_from_slice(self.0.as_bytes()),
            })
        })
    }
}

async fn introspection_response(key: &PrivateKey) -> SignedIntrospectionResponse {
    let signer = key.select_asymmetric_signer().await;
    let response = Jwt::builder()
        .typ("token-introspection+jwt")
        .iss("https://issuer.example")
        .audience("resource")
        .iat(timestamp(NOW))
        .exp(timestamp(NOW + 120))
        .claims(serde_json::json!({"token_introspection": {
            "active": true, "sub": "user", "aud": "resource",
            "cnf": {"jkt": signer.public_key_jwk().thumbprint()}
        }}))
        .build()
        .to_jws_compact(&*signer)
        .await
        .unwrap();
    SignedIntrospectionResponse(response.expose_secret().to_owned())
}

#[rstest]
#[case(Duration::ZERO)]
#[case(Duration::from_secs(10))]
#[tokio::test]
async fn introspection_response_proof_and_nonce_share_clock(#[case] leeway: Duration) {
    let clock = time();
    let nonce_checker = NonceClock::new(&clock);
    let initial = Clock::now(&clock);
    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let verifier = NativeVerifierPlatform
        .create_verifier_from_jwk(key.as_private_jwk().public_jwk())
        .await
        .unwrap();
    let response = introspection_response(&key).await;
    let endpoint: EndpointUrl = "https://issuer.example/introspect".parse().unwrap();
    let raw = TokenIntrospection::builder()
        .client_id("resource")
        .issuer("https://issuer.example")
        .introspection_endpoint(endpoint.clone())
        .client_auth(NoAuth)
        .jws_verifier_factory(factory(verifier.clone()))
        .clock(clock.clone())
        .clock_leeway(leeway)
        .build()
        .await
        .unwrap();
    let validator = IntrospectionValidator::builder()
        .aud(ClaimCheck::required_value("resource"))
        .client_id("resource")
        .issuer("https://issuer.example")
        .introspection_endpoint(endpoint)
        .client_auth(NoAuth)
        .http_client(response.clone())
        .jws_verifier_factory(factory(verifier))
        .clock(Arc::new(clock.clone()))
        .clock_leeway(leeway)
        .max_dpop_proof_age(Duration::from_secs(60))
        .dpop_nonce_checker(nonce_checker.clone())
        .build()
        .await
        .unwrap();
    let token = SecretString::new("opaque-token");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("DPoP opaque-token"),
    );
    headers.insert(
        "dpop",
        sign_proof(&key, token.expose_secret(), NOW)
            .await
            .parse()
            .unwrap(),
    );

    request(&validator, &headers).await.unwrap();
    clock.advance_monotonic(Duration::from_hours(24)).unwrap();
    request(&validator, &headers).await.unwrap();
    let monotonic = Timer::now(&clock);
    let proof_boundary = initial
        .checked_add(Duration::from_secs(60) + leeway)
        .unwrap();
    for reading in [
        proof_boundary.checked_sub(Duration::from_nanos(1)).unwrap(),
        proof_boundary,
    ] {
        clock.set_wall_time(reading);
        request(&validator, &headers).await.unwrap();
    }
    clock.set_wall_time(proof_boundary.checked_add(Duration::from_nanos(1)).unwrap());
    assert!(matches!(
        request(&validator, &headers).await,
        Err(IntrospectionValidateError::Binding {
            source: TokenBindingError::DPoPBinding { .. },
            ..
        })
    ));

    headers.insert(
        "dpop",
        sign_proof(&key, token.expose_secret(), NOW + 100)
            .await
            .parse()
            .unwrap(),
    );
    let expiry = initial
        .checked_add(Duration::from_secs(120) + leeway)
        .unwrap();
    clock.set_wall_time(expiry.checked_sub(Duration::from_nanos(1)).unwrap());
    request(&validator, &headers).await.unwrap();
    raw.introspect::<_, ()>(&response, &token).await.unwrap();
    for reading in [expiry, expiry.checked_add(Duration::from_nanos(1)).unwrap()] {
        clock.set_wall_time(reading);
        assert!(matches!(
            request(&validator, &headers).await,
            Err(IntrospectionValidateError::Call {
                source: IntrospectionCallError::JwtResponse {
                    source: JwtValidationError::Expired { .. }
                },
                ..
            })
        ));
        assert!(matches!(
            raw.introspect::<_, ()>(&response, &token).await,
            Err(IntrospectionCallError::JwtResponse {
                source: JwtValidationError::Expired { .. }
            })
        ));
    }
    clock.set_wall_time(initial);
    headers.insert(
        "dpop",
        sign_proof(&key, token.expose_secret(), NOW)
            .await
            .parse()
            .unwrap(),
    );
    request(&validator, &headers).await.unwrap();
    raw.introspect::<_, ()>(&response, &token).await.unwrap();
    assert_eq!(Timer::now(&clock), monotonic);
    assert!(nonce_checker.calls.load(Ordering::Relaxed) > 0);
}

struct DelayedJwksFailure(huskarl_resource_server::core::time::ManualTime);

impl huskarl_resource_server::core::http::HttpClient for DelayedJwksFailure {
    fn execute(
        &self,
        _: http::Request<bytes::Bytes>,
        _: huskarl_resource_server::core::http::Idempotency,
    ) -> huskarl_resource_server::core::platform::MaybeSendBoxFuture<
        '_,
        Result<
            huskarl_resource_server::core::http::HttpResponse,
            huskarl_resource_server::core::Error,
        >,
    > {
        Box::pin(async move {
            self.0.advance(std::time::Duration::from_secs(7)).unwrap();
            Ok(huskarl_resource_server::core::http::HttpResponse {
                status: http::StatusCode::SERVICE_UNAVAILABLE,
                headers: http::HeaderMap::from_iter([(
                    http::header::RETRY_AFTER,
                    http::HeaderValue::from_static("Thu, 01 Jan 1970 00:17:40 GMT"),
                )]),
                body: bytes::Bytes::new(),
            })
        })
    }
}

#[rstest::rstest]
#[case::clock_first(true, false)]
#[case::source_first(false, false)]
#[case::explicit_factory(true, true)]
#[tokio::test]
async fn custom_jwks_source_inherits_clock_in_either_order(
    #[case] clock_first: bool,
    #[case] explicit_factory: bool,
) {
    let time = ManualTime::new(jiff::Timestamp::new(1_000, 250_000_000).unwrap());
    let builder = CustomValidator::builder()
        .jwks_uri("https://as.example/jwks".parse().unwrap())
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform));
    let result = if explicit_factory {
        let factory = huskarl_resource_server::core::jwk::JwksSource::builder()
            .http_client(DelayedJwksFailure(time.clone()))
            .clock(ManualTime::new(jiff::Timestamp::new(1_020, 0).unwrap()))
            .build();
        builder
            .clock(time)
            .jws_verifier_factory(factory)
            .build()
            .await
    } else if clock_first {
        builder
            .clock(time.clone())
            .jwks_source(DelayedJwksFailure(time))
            .build()
            .await
    } else {
        builder
            .jwks_source(DelayedJwksFailure(time.clone()))
            .clock(time)
            .build()
            .await
    };
    let error = result.err().expect("JWKS fetch fails");
    assert_eq!(
        error.retry_advice(),
        huskarl_resource_server::core::RetryAdvice::retry_after(Duration::from_millis(
            if explicit_factory { 40_000 } else { 52_750 }
        ))
    );
}

#[rstest::rstest]
#[case::clock_first(true, false)]
#[case::source_first(false, false)]
#[case::explicit_factory(true, true)]
#[tokio::test]
async fn rfc9068_jwks_source_inherits_clock_in_either_order(
    #[case] clock_first: bool,
    #[case] explicit_factory: bool,
) {
    let time = ManualTime::new(jiff::Timestamp::new(1_000, 250_000_000).unwrap());
    let builder = Rfc9068Validator::builder()
        .issuer("https://as.example")
        .audience("api")
        .jwks_uri("https://as.example/jwks".parse().unwrap())
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform));
    let result = if explicit_factory {
        let factory = huskarl_resource_server::core::jwk::JwksSource::builder()
            .http_client(DelayedJwksFailure(time.clone()))
            .clock(ManualTime::new(jiff::Timestamp::new(1_020, 0).unwrap()))
            .build();
        builder
            .clock(time)
            .jws_verifier_factory(factory)
            .build()
            .await
    } else if clock_first {
        builder
            .clock(time.clone())
            .jwks_source(DelayedJwksFailure(time))
            .build()
            .await
    } else {
        builder
            .jwks_source(DelayedJwksFailure(time.clone()))
            .clock(time)
            .build()
            .await
    };
    let error = result.err().expect("JWKS fetch fails");
    assert_eq!(
        error.retry_advice(),
        huskarl_resource_server::core::RetryAdvice::retry_after(Duration::from_millis(
            if explicit_factory { 40_000 } else { 52_750 }
        ))
    );
}

#[derive(Debug)]
struct AdvancingVerifier {
    inner: Arc<dyn JwsVerifier>,
    clock: ManualTime,
}

impl JwsVerifier for AdvancingVerifier {
    fn key_match(&self, key: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        self.inner.key_match(key)
    }
    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        key: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async move {
            self.inner.verify(input, signature, key).await?;
            self.clock.advance(Duration::from_secs(300)).unwrap();
            Ok(())
        })
    }
}

#[derive(Clone)]
struct DelayedIntrospectionResponse {
    response: SignedIntrospectionResponse,
    clock: ManualTime,
}

impl HttpClient for DelayedIntrospectionResponse {
    fn execute(
        &self,
        request: http::Request<bytes::Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            self.clock.advance(Duration::from_secs(7)).unwrap();
            self.response.execute(request, idempotency).await
        })
    }
}

#[derive(Debug, Clone)]
struct CountingClock {
    time: ManualTime,
    reads: Arc<AtomicUsize>,
}

impl Clock for CountingClock {
    fn now(&self) -> jiff::Timestamp {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Clock::now(&self.time)
    }
}

#[tokio::test]
async fn introspection_keeps_receipt_snapshot_during_signature_verification() {
    let time = time();
    let clock = CountingClock {
        time: time.clone(),
        reads: Arc::new(AtomicUsize::new(0)),
    };
    let received_at = Clock::now(&time)
        .checked_add(Duration::from_secs(7))
        .unwrap();
    let nonce_checker = Arc::new(NonceClock {
        clock: time.clone(),
        calls: AtomicUsize::new(0),
        expected: Some(received_at),
    });
    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let verifier = NativeVerifierPlatform
        .create_verifier_from_jwk(key.as_private_jwk().public_jwk())
        .await
        .unwrap();
    let verifier = Arc::new(AdvancingVerifier {
        inner: verifier,
        clock: time.clone(),
    });
    let validator = IntrospectionValidator::builder()
        .aud(ClaimCheck::required_value("resource"))
        .client_id("resource")
        .issuer("https://issuer.example")
        .introspection_endpoint("https://issuer.example/introspect".parse().unwrap())
        .client_auth(NoAuth)
        .http_client(DelayedIntrospectionResponse {
            response: introspection_response(&key).await,
            clock: time.clone(),
        })
        .jws_verifier_factory(factory(verifier))
        .clock(clock.clone())
        .clock_leeway(Duration::ZERO)
        .max_dpop_proof_age(Duration::from_secs(60))
        .dpop_nonce_checker(nonce_checker.clone())
        .build()
        .await
        .unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        "DPoP opaque-token".parse().unwrap(),
    );
    // Valid at receipt, but in the future at request time and too old after verification.
    headers.insert(
        "dpop",
        sign_proof(&key, "opaque-token", NOW + 7)
            .await
            .parse()
            .unwrap(),
    );
    clock.reads.store(0, Ordering::Relaxed);
    request(&validator, &headers).await.unwrap();
    assert_eq!(
        clock.reads.load(Ordering::Relaxed),
        2,
        "request authentication and response receipt are the only clock reads"
    );
    assert_eq!(
        Clock::now(&time),
        received_at.checked_add(Duration::from_secs(300)).unwrap()
    );
    assert_eq!(nonce_checker.calls.load(Ordering::Relaxed), 1);
    assert!(matches!(
        request(&validator, &headers).await,
        Err(IntrospectionValidateError::Call {
            source: IntrospectionCallError::JwtResponse {
                source: JwtValidationError::Expired { .. }
            },
            ..
        })
    ));
    assert_eq!(nonce_checker.calls.load(Ordering::Relaxed), 1);
}
