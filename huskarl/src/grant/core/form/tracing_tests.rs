use std::sync::{Arc, Mutex};

use tracing::{Instrument, instrument::WithSubscriber};

use super::*;
use crate::core::{dpop::NoDPoP, http::HttpResponse, platform::MaybeSendBoxFuture};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("capture mutex poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct ResponseClient(HttpResponse);

#[derive(Serialize)]
struct Form {
    client_secret: &'static str,
    code: &'static str,
}

impl HttpClient for ResponseClient {
    fn execute(
        &self,
        _: Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

#[tokio::test]
async fn info_has_one_acquisition_summary_and_no_cache_hit_noise() {
    use crate::{
        cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, TokenSource},
        core::client_auth::NoAuth,
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    };

    let output = Capture::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        let grant = ClientCredentialsGrant::builder()
            .client_id("secret-client-id")
            .client_auth(NoAuth)
            .token_endpoint("https://example.com/secret-path".parse().unwrap())
            .http_client(ResponseClient(HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: Bytes::from_static(
                    br#"{"access_token":"secret-access","token_type":"Bearer","expires_in":3600}"#,
                ),
            }))
            .build();
        let source = GrantTokenSource::builder()
            .grant(grant)
            .grant_parameters(ClientCredentialsGrantParameters::builder().build())
            .refresh_store(InMemoryRefreshTokenStore::default())
            .build();
        let cache = InMemoryTokenCache::builder().source(source).build();
        for _ in 0..3 {
            cache.token().await.unwrap();
        }
    }
    .with_subscriber(subscriber)
    .await;

    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("huskarl.token.acquire"), "{text}");
    assert!(text.contains("outcome=\"success\""), "{text}");
    assert!(!text.contains("secret-"), "{text}");
}

// Capture span attributes as well as events: default #[instrument] argument
// recording would leak the request even if every event were carefully redacted.
#[tokio::test]
async fn levels_preserve_context_without_recording_secrets() {
    for level in [
        tracing::Level::INFO,
        tracing::Level::DEBUG,
        tracing::Level::TRACE,
    ] {
        let output = Capture::default();
        let writer = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_ansi(false)
            .without_time()
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .with_writer(move || writer.clone())
            .finish();
        async {
            let parent = tracing::info_span!("application_request");
            async {
                for (status, body) in [
                    (200, r#"{"access_token":"secret-access","refresh_token":"secret-refresh"}"#),
                    (400, r#"{"error":"secret-extension-code","error_description":"secret-description","error_uri":"https://secret-error-uri","extra":"secret-extra"}"#),
                    (502, "secret-malformed-body"),
                ] {
                    let client = ResponseClient(HttpResponse {
                        status: http::StatusCode::from_u16(status).unwrap(),
                        headers: http::HeaderMap::from_iter([
                            (http::HeaderName::from_static("dpop-nonce"), HeaderValue::from_static("secret-nonce")),
                        ]),
                        body: Bytes::from_static(body.as_bytes()),
                    });
                    let uri = "https://example.com/secret-path?code=secret-query".parse().unwrap();
                    let form = Form { client_secret: "secret-client", code: "secret-code" };
                    let clock = crate::core::time::PlatformClock;
                    let request = OAuth2FormRequest::builder()
                        .now(crate::core::time::Clock::now(&clock))
                        .uri(&uri)
                        .form(&form)
                        .auth_params(AuthenticationParams::builder().build())
                        .dpop(&NoDPoP)
                        .build();
                    let result: Result<serde_json::Value, Error> =
                        request.execute(&client, &clock).await.map(|(value, _)| value);
                    assert_eq!(result.is_ok(), status == 200);
                }
            }.instrument(parent).await;
        }.with_subscriber(subscriber).await;

        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("secret-"), "{text}");
        assert!(text.contains("application_request"), "{text}");
        assert_eq!(
            text.contains("Received OAuth form response"),
            level != tracing::Level::INFO,
            "{text}"
        );
        for status in [200, 400, 502] {
            assert_eq!(
                text.contains(&format!("status={status}")),
                level == tracing::Level::TRACE || (level == tracing::Level::DEBUG && status != 200),
                "{text}"
            );
        }
        assert_eq!(
            text.contains("Sending OAuth form request"),
            level == tracing::Level::TRACE,
            "{text}"
        );
        if level != tracing::Level::INFO {
            assert!(text.contains("oauth_error=\"other\""), "{text}");
            assert!(
                text.contains("application_request:huskarl.http.form"),
                "{text}"
            );
        }
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "exercise diagnostic levels and secret exclusions together"
)]
async fn exchange_reports_results_at_debug_and_policy_at_trace() {
    use crate::{
        core::client_auth::NoAuth,
        grant::{
            client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
            core::OAuth2ExchangeGrant,
        },
    };

    for level in [
        tracing::Level::INFO,
        tracing::Level::DEBUG,
        tracing::Level::TRACE,
    ] {
        for (body, success, tokens_present) in [
            (
                r#"{"access_token":"secret-access","token_type":"BeaRer","expires_in":3600,"refresh_token":"secret-refresh","id_token":"secret-id"}"#,
                true,
                true,
            ),
            (
                r#"{"access_token":"secret-access","token_type":"Bearer","expires_in":3600}"#,
                true,
                false,
            ),
            (
                r#"{"access_token":"secret-access","token_type":"secret-unknown-type"}"#,
                false,
                false,
            ),
            (r#"{"error":"secret-extension-code"}"#, false, false),
        ] {
            let output = Capture::default();
            let writer = output.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(level)
                .with_ansi(false)
                .without_time()
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                .with_writer(move || writer.clone())
                .finish();
            async {
                let parent =
                    tracing::info_span!("application_request", grant_type = "caller_value");
                async {
                    let grant = ClientCredentialsGrant::builder()
                        .client_id("secret-client")
                        .client_auth(NoAuth)
                        .token_endpoint("https://example.com/secret-path".parse().unwrap())
                        .http_client(ResponseClient(HttpResponse {
                            status: http::StatusCode::OK,
                            headers: http::HeaderMap::new(),
                            body: Bytes::from_static(body.as_bytes()),
                        }))
                        .build();
                    let result = grant
                        .exchange(ClientCredentialsGrantParameters::builder().build())
                        .await;
                    assert_eq!(result.is_ok(), success);
                    tracing::info!("Exchange returned to caller");
                }
                .instrument(parent)
                .await;
            }
            .with_subscriber(subscriber)
            .await;

            let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
            let caller_event = text
                .lines()
                .find(|line| line.contains("Exchange returned to caller"))
                .unwrap();
            assert!(
                caller_event.contains(r#"application_request{grant_type="caller_value"}"#),
                "{text}"
            );
            assert!(!text.contains("secret-"), "{text}");
            assert_eq!(
                text.contains(r#"huskarl.grant.exchange{grant_type="client_credentials"}"#),
                level != tracing::Level::INFO,
                "{text}"
            );
            let completed: Vec<_> = text
                .lines()
                .filter(|line| line.contains("Token exchange completed"))
                .collect();
            assert_eq!(
                completed.len(),
                usize::from(success && level != tracing::Level::INFO),
                "{text}"
            );
            if let Some(event) = completed.first() {
                for field in [
                    "outcome=\"success\"".to_owned(),
                    "token_type=\"Bearer\"".to_owned(),
                    "expires_in_secs=3600".to_owned(),
                    format!("refresh_token_present={tokens_present}"),
                    format!("id_token_present={tokens_present}"),
                ] {
                    assert!(event.contains(&field), "{text}");
                }
            }
            for message in [
                "Selected transport authentication policy",
                "Selected refresh-token binding policy",
                "Selected token binding policy",
                "No client authentication in the request body or headers",
                "Received OAuth form response",
            ] {
                assert_eq!(
                    text.contains(message),
                    level == tracing::Level::TRACE,
                    "{text}"
                );
            }
        }
    }
}

#[derive(Debug)]
struct AcceptSignature;

impl crate::core::crypto::verifier::JwsVerifier for AcceptSignature {
    fn key_match(
        &self,
        _: &crate::core::crypto::verifier::KeyMatch<'_>,
    ) -> Option<crate::core::crypto::KeyMatchStrength> {
        Some(crate::core::crypto::KeyMatchStrength::ByAlgorithm)
    }

    fn verify<'a>(
        &'a self,
        _: &'a [u8],
        _: &'a [u8],
        _: &'a crate::core::crypto::verifier::KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), crate::core::crypto::verifier::VerifyError>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn validation_reasons_and_policy_never_expose_claim_values() {
    use base64::prelude::*;

    use crate::{
        core::jwt::validator::JwtValidator,
        token::id_token::{IdToken, IdTokenValidator},
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({
        "iss": "secret-issuer", "sub": "secret-subject", "aud": "secret-client",
        "nonce": "secret-nonce", "iat": now, "exp": now + 3600,
    });
    let token = format!(
        "{}.{}.c2ln",
        BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"secret-key"}"#),
        BASE64_URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let id_token: IdToken = serde_json::from_value(serde_json::json!(token)).unwrap();

    for level in [tracing::Level::DEBUG, tracing::Level::TRACE] {
        let output = Capture::default();
        let writer = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_ansi(false)
            .without_time()
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .with_writer(move || writer.clone())
            .finish();
        async {
            let validator = JwtValidator::builder()
                .verifier(AcceptSignature)
                .aud("secret-wrong-audience")
                .build();
            assert!(validator.validate::<()>(&token).await.is_err());
            let validator = IdTokenValidator::builder()
                .verifier(AcceptSignature)
                .issuer("secret-issuer")
                .audience("secret-client")
                .build();
            assert!(
                validator
                    .validate(&id_token, Some("secret-wrong-nonce"))
                    .await
                    .is_err()
            );
            assert!(
                validator
                    .validate(&id_token, Some("secret-nonce"))
                    .await
                    .is_ok()
            );
        }
        .with_subscriber(subscriber)
        .await;

        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("reason=\"audience_mismatch\""), "{text}");
        assert!(text.contains("reason=\"nonce_mismatch\""), "{text}");
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("ID-token validation completed"))
                .count(),
            1,
            "{text}"
        );
        assert!(!text.contains("secret-"), "{text}");
        assert!(!text.contains(&token), "{text}");
        assert!(!text.contains("check=\""), "{text}");
        for field in [
            "audience_check_enabled=true",
            "nonce_check_enabled=true",
            "authentication_age_check_enabled=false",
        ] {
            assert_eq!(
                text.contains(field),
                level == tracing::Level::TRACE,
                "{text}"
            );
        }
    }
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn counter_traces_preserve_http_dimensions_without_request_secrets() {
    use crate::core::http::MetricsHttpClient;

    let output = Capture::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        for status in [http::StatusCode::OK, http::StatusCode::UNAUTHORIZED] {
            let client = MetricsHttpClient::builder()
                .inner(ResponseClient(HttpResponse {
                    status,
                    headers: http::HeaderMap::new(),
                    body: Bytes::from_static(b"secret-response"),
                }))
                .build();
            client
                .execute(
                    Request::builder()
                        .method("POST")
                        .uri("https://counter.example/secret-path?token=secret-query")
                        .header("Authorization", "Bearer secret-token")
                        .body(Bytes::from_static(b"secret-body"))
                        .unwrap(),
                    Idempotency::Unknown,
                )
                .await
                .unwrap();
        }
    }
    .with_subscriber(subscriber)
    .await;

    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.lines().count(), 2, "{text}");
    for expected in [
        "huskarl.http.request",
        "host=\"counter.example\"",
        "method=\"POST\"",
        "outcome=\"success\"",
        "outcome=\"error\"",
        "status=200",
        "status=401",
        "transport_error=false",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("secret-"), "{text}");
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn counter_traces_preserve_verifier_failure_classification() {
    use crate::core::crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, MetricsJwsVerifier, VerifyError},
    };

    #[derive(Debug)]
    struct Unavailable;
    impl JwsVerifier for Unavailable {
        fn key_match(&self, _: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            None
        }
        fn verify<'a>(
            &'a self,
            _: &'a [u8],
            _: &'a [u8],
            _: &'a KeyMatch<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
            Box::pin(async { Err(VerifyError::KeysUnavailable) })
        }
        fn try_refresh(&self) -> MaybeSendBoxFuture<'_, bool> {
            Box::pin(async { false })
        }
    }

    let output = Capture::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        let verifier = MetricsJwsVerifier::builder()
            .inner(Unavailable)
            .name("issuer-42")
            .build();
        let key_match = KeyMatch::builder()
            .alg("ES256")
            .kid("secret-untrusted-kid")
            .build();
        assert!(
            verifier
                .verify(b"secret-input", b"secret-signature", &key_match)
                .await
                .is_err()
        );
        assert!(!verifier.try_refresh().await);
    }
    .with_subscriber(subscriber)
    .await;
    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.lines().count(), 2, "{text}");
    for expected in [
        "huskarl.jws.verify",
        "huskarl.jws.refresh",
        "name=\"issuer-42\"",
        "alg=\"ES256\"",
        "outcome=\"keys_unavailable\"",
        "outcome=\"not_refreshed\"",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("secret-"), "{text}");
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn counter_traces_attribute_aead_to_the_selected_key_without_payloads() {
    use crate::core::{
        crypto::cipher::{
            AeadDecryptor, AeadEncryptorSelector, MetricsAeadDecryptor,
            MetricsAeadEncryptorSelector,
        },
        jwk::{OctKey, SymmetricJwk},
    };

    let output = Capture::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        let jwk = SymmetricJwk::builder()
            .key(OctKey::builder().k(vec![42; 32]).build())
            .kid("key-2026-42")
            .build();
        let key = huskarl_crypto_native::aead::AesGcmKey::from_jwk(jwk).unwrap();
        let selector = MetricsAeadEncryptorSelector::builder()
            .inner(key)
            .name("sessions-42")
            .build();
        let snapshot = selector.select_encryptor().await;
        let decryptor = MetricsAeadDecryptor::builder()
            .inner(selector)
            .name("sessions-42")
            .build();
        for _ in 0..2 {
            let encrypted = snapshot
                .encrypt(b"secret-plaintext", b"secret-aad")
                .await
                .unwrap();
            assert!(
                decryptor
                    .decrypt(
                        None,
                        &encrypted.nonce,
                        &encrypted.ciphertext,
                        &encrypted.tag,
                        b"secret-aad"
                    )
                    .await
                    .is_ok()
            );
            assert!(
                decryptor
                    .decrypt(
                        None,
                        &encrypted.nonce,
                        &encrypted.ciphertext,
                        &encrypted.tag,
                        b"secret-wrong-aad"
                    )
                    .await
                    .is_err()
            );
        }
        assert!(!decryptor.try_refresh().await);
    }
    .with_subscriber(subscriber)
    .await;
    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.matches("huskarl.aead.select").count(), 1, "{text}");
    assert_eq!(text.matches("huskarl.aead.encrypt").count(), 2, "{text}");
    for expected in [
        "huskarl.aead.decrypt",
        "huskarl.aead.refresh",
        "name=\"sessions-42\"",
        "kid=\"key-2026-42\"",
        "outcome=\"success\"",
        "outcome=\"error\"",
        "outcome=\"not_refreshed\"",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("secret-"), "{text}");
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn counter_traces_exclude_custom_labels() {
    use crate::{
        cache::{GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, TokenSource},
        core::client_auth::NoAuth,
        grant::client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    };

    let output = Capture::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        let grant = ClientCredentialsGrant::builder()
            .client_id("secret-client-id")
            .client_auth(NoAuth)
            .token_endpoint("https://example.com/secret-path".parse().unwrap())
            .http_client(ResponseClient(HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: Bytes::from_static(
                    br#"{"access_token":"secret-access","token_type":"Bearer","expires_in":3600}"#,
                ),
            }))
            .build();
        let source = GrantTokenSource::builder()
            .grant(grant)
            .grant_parameters(ClientCredentialsGrantParameters::builder().build())
            .refresh_store(InMemoryRefreshTokenStore::default())
            .metric_labels(vec![::metrics::Label::new(
                "deployment",
                "region-instance-1234",
            )])
            .build();
        let cache = InMemoryTokenCache::builder().source(source).build();
        for _ in 0..3 {
            cache.token().await.unwrap();
        }
    }
    .with_subscriber(subscriber)
    .await;

    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    let classified: Vec<_> = text
        .lines()
        .filter(|line| line.contains("Token acquisition classified"))
        .collect();
    assert_eq!(classified.len(), 1, "{text}");
    assert!(!text.contains("labels="), "{text}");
    assert!(!text.contains("deployment"), "{text}");
    assert!(!text.contains("region-instance-1234"), "{text}");
    assert!(classified[0].contains(r#"outcome="success""#), "{text}");
    assert!(!text.contains("Counter label"), "{text}");
    assert!(!text.contains("label_key"), "{text}");
    assert!(text.contains("huskarl.token.acquire"), "{text}");
    assert!(text.contains("outcome=\"success\""), "{text}");
    assert!(!text.contains("secret-"), "{text}");
}

#[tokio::test]
async fn custom_grant_type_is_recorded_on_exchange_without_other_form_fields() {
    #[derive(Serialize)]
    struct CustomForm {
        grant_type: &'static str,
        assertion: &'static str,
    }
    let output = Capture::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_writer(move || writer.clone())
        .finish();
    async {
        let exchange =
            tracing::debug_span!("huskarl.grant.exchange", grant_type = tracing::field::Empty);
        let form = CustomForm {
            grant_type: "urn:example:custom-grant",
            assertion: "secret-assertion",
        };
        let uri = "https://example.com/token".parse().unwrap();
        OAuth2FormRequest::builder()
            .now(crate::core::time::Clock::now(
                &crate::core::time::PlatformClock,
            ))
            .uri(&uri)
            .form(&form)
            .exchange_span(&exchange)
            .auth_params(AuthenticationParams::builder().build())
            .dpop(&NoDPoP)
            .build()
            .build_request()
            .await
            .unwrap();
    }
    .with_subscriber(subscriber)
    .await;
    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(
        text.contains(r#"huskarl.grant.exchange{grant_type="urn:example:custom-grant"}"#),
        "{text}"
    );
    assert!(!text.contains("secret-"), "{text}");
    assert!(!text.contains("assertion"), "{text}");
}

#[tokio::test]
async fn id_token_jwt_failures_emit_one_precise_debug_event() {
    use base64::prelude::*;

    use crate::token::id_token::{IdToken, IdTokenValidator};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let encode = |claims: serde_json::Value| {
        format!(
            "{}.{}.c2ln",
            BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            BASE64_URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    };
    let claims = serde_json::json!({
        "iss": "secret-issuer", "sub": "secret-subject", "aud": "secret-client",
        "iat": now, "exp": now + 3600,
    });
    let mut wrong_audience = claims.clone();
    wrong_audience["aud"] = serde_json::json!("secret-wrong-audience");
    let mut invalid_extra = claims;
    invalid_extra["nonce"] = serde_json::json!(42);

    for (token, reason) in [
        ("secret-malformed-token".to_owned(), "malformed_jwt"),
        (encode(wrong_audience), "audience_mismatch"),
        (encode(invalid_extra), "invalid_extra_claims"),
    ] {
        let output = Capture::default();
        let writer = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        async {
            let id_token: IdToken = serde_json::from_value(serde_json::json!(token)).unwrap();
            let validator = IdTokenValidator::builder()
                .verifier(AcceptSignature)
                .issuer("secret-issuer")
                .audience("secret-client")
                .build();
            assert!(validator.validate(&id_token, None).await.is_err());
        }
        .with_subscriber(subscriber)
        .await;
        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains(&format!("reason=\"{reason}\"")), "{text}");
        assert!(text.contains("huskarl.id_token.validate"), "{text}");
        assert!(!text.contains("jwt_validation"), "{text}");
        assert!(!text.contains("secret-"), "{text}");
        assert!(!text.contains(&token), "{text}");
    }
}
