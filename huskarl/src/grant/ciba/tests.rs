use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use futures_util::FutureExt as _;
use http::{HeaderMap, Request, StatusCode};
use huskarl_crypto_native::asymmetric::{
    signer::{GenerateAlgorithm, PrivateKey},
    verifier::AsymmetricPublicKey,
};
use serde_json::{Value, json};

use super::*;
use crate::{
    core::{
        Error, RetryAdvice,
        client_auth::{ClientSecret, NoAuth},
        crypto::signer::AsymmetricJwsSignerSelector,
        http::{HttpClient, HttpResponse, Idempotency},
        jwt::{Jwt, validator::JwtValidator},
        platform::{Duration, MaybeSendBoxFuture},
        secrets::{ProvidedSecret, SecretString},
        server_metadata::AuthorizationServerMetadata,
        time::{Clock, ManualTime, system_time_from_timestamp_saturating},
    },
    grant::{ClientConfiguration, core::OAuth2ExchangeGrant},
};

#[derive(Clone, Default)]
struct Transport {
    responses: Arc<Mutex<VecDeque<HttpResponse>>>,
    requests: Arc<Mutex<Vec<Request<Bytes>>>>,
    mtls: bool,
}

impl Transport {
    fn respond(&self, status: StatusCode, body: &Value) {
        self.responses.lock().unwrap().push_back(HttpResponse {
            status,
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
        });
    }

    fn form(&self, index: usize) -> HashMap<String, String> {
        form_urlencoded::parse(self.requests.lock().unwrap()[index].body())
            .into_owned()
            .collect()
    }
}

impl HttpClient for Transport {
    fn uses_mtls(&self) -> bool {
        self.mtls
    }

    fn execute(
        &self,
        request: Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        self.requests.lock().unwrap().push(request);
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected HTTP request");
        Box::pin(async move { Ok(response) })
    }
}

struct Fixture {
    key: PrivateKey,
    verifier: AsymmetricPublicKey,
    time: ManualTime,
    http: Transport,
}

impl Fixture {
    async fn new() -> Self {
        let key =
            PrivateKey::generate(GenerateAlgorithm::Es256, Some("provider-key".into())).unwrap();
        let verifier = AsymmetricPublicKey::from_jwk(
            key.select_asymmetric_signer()
                .await
                .public_key_jwk()
                .into_owned(),
        )
        .unwrap();
        Self {
            key,
            verifier,
            time: ManualTime::new(jiff::Timestamp::from_second(1_700_000_000).unwrap()),
            http: Transport::default(),
        }
    }

    fn grant(&self, signed: bool, retries: u32) -> CibaPollGrant {
        self.grant_with_token_age(signed, retries, None)
    }

    fn grant_with_token_age(
        &self,
        signed: bool,
        retries: u32,
        max_age: Option<Duration>,
    ) -> CibaPollGrant {
        let client = ClientConfiguration::builder()
            .client_id("client")
            .client_auth(ClientSecret::new(ProvidedSecret::new(SecretString::new(
                "secret",
            ))))
            .build();
        CibaPollGrant::builder()
            .client(&client)
            .issuer("https://as.example")
            .token_endpoint("https://as.example/token".parse().unwrap())
            .backchannel_authentication_endpoint("https://as.example/backchannel".parse().unwrap())
            .http_client(self.http.clone())
            .clock(self.time.clone())
            .timer(self.time.clone())
            .jws_verifier(self.verifier.clone())
            .maybe_request_signer(signed.then(|| self.key.clone()))
            .max_transient_poll_failures(retries)
            .maybe_max_id_token_age(max_age)
            .build()
            .unwrap()
    }

    async fn token(&self, issuer: &str, audience: &str) -> Value {
        let jwt = Jwt::builder()
            .iss(issuer)
            .audience(audience)
            .sub("user")
            .issued_at_not_before_expires_after(
                system_time_from_timestamp_saturating(self.time.now()),
                Duration::from_secs(600),
            )
            .claims(())
            .build()
            .to_jws_compact(self.key.select_asymmetric_signer().await.as_ref())
            .await
            .unwrap();
        json!({"access_token":"access", "token_type":"Bearer", "id_token":jwt.expose_secret(), "refresh_token":"refresh"})
    }
}

fn pending() -> PendingState {
    PendingState::builder()
        .expires_at(system_time_from_timestamp_saturating(
            jiff::Timestamp::from_second(1_700_003_600).unwrap(),
        ))
        .auth_req_id("request-id")
        .interval_secs(5)
        .build()
}

fn input() -> StartInput {
    StartInput::builder()
        .hint(CibaHint::login_hint("person@example.com"))
        .build()
}

#[tokio::test]
async fn start_and_complete_with_validated_identity() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    f.http.respond(
        StatusCode::OK,
        &json!({"auth_req_id":"request-id", "expires_in":120}),
    );
    let mut started = grant.start(input()).await.unwrap();
    assert_eq!(started.pending_state.interval_secs, 5);
    assert_eq!(
        started.expires_at,
        system_time_from_timestamp_saturating(f.time.now()) + Duration::from_secs(120)
    );
    let form = f.http.form(0);
    assert_eq!(form["scope"], "openid");
    assert_eq!(form["login_hint"], "person@example.com");
    assert_eq!(form["client_id"], "client");
    assert_eq!(form["client_secret"], "secret");
    assert!(!form.contains_key("client_notification_token"));
    f.http.respond(
        StatusCode::OK,
        &f.token("https://as.example", "client").await,
    );
    let PollResult::Complete(result) = grant.poll(&mut started.pending_state, None).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(result.id_token.sub.as_deref(), Some("user"));
    assert!(result.token_response.refresh_token().is_some());
    assert_eq!(
        f.http.form(1)["grant_type"],
        "urn:openid:params:grant-type:ciba"
    );
    assert_eq!(f.http.form(1)["auth_req_id"], "request-id");
    assert_eq!(
        grant.to_refresh_grant().issuer(),
        Some("https://as.example")
    );
    assert!(grant.jws_verifier().is_some());
}

#[tokio::test]
async fn signed_requests_contain_all_authentication_parameters_and_fresh_jti() {
    let f = Fixture::new().await;
    let grant = f.grant(true, 5);
    let validator = JwtValidator::builder()
        .verifier(f.verifier.clone())
        .clock(f.time.clone())
        .typ(crate::core::jwt::validator::ClaimCheck::required_value(
            "oauth-authz-req+jwt",
        ))
        .build();
    let mut ids = Vec::new();
    for hint in [
        CibaHint::login_hint_token(String::from("hint-token")),
        CibaHint::id_token_hint("previous-id-token"),
    ] {
        f.http.respond(
            StatusCode::OK,
            &json!({"auth_req_id":"id", "expires_in":120, "interval":2}),
        );
        grant
            .start(
                StartInput::builder()
                    .hint(hint)
                    .scope(bon::vec!["openid", "email"])
                    .acr_values(bon::vec!["strong", "normal"])
                    .binding_message("A123")
                    .user_code("private-code")
                    .requested_expiry(std::num::NonZeroU32::new(60).unwrap())
                    .build(),
            )
            .await
            .unwrap();
        let form = f.http.form(ids.len());
        assert_eq!(
            form.len(),
            3,
            "only request and client authentication belong outside the JWT"
        );
        let claims = validator.validate::<Value>(&form["request"]).await.unwrap();
        assert_eq!(claims.iss.as_deref(), Some("client"));
        assert_eq!(claims.aud, ["https://as.example"]);
        assert!(claims.iat.is_some() && claims.exp.is_some());
        ids.push(claims.jti.unwrap());
        assert_eq!(claims.claims["scope"], "openid email");
        assert_eq!(claims.claims["acr_values"], "strong normal");
        assert_eq!(claims.claims["binding_message"], "A123");
        assert_eq!(claims.claims["user_code"], "private-code");
        assert_eq!(claims.claims["requested_expiry"], 60);
        assert_ne!(
            claims.claims.get("login_hint_token").is_some(),
            claims.claims.get("id_token_hint").is_some()
        );
    }
    assert_ne!(ids[0], ids[1]);
}

#[tokio::test]
async fn polling_verdicts_match_device_flow_and_server_errors_do_not_change_cadence() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    let mut state = pending();
    for error in ["authorization_pending", "slow_down"] {
        f.http
            .respond(StatusCode::BAD_REQUEST, &json!({"error":error}));
        assert!(matches!(
            grant.poll(&mut state, None).await,
            Ok(PollResult::Pending)
        ));
    }
    assert_eq!(state.interval_secs, 10);
    f.http.respond(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({"error":"slow_down"}),
    );
    assert!(matches!(
        grant.poll(&mut state, None).await,
        Err(PollError::Exchange { .. })
    ));
    assert_eq!(state.interval_secs, 10);
}

#[rstest::rstest]
#[case::denied("access_denied")]
#[case::expired("expired_token")]
#[case::invalid_request("invalid_request")]
#[case::invalid_grant("invalid_grant")]
#[tokio::test]
async fn terminal_polling_verdicts_preserve_the_error(#[case] code: &str) {
    let f = Fixture::new().await;
    f.http
        .respond(StatusCode::BAD_REQUEST, &json!({"error":code}));
    let error = f
        .grant(false, 5)
        .poll(&mut pending(), None)
        .await
        .unwrap_err();
    assert_eq!(error.retry_advice(), RetryAdvice::No);
    match code {
        "access_denied" => assert!(matches!(error, PollError::AccessDenied)),
        "expired_token" => assert!(matches!(error, PollError::TokenExpired)),
        _ => {
            let PollError::Exchange { source } = error else {
                panic!("expected an exchange error, got {error:?}");
            };
            assert_eq!(source.verdict().unwrap().code().as_str(), code);
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum InvalidIdentity {
    MissingToken,
    Issuer,
    Audience,
    Signature,
    Expired,
}

#[rstest::rstest]
#[case::missing_token(InvalidIdentity::MissingToken)]
#[case::wrong_issuer(InvalidIdentity::Issuer)]
#[case::wrong_audience(InvalidIdentity::Audience)]
#[case::wrong_signature(InvalidIdentity::Signature)]
#[case::expired(InvalidIdentity::Expired)]
#[tokio::test]
async fn completion_rejects_invalid_identity(#[case] case: InvalidIdentity) {
    use crate::{
        core::jwt::validator::JwtValidationError, token::id_token::IdTokenValidationError,
    };

    let f = Fixture::new().await;
    let body = match case {
        InvalidIdentity::MissingToken => json!({"access_token":"access", "token_type":"Bearer"}),
        InvalidIdentity::Issuer => f.token("https://wrong.example", "client").await,
        InvalidIdentity::Audience => f.token("https://as.example", "wrong-client").await,
        InvalidIdentity::Signature => {
            Fixture::new()
                .await
                .token("https://as.example", "client")
                .await
        }
        InvalidIdentity::Expired => {
            let token = f.token("https://as.example", "client").await;
            f.time.advance(Duration::from_secs(1000)).unwrap();
            token
        }
    };
    f.http.respond(StatusCode::OK, &body);
    let error = f
        .grant(false, 5)
        .poll(&mut pending(), None)
        .await
        .unwrap_err();
    assert_eq!(error.retry_advice(), RetryAdvice::No);
    match (case, error) {
        (InvalidIdentity::MissingToken, PollError::MissingIdToken { .. }) => {}
        (
            case,
            PollError::ValidatingIdToken {
                source: IdTokenValidationError::Jwt { source },
                ..
            },
        ) => assert!(matches!(
            (case, source),
            (
                InvalidIdentity::Issuer,
                JwtValidationError::ClaimMismatch { claim: "iss", .. }
            ) | (
                InvalidIdentity::Audience,
                JwtValidationError::ClaimMismatch { claim: "aud", .. }
            ) | (
                InvalidIdentity::Signature,
                JwtValidationError::Signature { .. }
            ) | (InvalidIdentity::Expired, JwtValidationError::Expired { .. })
        )),
        (case, error) => panic!("unexpected error for {case:?}: {error:?}"),
    }
}

#[tokio::test]
async fn automatic_polling_honors_slow_down_retry_after_and_stops_after_completion_failure() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    f.http
        .respond(StatusCode::BAD_REQUEST, &json!({"error":"slow_down"}));
    f.http.respond(StatusCode::SERVICE_UNAVAILABLE, &json!({}));
    f.http
        .responses
        .lock()
        .unwrap()
        .back_mut()
        .unwrap()
        .headers
        .insert("retry-after", "20".parse().unwrap());
    f.http.respond(
        StatusCode::OK,
        &json!({"access_token":"access", "token_type":"Bearer"}),
    );
    let mut state = pending();
    state.interval_secs = 1;
    let mut future = std::pin::pin!(grant.poll_to_completion(&mut state, None));
    for seconds in [5, 10, 20] {
        assert!(future.as_mut().now_or_never().is_none());
        f.time.advance(Duration::from_secs(seconds - 1)).unwrap();
        assert!(future.as_mut().now_or_never().is_none());
        f.time.advance(Duration::from_secs(1)).unwrap();
    }
    assert!(matches!(
        future.as_mut().now_or_never(),
        Some(Err(PollError::MissingIdToken { .. }))
    ));
    assert_eq!(f.http.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn transient_retry_budget_is_bounded() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 1);
    for _ in 0..2 {
        f.http.respond(StatusCode::SERVICE_UNAVAILABLE, &json!({}));
    }
    let mut state = pending();
    let mut future = std::pin::pin!(grant.poll_to_completion(&mut state, None));
    for _ in 0..2 {
        assert!(future.as_mut().now_or_never().is_none());
        f.time.advance(Duration::from_secs(5)).unwrap();
    }
    assert!(matches!(
        future.as_mut().now_or_never(),
        Some(Err(PollError::Exchange { .. }))
    ));
}

#[rstest::rstest]
#[case::missing_expiry(json!({"auth_req_id":"id"}))]
#[case::empty_request_id(json!({"auth_req_id":"", "expires_in":5}))]
#[case::zero_expiry(json!({"auth_req_id":"id", "expires_in":0}))]
#[case::string_expiry(json!({"auth_req_id":"id", "expires_in":"60"}))]
#[case::string_interval(json!({"auth_req_id":"id", "expires_in":60, "interval":"5"}))]
#[case::zero_interval(json!({"auth_req_id":"id", "expires_in":5, "interval":0}))]
#[tokio::test]
async fn invalid_acknowledgements_are_rejected(#[case] body: Value) {
    let f = Fixture::new().await;
    f.http.respond(StatusCode::OK, &body);
    assert!(f.grant(false, 5).start(input()).await.is_err());
}

#[tokio::test]
async fn start_preserves_provider_errors() {
    let f = Fixture::new().await;
    f.http
        .respond(StatusCode::BAD_REQUEST, &json!({"error":"unknown_user_id"}));
    let err = f.grant(false, 5).start(input()).await.unwrap_err();
    assert_eq!(err.verdict().unwrap().code().as_str(), "unknown_user_id");
}

fn metadata() -> AuthorizationServerMetadata {
    serde_json::from_value(json!({
        "issuer":"https://as.example", "token_endpoint":"https://as.example/token",
        "response_types_supported":[], "backchannel_authentication_endpoint":"https://as.example/backchannel",
        "backchannel_token_delivery_modes_supported":["poll"],
        "id_token_signing_alg_values_supported":["ES256"],
        "mtls_endpoint_aliases":{"token_endpoint":"https://mtls.example/token", "backchannel_authentication_endpoint":"https://mtls.example/backchannel"}
    })).unwrap()
}

#[tokio::test]
async fn metadata_selects_mtls_endpoint_aliases() {
    let mut f = Fixture::new().await;
    f.http.mtls = true;
    let metadata = metadata();
    let grant = CibaPollGrant::builder_from_metadata(&metadata)
        .unwrap()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(f.http.clone())
        .jws_verifier(f.verifier.clone())
        .build()
        .unwrap();
    f.http.respond(
        StatusCode::OK,
        &json!({"auth_req_id":"id", "expires_in":10}),
    );
    grant.start(input()).await.unwrap();
    assert_eq!(
        f.http.requests.lock().unwrap()[0].uri(),
        "https://mtls.example/backchannel"
    );
    assert_eq!(
        grant.effective_token_endpoint().to_string(),
        "https://mtls.example/token"
    );
}

#[tokio::test]
async fn metadata_prohibits_unsupported_user_codes() {
    let mut f = Fixture::new().await;
    f.http.mtls = true;
    let metadata = metadata();
    let grant = CibaPollGrant::builder_from_metadata(&metadata)
        .unwrap()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(f.http.clone())
        .jws_verifier(f.verifier.clone())
        .build()
        .unwrap();
    assert!(
        grant
            .start(
                StartInput::builder()
                    .hint(CibaHint::login_hint(SecretString::new("user")))
                    .user_code("code")
                    .build()
            )
            .await
            .is_err()
    );
    assert!(f.http.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn metadata_prohibits_unadvertised_request_signing() {
    let mut f = Fixture::new().await;
    f.http.mtls = true;
    let metadata = metadata();
    assert!(
        CibaPollGrant::builder_from_metadata(&metadata)
            .unwrap()
            .client_id("client")
            .client_auth(NoAuth)
            .http_client(f.http.clone())
            .jws_verifier(f.verifier.clone())
            .request_signer(f.key.clone())
            .build()
            .is_err()
    );
}

#[rstest::rstest]
#[case::missing(None)]
#[case::ping(Some(bon::vec!["ping"]))]
#[case::push(Some(bon::vec!["push"]))]
#[tokio::test]
async fn metadata_requires_poll_mode(#[case] modes: Option<Vec<String>>) {
    let mut f = Fixture::new().await;
    f.http.mtls = true;
    let mut metadata = metadata();
    metadata.backchannel_token_delivery_modes_supported = modes;
    assert!(
        CibaPollGrant::builder_from_metadata(&metadata)
            .unwrap()
            .client_id("client")
            .client_auth(NoAuth)
            .http_client(f.http.clone())
            .jws_verifier(f.verifier.clone())
            .build()
            .is_err()
    );
}

#[tokio::test]
async fn metadata_checks_selected_request_signing_algorithm() {
    let mut f = Fixture::new().await;
    f.http.mtls = true;
    let mut signing_metadata = metadata();
    signing_metadata.backchannel_authentication_request_signing_alg_values_supported =
        Some(vec!["RS256".into()]);
    let grant = CibaPollGrant::builder_from_metadata(&signing_metadata)
        .unwrap()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(f.http.clone())
        .jws_verifier(f.verifier.clone())
        .request_signer(f.key.clone())
        .build()
        .unwrap();
    assert!(
        grant.start(input()).await.is_err(),
        "the selected ES256 key is not advertised"
    );
    assert!(f.http.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unauthenticated_clients_are_rejected() {
    let f = Fixture::new().await;
    let metadata = metadata();
    assert!(
        CibaPollGrant::builder_from_metadata(&metadata)
            .unwrap()
            .client_id("client")
            .client_auth(NoAuth)
            .http_client(f.http.clone())
            .jws_verifier(f.verifier.clone())
            .build()
            .is_err()
    );
}

#[test]
fn persisted_state_round_trips_without_debug_exposure() {
    let state = pending();
    let restored: PendingState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    assert_eq!(restored.auth_req_id, state.auth_req_id);
    assert_eq!(restored.interval_secs, 5);
    assert!(!format!("{state:?}").contains("request-id"));
    assert!(!format!("{:?}", input()).contains("person@example.com"));
}

#[tokio::test]
async fn unsigned_start_encodes_all_parameters() {
    let f = Fixture::new().await;
    f.http.respond(
        StatusCode::OK,
        &json!({"auth_req_id":"id", "expires_in":60}),
    );
    f.grant(false, 5)
        .start(
            StartInput::builder()
                .hint(CibaHint::login_hint("person@example.com"))
                .scope(bon::vec!["openid", "email"])
                .acr_values(bon::vec!["strong", "normal"])
                .binding_message("A123")
                .user_code("private-code")
                .requested_expiry(std::num::NonZeroU32::new(60).unwrap())
                .resource(bon::vec!["https://one.example", "https://two.example"])
                .authorization_details(vec![
                    crate::core::AuthorizationDetail::builder("payment_initiation").build(),
                ])
                .build(),
        )
        .await
        .unwrap();
    let form = f.http.form(0);
    assert_eq!(form["scope"], "openid email");
    assert_eq!(form["login_hint"], "person@example.com");
    assert_eq!(form["acr_values"], "strong normal");
    assert_eq!(form["binding_message"], "A123");
    assert_eq!(form["user_code"], "private-code");
    assert_eq!(form["requested_expiry"], "60");
    assert_eq!(
        serde_json::from_str::<Value>(&form["authorization_details"]).unwrap(),
        json!([{"type":"payment_initiation"}])
    );
    let requests = f.http.requests.lock().unwrap();
    let resources: Vec<_> = form_urlencoded::parse(requests[0].body())
        .filter(|(key, _)| key == "resource")
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(resources, ["https://one.example", "https://two.example"]);
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
#[tokio::test]
async fn start_retries_dpop_nonce_with_fresh_proofs_and_request_jwt(#[case] signed: bool) {
    let f = Fixture::new().await;
    let grant = CibaPollGrant::builder()
        .client_id("client")
        .client_auth(ClientSecret::new(ProvidedSecret::new(SecretString::new(
            "secret",
        ))))
        .issuer("https://as.example")
        .token_endpoint("https://as.example/token".parse().unwrap())
        .backchannel_authentication_endpoint("https://as.example/backchannel".parse().unwrap())
        .http_client(f.http.clone())
        .clock(f.time.clone())
        .jws_verifier(f.verifier.clone())
        .maybe_request_signer(signed.then(|| f.key.clone()))
        .dpop(
            crate::core::dpop::DPoP::builder()
                .signer(f.key.clone())
                .build(),
        )
        .build()
        .unwrap();
    f.http
        .respond(StatusCode::BAD_REQUEST, &json!({"error":"use_dpop_nonce"}));
    f.http
        .responses
        .lock()
        .unwrap()
        .back_mut()
        .unwrap()
        .headers
        .insert("dpop-nonce", "new-nonce".parse().unwrap());
    f.http.respond(
        StatusCode::OK,
        &json!({"auth_req_id":"id", "expires_in":60}),
    );
    grant.start(input()).await.unwrap();
    let proofs: Vec<String> = f
        .http
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.headers()["dpop"].to_str().unwrap().to_owned())
        .collect();
    assert_eq!(proofs.len(), 2);
    let validator = JwtValidator::builder()
        .verifier(f.verifier.clone())
        .clock(f.time.clone())
        .build();
    let first = validator.validate::<Value>(&proofs[0]).await.unwrap();
    let second = validator.validate::<Value>(&proofs[1]).await.unwrap();
    assert_ne!(first.jti, second.jti);
    assert!(first.claims.get("nonce").is_none());
    assert_eq!(second.claims["nonce"], "new-nonce");
    for proof in [&first, &second] {
        assert_eq!(proof.claims["htm"], "POST");
        assert_eq!(proof.claims["htu"], "https://as.example/backchannel");
    }
    if signed {
        let first = validator
            .validate::<Value>(&f.http.form(0)["request"])
            .await
            .unwrap();
        let second = validator
            .validate::<Value>(&f.http.form(1)["request"])
            .await
            .unwrap();
        assert_ne!(first.jti, second.jti);
        assert_eq!(first.claims, second.claims);
    }
}

#[rstest::rstest]
#[case::unset(None, true)]
#[case::configured(Some(Duration::from_secs(60)), false)]
#[tokio::test]
async fn polling_applies_optional_id_token_age(
    #[case] max_age: Option<Duration>,
    #[case] accepted: bool,
) {
    let f = Fixture::new().await;
    let grant = f.grant_with_token_age(false, 5, max_age);
    let token = f.token("https://as.example", "client").await;
    f.time.advance(Duration::from_secs(71)).unwrap();
    f.http.respond(StatusCode::OK, &token);
    let result = grant.poll(&mut pending(), None).await;
    if accepted {
        assert!(matches!(result.unwrap(), PollResult::Complete(_)));
    } else {
        assert!(matches!(
            result,
            Err(PollError::ValidatingIdToken {
                source: crate::token::id_token::IdTokenValidationError::Jwt {
                    source: crate::core::jwt::validator::JwtValidationError::TokenTooOld { .. }
                },
                ..
            })
        ));
    }
}

#[rstest::rstest]
#[case::huge_interval(false)]
#[case::huge_retry_after(true)]
#[tokio::test]
async fn restored_expiry_caps_huge_interval_and_retry_after(#[case] retry_after: bool) {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    f.http.respond(
        StatusCode::OK,
        &json!({
            "auth_req_id":"request-id", "expires_in":120,
            "interval": if retry_after { 5 } else { u32::MAX },
        }),
    );
    let started = grant.start(input()).await.unwrap();
    let mut state: PendingState =
        serde_json::from_value(serde_json::to_value(started.pending_state).unwrap()).unwrap();
    assert_eq!(state.expires_at, started.expires_at);
    if retry_after {
        f.http.respond(StatusCode::SERVICE_UNAVAILABLE, &json!({}));
        f.http
            .responses
            .lock()
            .unwrap()
            .back_mut()
            .unwrap()
            .headers
            .insert("retry-after", "4294967295".parse().unwrap());
    }
    let mut polling = std::pin::pin!(grant.poll_to_completion(&mut state, None));
    assert!(polling.as_mut().now_or_never().is_none());
    if retry_after {
        f.time.advance(Duration::from_secs(5)).unwrap();
        assert!(polling.as_mut().now_or_never().is_none());
    }
    f.time
        .advance(Duration::from_secs(if retry_after { 114 } else { 119 }))
        .unwrap();
    assert!(polling.as_mut().now_or_never().is_none());
    f.time.advance(Duration::from_secs(1)).unwrap();
    assert!(matches!(
        polling.as_mut().now_or_never(),
        Some(Err(PollError::TokenExpired))
    ));
    assert_eq!(
        f.http.requests.lock().unwrap().len(),
        if retry_after { 2 } else { 1 }
    );
}

#[tokio::test]
async fn expired_state_never_waits_or_sends_a_request() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    let mut state = pending();
    state.expires_at = system_time_from_timestamp_saturating(f.time.now());
    assert!(matches!(
        grant.poll_to_completion(&mut state, None).await,
        Err(PollError::TokenExpired)
    ));
    assert!(f.http.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn expected_subject_survives_restoration_and_rejects_another_user() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    f.http.respond(
        StatusCode::OK,
        &json!({"auth_req_id":"id", "expires_in":120}),
    );
    let started = grant
        .start(
            StartInput::builder()
                .hint(CibaHint::login_hint("person@example.com"))
                .expected_sub("expected-user")
                .build(),
        )
        .await
        .unwrap();
    let mut state: PendingState =
        serde_json::from_value(serde_json::to_value(started.pending_state).unwrap()).unwrap();
    assert_eq!(state.expected_sub.as_deref(), Some("expected-user"));
    f.http.respond(
        StatusCode::OK,
        &f.token("https://as.example", "client").await,
    );
    let error = grant.poll(&mut state, None).await.unwrap_err();
    assert!(matches!(error, PollError::SubjectMismatch { .. }));
    let response = error.into_token_response().unwrap();
    let error = grant.complete(response, &state).await.unwrap_err();
    assert!(matches!(error, PollError::SubjectMismatch { .. }));

    state.expected_sub = Some("user".into());
    f.http.respond(
        StatusCode::OK,
        &f.token("https://as.example", "client").await,
    );
    assert!(matches!(
        grant.poll(&mut state, None).await.unwrap(),
        PollResult::Complete(_)
    ));
}

#[cfg(feature = "experimental-oidc-key-binding")]
#[tokio::test]
async fn bound_key_is_rejected_before_authentication_starts() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    for scope in [bon::vec!["bound_key"], bon::vec!["email openid bound_key"]] {
        let error = grant
            .start(
                StartInput::builder()
                    .hint(CibaHint::login_hint("person@example.com"))
                    .scope(scope)
                    .build(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("bound_key"));
    }
    assert!(f.http.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn validation_can_be_retried_after_verifier_outage_without_redemption() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::core::crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    };

    #[derive(Debug)]
    struct RecoveringVerifier {
        available: Arc<AtomicBool>,
        key: AsymmetricPublicKey,
    }
    impl JwsVerifier for RecoveringVerifier {
        fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
            self.key.key_match(key_match)
        }
        fn verify<'a>(
            &'a self,
            input: &'a [u8],
            signature: &'a [u8],
            key_match: &'a KeyMatch<'a>,
        ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
            Box::pin(async move {
                if !self.available.load(Ordering::SeqCst) {
                    return Err(VerifyError::KeysUnavailable);
                }
                self.key.verify(input, signature, key_match).await
            })
        }
    }
    let f = Fixture::new().await;
    let available = Arc::new(AtomicBool::new(false));
    let grant = CibaPollGrant::builder()
        .client_id("client")
        .client_auth(ClientSecret::new(ProvidedSecret::new(SecretString::new(
            "secret",
        ))))
        .issuer("https://as.example")
        .token_endpoint("https://as.example/token".parse().unwrap())
        .backchannel_authentication_endpoint("https://as.example/backchannel".parse().unwrap())
        .http_client(f.http.clone())
        .clock(f.time.clone())
        .timer(f.time.clone())
        .jws_verifier(RecoveringVerifier {
            available: available.clone(),
            key: f.verifier.clone(),
        })
        .build()
        .unwrap();
    f.http.respond(
        StatusCode::OK,
        &f.token("https://as.example", "client").await,
    );
    let error = grant.poll(&mut pending(), None).await.unwrap_err();
    assert!(matches!(error, PollError::ValidatingIdToken { .. }));
    assert!(matches!(error.retry_advice(), RetryAdvice::No));
    let response = error.into_token_response().unwrap();
    let received_at = response.received_at();
    available.store(true, Ordering::SeqCst);
    let completed = grant.complete(response, &pending()).await.unwrap();
    assert_eq!(completed.id_token.sub.as_deref(), Some("user"));
    assert!(completed.token_response.refresh_token().is_some());
    assert_eq!(completed.token_response.received_at(), received_at);
    assert_eq!(f.http.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn unrepresentable_timer_deadline_does_not_park_ciba_forever() {
    let f = Fixture::new().await;
    let grant = f.grant(false, 5);
    f.time.advance_monotonic(Duration::MAX).unwrap();
    assert!(matches!(
        grant.poll_to_completion(&mut pending(), None).await,
        Err(PollError::TokenExpired)
    ));
    assert!(f.http.requests.lock().unwrap().is_empty());
}
