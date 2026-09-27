use super::*;

/// One grant per authorization server; a per-session grant derived at each
/// leg (simulating the key round-tripping through the caller's session
/// store) signs the PAR request and the token exchange with the same key.
#[tokio::test]
async fn session_key_signs_par_and_token() {
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

    let http = RecordingHttp::default();
    let grant = session_keyed_par_grant(http.clone()).await;
    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();

    let output = grant
        .with_session_dpop_key(key.clone())
        .unwrap()
        .start(StartInput::scope(bon::vec!["api"]))
        .await
        .unwrap();

    let completed = grant
        .with_session_dpop_key(key)
        .unwrap()
        .complete(
            &output.pending_state,
            CompleteInput::builder()
                .code("the-code")
                .state(output.pending_state.state.clone())
                .build(),
        )
        .await
        .unwrap();

    assert!(matches!(
        completed.token_response.access_token(),
        AccessToken::DPoP(_)
    ));

    let seen = http.seen.lock().unwrap();
    assert!(
        seen.iter().any(|(p, dpop)| p.ends_with("/par") && *dpop),
        "PAR request should carry a DPoP proof: {seen:?}"
    );
    assert!(
        seen.iter().any(|(p, dpop)| p.ends_with("/token") && *dpop),
        "token request should carry a DPoP proof: {seen:?}"
    );
}

/// A different key bound at completion than the one bound at PAR time is
/// rejected before the token request goes out.
#[tokio::test]
async fn mismatched_session_key_at_complete_is_rejected() {
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

    let http = RecordingHttp::default();
    let grant = session_keyed_par_grant(http.clone()).await;

    let output = grant
        .with_session_dpop_key(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
        .unwrap()
        .start(StartInput::scope(bon::vec!["api"]))
        .await
        .unwrap();

    let result = grant
        .with_session_dpop_key(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
        .unwrap()
        .complete(
            &output.pending_state,
            CompleteInput::builder()
                .code("the-code")
                .state(output.pending_state.state.clone())
                .build(),
        )
        .await;

    let _err = result.expect_err("mismatched DPoP key must be rejected");
    let seen = http.seen.lock().unwrap();
    assert!(
        !seen.iter().any(|(p, _)| p.ends_with("/token")),
        "no token request should be made on mismatch: {seen:?}"
    );
}

/// Serves one canned token-endpoint response.
struct TokenHttp {
    body: &'static str,
}

impl HttpClient for TokenHttp {
    fn execute(
        &self,
        _request: http::Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        let body = Bytes::from_static(self.body.as_bytes());
        Box::pin(async move {
            Ok(HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body,
            })
        })
    }
}

async fn completing_grant(oidc: Option<bool>, body: &'static str) -> Grant {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(TokenHttp { body })
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .maybe_oidc(oidc)
        .issuer("https://as.example.com")
        .jws_verifier_factory(StubVerifierFactory)
        .build()
        .await
        .unwrap()
}

fn pending(openid_requested: bool) -> PendingState {
    PendingState {
        redirect_uri: "http://127.0.0.1/cb".to_string(),
        pkce_verifier: None,
        state: "st".to_string(),
        nonce: None,
        dpop_jkt: None,
        openid_requested,
        response_mode: None,
    }
}

fn complete_input() -> CompleteInput {
    CompleteInput::builder().code("code").state("st").build()
}

/// OIDC Core 1.0 §3.1.3.3: an `openid` grant's token response must carry
/// an ID token — unless the server narrowed `openid` out of the granted
/// scope (RFC 6749 §3.3), or the grant opted out of OIDC semantics.
/// `oidc(true)` skips the narrowing excuse.
#[rstest::rstest]
#[case::openid_no_scope_echoed(None, true, r#"{"access_token":"t","token_type":"bearer"}"#, true)]
#[case::openid_scope_echoed(
    None,
    true,
    r#"{"access_token":"t","token_type":"bearer","scope":"openid profile"}"#,
    true
)]
#[case::openid_narrowed_away(
    None,
    true,
    r#"{"access_token":"t","token_type":"bearer","scope":"profile"}"#,
    false
)]
#[case::not_an_oidc_flow(None, false, r#"{"access_token":"t","token_type":"bearer"}"#, false)]
#[case::forced_oidc_ignores_narrowing(
    Some(true),
    false,
    r#"{"access_token":"t","token_type":"bearer","scope":"profile"}"#,
    true
)]
#[case::forced_non_oidc(
    Some(false),
    true,
    r#"{"access_token":"t","token_type":"bearer"}"#,
    false
)]
#[tokio::test]
async fn missing_id_token_enforcement(
    #[case] oidc: Option<bool>,
    #[case] openid_requested: bool,
    #[case] body: &'static str,
    #[case] expect_error: bool,
) {
    let grant = completing_grant(oidc, body).await;

    let result = grant
        .complete(&pending(openid_requested), complete_input())
        .await;

    if expect_error {
        let err = result.expect_err("missing ID token must be rejected");
        assert!(
            matches!(complete_cause(&err), CompleteError::MissingIdToken),
            "got {err:?}"
        );
    } else {
        let output = result.expect("completion must succeed");
        assert!(output.id_token.is_none());
    }
}

/// A state-matched OAuth error response surfaces from completion carrying
/// the server's code and description.
#[tokio::test]
async fn error_payload_surfaces_from_complete() {
    let grant = completing_grant(None, r#"{"access_token":"t","token_type":"bearer"}"#).await;

    let input: CompleteInput = "error=access_denied&error_description=user+denied\
                                &error_uri=https%3A%2F%2Fas.example.com%2Fdoc&state=st"
        .parse()
        .unwrap();
    let err = grant
        .complete(&pending(false), input)
        .await
        .expect_err("an error payload must not complete");
    // The server judged the request and said no; it did not misbehave.
    assert_eq!(
        err.verdict().map(|v| v.code().as_str()),
        Some("access_denied")
    );
    assert_eq!(
        err.verdict()
            .and_then(huskarl_core::OAuthError::description),
        Some("user denied")
    );

    // The typed cause retains endpoint-specific context.
    let source: &CompleteError = err.cause().downcast_ref().expect("carries a CompleteError");
    assert!(
        matches!(source, CompleteError::OAuthError { verdict }
            if verdict.uri() == Some("https://as.example.com/doc")),
        "got {source:?}"
    );
}

/// An error response that is not bound to the pending state is CSRF, not a
/// denied login: it is rejected before the OAuth code is reported.
#[rstest]
#[case::mismatched_state("error=access_denied&state=other")]
#[case::absent_state("error=access_denied")]
#[tokio::test]
async fn unsolicited_error_payload_is_rejected_as_state_mismatch(#[case] callback: &str) {
    let grant = completing_grant(None, r#"{"access_token":"t","token_type":"bearer"}"#).await;

    let err = grant
        .complete(&pending(false), callback.parse().unwrap())
        .await
        .expect_err("an unbound error payload must not complete");
    assert_eq!(
        err.verdict().map(|v| v.code().as_str()),
        None,
        "got {err:?}"
    );
    assert!(
        matches!(
            err.cause().downcast_ref(),
            Some(CompleteError::StateMismatch)
        ),
        "got {err:?}"
    );
}

/// A completing grant with a real ES256 verifier wired for JARM, plus the
/// signer minting its response JWTs.
async fn jarm_grant(
    body: &'static str,
) -> (Grant, huskarl_crypto_native::asymmetric::signer::PrivateKey) {
    use huskarl_crypto_native::{
        NativeVerifierPlatform,
        asymmetric::signer::{GenerateAlgorithm, PrivateKey},
    };

    use crate::core::crypto::verifier::JwsVerifierPlatform as _;

    let signer = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let verifier = NativeVerifierPlatform
        .create_verifier_from_jwk(signer.as_private_jwk().public_jwk())
        .await
        .unwrap();

    let mut grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(TokenHttp { body })
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();
    grant.jws_verifier = Some(verifier);
    grant.issuer = Some("https://as.example.com".to_string());
    (grant, signer)
}

/// Signs a JARM response JWT with the given `iss`/`aud` and claim body.
async fn mint_jarm(
    signer: &huskarl_crypto_native::asymmetric::signer::PrivateKey,
    iss: &str,
    aud: &str,
    claims: serde_json::Value,
) -> String {
    use crate::core::crypto::signer::JwsSignerSelector as _;

    crate::core::jwt::Jwt::builder()
        .iss(iss.to_string())
        .aud(vec![aud.to_string()])
        .issued_now_expires_after(Duration::from_mins(5))
        .claims(claims)
        .build()
        .to_jws_compact(&*signer.select_signer().await)
        .await
        .unwrap()
        .expose_secret()
        .to_string()
}

fn pending_jarm() -> PendingState {
    PendingState {
        response_mode: Some(ResponseMode::QueryJwt),
        ..pending(false)
    }
}

#[tokio::test]
async fn jarm_response_completes() {
    let (grant, signer) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;
    let jarm = mint_jarm(
        &signer,
        "https://as.example.com",
        "client",
        serde_json::json!({"code": "the-code", "state": "st"}),
    )
    .await;

    let input: CompleteInput = format!("response={jarm}").parse().unwrap();
    grant
        .complete(&pending_jarm(), input)
        .await
        .expect("a valid JARM response must complete");
}

/// A JARM error response is verified and state-checked before the OAuth
/// error surfaces — the fold makes it bind to the flow like any callback.
#[tokio::test]
async fn jarm_error_response_surfaces_oauth_error() {
    let (grant, signer) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;
    let jarm = mint_jarm(
        &signer,
        "https://as.example.com",
        "client",
        serde_json::json!({"error": "access_denied", "error_description": "user denied", "state": "st"}),
    )
    .await;

    let input: CompleteInput = format!("response={jarm}").parse().unwrap();
    let err = grant
        .complete(&pending_jarm(), input)
        .await
        .expect_err("a JARM error response must not complete");
    assert_eq!(
        err.verdict().map(|v| v.code().as_str()),
        Some("access_denied")
    );
}

/// The state check runs on the folded JARM parameters.
#[tokio::test]
async fn jarm_state_mismatch_rejected() {
    let (grant, signer) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;
    let jarm = mint_jarm(
        &signer,
        "https://as.example.com",
        "client",
        serde_json::json!({"code": "the-code", "state": "not-st"}),
    )
    .await;

    let input: CompleteInput = format!("response={jarm}").parse().unwrap();
    let err = grant
        .complete(&pending_jarm(), input)
        .await
        .expect_err("a JARM state mismatch must be rejected");
    assert!(
        matches!(complete_cause(&err), CompleteError::StateMismatch),
        "got {err:?}"
    );
}

/// The state check binds a JARM error to the flow too: one that omits
/// `state` is rejected before its OAuth error is reported.
#[tokio::test]
async fn jarm_error_without_state_rejected() {
    let (grant, signer) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;
    let jarm = mint_jarm(
        &signer,
        "https://as.example.com",
        "client",
        serde_json::json!({"error": "access_denied"}),
    )
    .await;

    let input: CompleteInput = format!("response={jarm}").parse().unwrap();
    let err = grant
        .complete(&pending_jarm(), input)
        .await
        .expect_err("a JARM error without state must be rejected");
    assert_eq!(
        err.verdict().map(|v| v.code().as_str()),
        None,
        "got {err:?}"
    );
    assert!(
        matches!(complete_cause(&err), CompleteError::StateMismatch),
        "got {err:?}"
    );
}

/// Requesting JARM and receiving plain parameters — including a forged
/// unsigned error — is a downgrade and must be rejected before any other
/// handling.
#[rstest::rstest]
#[case::plain_success("code=abc&state=st")]
#[case::forged_plain_error("error=access_denied")]
#[tokio::test]
async fn plain_callback_when_jarm_expected_rejected(#[case] callback: &str) {
    let (grant, _) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;

    let err = grant
        .complete(&pending_jarm(), callback.parse().unwrap())
        .await
        .expect_err("plain parameters must not satisfy a JARM flow");
    assert!(
        matches!(complete_cause(&err), CompleteError::MissingJarmResponse),
        "got {err:?}"
    );
}

#[tokio::test]
async fn unrequested_jarm_response_rejected() {
    let (grant, signer) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;
    let jarm = mint_jarm(
        &signer,
        "https://as.example.com",
        "client",
        serde_json::json!({"code": "the-code", "state": "st"}),
    )
    .await;

    let input: CompleteInput = format!("response={jarm}").parse().unwrap();
    let err = grant
        .complete(&pending(false), input)
        .await
        .expect_err("an unrequested JARM response must be rejected");
    assert!(
        matches!(complete_cause(&err), CompleteError::UnexpectedJarmResponse),
        "got {err:?}"
    );
}

/// `aud` must be this client (JARM §2.4) — the mix-up defense.
#[tokio::test]
async fn jarm_wrong_audience_rejected() {
    let (grant, signer) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;
    let jarm = mint_jarm(
        &signer,
        "https://as.example.com",
        "other-client",
        serde_json::json!({"code": "the-code", "state": "st"}),
    )
    .await;

    let input: CompleteInput = format!("response={jarm}").parse().unwrap();
    let err = grant
        .complete(&pending_jarm(), input)
        .await
        .expect_err("a JARM response for another client must be rejected");
    assert!(
        matches!(complete_cause(&err), CompleteError::JarmValidation { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn jarm_alg_outside_allowlist_rejected() {
    let (mut grant, signer) = jarm_grant(r#"{"access_token":"t","token_type":"bearer"}"#).await;
    grant.allowed_authorization_signed_response_algs =
        Some(["PS256".to_string()].into_iter().collect());
    let jarm = mint_jarm(
        &signer,
        "https://as.example.com",
        "client",
        serde_json::json!({"code": "the-code", "state": "st"}),
    )
    .await;

    let input: CompleteInput = format!("response={jarm}").parse().unwrap();
    let err = grant
        .complete(&pending_jarm(), input)
        .await
        .expect_err("an ES256 JARM response must be rejected by a PS256 allowlist");
    assert!(
        matches!(complete_cause(&err), CompleteError::JarmValidation { .. }),
        "got {err:?}"
    );
}
