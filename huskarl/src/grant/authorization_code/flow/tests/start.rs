use super::*;

async fn start_url(grant: &Grant) -> String {
    grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap()
        .authorization_url
        .to_string()
}

#[tokio::test]
async fn direct_request_object_repeats_required_oidc_parameters() {
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let mut grant = Grant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .jar(key)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();
    make_oidc_capable(&mut grant);
    let output = grant
        .start(StartInput::scope(bon::vec!["openid", "profile"]))
        .await
        .unwrap();
    let query: std::collections::HashMap<String, String> =
        crate::core::oauth_form::from_str(output.authorization_url.query().unwrap()).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &BASE64_URL_SAFE_NO_PAD
            .decode(query["request"].split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    for (name, expected) in [
        ("client_id", "client"),
        ("response_type", "code"),
        ("scope", "openid profile"),
    ] {
        assert_eq!(query[name], expected);
        assert_eq!(claims[name], expected);
    }
    // Session parameters remain within the signed request object.
    assert!(!query.contains_key("nonce"));
    assert!(!query.contains_key("state"));
    assert!(claims["nonce"].is_string());
    assert!(claims["state"].is_string());
}

#[tokio::test]
async fn direct_request_object_omits_absent_scope() {
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let grant = Grant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .jar(key)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();
    let output = grant.start(StartInput::builder().build()).await.unwrap();
    let query: std::collections::HashMap<String, String> =
        crate::core::oauth_form::from_str(output.authorization_url.query().unwrap()).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &BASE64_URL_SAFE_NO_PAD
            .decode(query["request"].split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert!(!query.contains_key("scope"));
    assert!(claims.get("scope").is_none());
    for (name, expected) in [("client_id", "client"), ("response_type", "code")] {
        assert_eq!(query[name], expected);
        assert_eq!(claims[name], expected);
    }
}

/// Serves one canned PAR response, for exercising the PAR delivery path.
struct ParHttp;

impl HttpClient for ParHttp {
    fn execute(
        &self,
        _request: http::Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async {
            Ok(HttpResponse {
                status: http::StatusCode::CREATED,
                headers: http::HeaderMap::new(),
                body: Bytes::from_static(
                    br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#,
                ),
            })
        })
    }
}

/// Challenges the first PAR request for a `DPoP` nonce, then accepts a retry
/// only when its freshly generated proof carries that nonce.
#[derive(Clone, Default)]
struct NonceParHttp {
    attempts: Arc<AtomicUsize>,
}

impl HttpClient for NonceParHttp {
    fn execute(
        &self,
        request: http::Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        let proof = request
            .headers()
            .get("DPoP")
            .expect("PAR request should carry a DPoP proof")
            .to_str()
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(proof.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();

        let mut headers = http::HeaderMap::new();
        let (status, body) = if attempt == 0 {
            assert!(claims.get("nonce").is_none());
            headers.insert("DPoP-Nonce", "fresh-nonce".parse().unwrap());
            (
                http::StatusCode::BAD_REQUEST,
                Bytes::from_static(br#"{"error":"use_dpop_nonce"}"#),
            )
        } else {
            assert_eq!(claims["nonce"], "fresh-nonce");
            (
                http::StatusCode::CREATED,
                Bytes::from_static(
                    br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#,
                ),
            )
        };

        Box::pin(async move {
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// The unbound session-keyed template itself refuses to run a flow: PAR
/// proof signing fails until a session key is bound.
#[tokio::test]
async fn unbound_session_template_rejects_start() {
    let http = RecordingHttp::default();
    let grant = session_keyed_par_grant(http.clone()).await;

    let _err = grant
        .start(StartInput::scope(bon::vec!["api"]))
        .await
        .expect_err("unbound SessionKeyedDPoP must not sign a PAR request");
}

#[tokio::test]
async fn par_start_resolves_expiry_to_an_absolute_instant() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(ParHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .pushed_authorization_request_endpoint("https://as.example.com/par".parse().unwrap())
        .prefer_pushed_authorization_requests(true)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let before = SystemTime::now();
    let output = grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap();
    let expires_at = output.expires_at.expect("PAR delivery sets an expiry");

    // The RFC 9126 `expires_in` (90s) is anchored at receipt.
    let lower = before + Duration::from_secs(90);
    let upper = SystemTime::now() + Duration::from_secs(90);
    assert!(
        expires_at >= lower && expires_at <= upper,
        "expected within [{lower:?}, {upper:?}], got {expires_at:?}"
    );
}

#[tokio::test]
async fn par_retries_once_with_the_server_dpop_nonce() {
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};

    let http = NonceParHttp::default();
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(http.clone())
        .client_auth(NoAuth)
        .dpop(
            crate::core::dpop::DPoP::builder()
                .signer(PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap())
                .build(),
        )
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .pushed_authorization_request_endpoint("https://as.example.com/par".parse().unwrap())
        .prefer_pushed_authorization_requests(true)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap();

    assert_eq!(http.attempts.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn direct_start_has_no_expiry() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let output = grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap();
    assert_eq!(output.expires_at, None);
}

#[tokio::test]
async fn default_builder_uses_s256() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let url = start_url(&grant).await;
    assert!(url.contains("code_challenge_method=S256"), "{url}");
    assert!(url.contains("code_challenge="), "{url}");
}

/// The persisted nonce must track whether the parameter was actually
/// sent: completion skips the check when it wasn't, so an ID token
/// legitimately issued without a nonce claim validates.
#[tokio::test]
async fn nonce_persisted_only_when_sent() {
    let mut grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();
    make_oidc_capable(&mut grant);

    let openid = grant
        .start(StartInput::scope(bon::vec!["openid"]))
        .await
        .unwrap();
    assert!(
        openid.pending_state.nonce.is_some(),
        "openid scope sends the nonce, so it must be persisted"
    );
    assert!(
        openid.pending_state.openid_requested,
        "openid scope must be recorded for completion-side enforcement"
    );

    let plain = grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap();
    assert!(
        plain.pending_state.nonce.is_none(),
        "no openid scope: nonce not sent, so none persisted for completion"
    );
    assert!(!plain.pending_state.openid_requested);
}

/// `oidc(false)`: `openid` is an ordinary scope — no nonce, no verifier
/// needed at start; the pending state still records the raw scope fact.
#[tokio::test]
async fn oidc_false_treats_openid_as_ordinary_scope() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .oidc(false)
        .build()
        .await
        .unwrap();

    let output = grant
        .start(StartInput::scope(bon::vec!["openid"]))
        .await
        .unwrap();
    assert!(output.pending_state.nonce.is_none());
    assert!(output.pending_state.openid_requested);
}

/// `oidc(true)`: OIDC semantics without `openid` in the scope — the
/// nonce is sent and the pending state records the raw scope fact.
#[tokio::test]
async fn oidc_true_forces_oidc_semantics_on_plain_scope() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .oidc(true)
        .issuer("https://as.example.com")
        .jws_verifier_factory(StubVerifierFactory)
        .build()
        .await
        .unwrap();

    let output = grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap();
    assert!(output.pending_state.nonce.is_some());
    assert!(!output.pending_state.openid_requested);
}

/// An OIDC flow that could never validate its required ID token (OIDC
/// Core 1.0 §3.1.3.3) fails at start, before the user is redirected.
#[tokio::test]
async fn oidc_start_without_verifier_fails_fast() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let err = grant
        .start(StartInput::scope(bon::vec!["openid"]))
        .await
        .expect_err("openid scope without a JWS verifier must not start");
    assert!(
        matches!(start_cause(&err), StartError::OidcVerifierNotConfigured),
        "got {err:?}"
    );
}

/// Same fail-fast for a missing issuer once a verifier is present.
#[tokio::test]
async fn oidc_start_without_issuer_fails_fast() {
    let mut grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();
    grant.jws_verifier = Some(std::sync::Arc::new(StubVerifier));

    let err = grant
        .start(StartInput::scope(bon::vec!["openid"]))
        .await
        .expect_err("openid scope without an issuer must not start");
    assert!(
        matches!(start_cause(&err), StartError::OidcIssuerNotConfigured),
        "got {err:?}"
    );
}

#[tokio::test]
async fn authorization_details_carried_as_a_single_json_value() {
    use crate::core::AuthorizationDetail;

    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let start_input = StartInput::builder()
        .scope(bon::vec!["payments"])
        .authorization_details(vec![
            AuthorizationDetail::builder("payment_initiation")
                .with("actions", serde_json::json!(["initiate"]))
                .build(),
        ])
        .build();

    let url = grant
        .start(start_input)
        .await
        .unwrap()
        .authorization_url
        .to_string();

    // RFC 9396 §3: one `authorization_details` parameter carrying URL-encoded
    // JSON (`%5B%7B` is `[{`), not repeated keys like a scalar list.
    assert_eq!(url.matches("authorization_details=").count(), 1, "{url}");
    assert!(url.contains("authorization_details=%5B%7B"), "{url}");
}

#[test]
fn start_input_scope_is_optional() {
    // RFC 6749 §3.1.1 / RFC 9396 §3: a request may omit scope and carry only
    // authorization_details.
    let start_input = StartInput::builder()
        .authorization_details(vec![
            crate::core::AuthorizationDetail::builder("payment_initiation").build(),
        ])
        .build();
    assert!(start_input.scope.is_none());
    assert!(start_input.authorization_details.is_some());
}

#[tokio::test]
async fn metadata_without_code_challenge_methods_still_uses_s256() {
    // RFC 8414 makes `code_challenge_methods_supported` optional even for
    // servers that support PKCE; omission must not silently disable it.
    let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
        "issuer": "https://as.example.com",
        "authorization_endpoint": "https://as.example.com/authorize",
        "token_endpoint": "https://as.example.com/token",
        "response_types_supported": ["code"],
    }))
    .unwrap();

    let grant: Grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
        .unwrap()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let url = start_url(&grant).await;
    assert!(url.contains("code_challenge_method=S256"), "{url}");
}

#[tokio::test]
async fn plain_only_metadata_uses_plain() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .code_challenge_methods_supported(vec!["plain".to_string()])
        .build()
        .await
        .unwrap();

    let url = start_url(&grant).await;
    assert!(url.contains("code_challenge_method=plain"), "{url}");
}

#[tokio::test]
async fn oversized_authorization_url_errors_instead_of_panicking() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    // `http::Uri` caps the total URI length at u16::MAX; a large
    // `id_token_hint` (an entire JWT in a query parameter) must surface
    // as an error rather than a panic.
    let result = grant
        .start(
            StartInput::builder()
                .scope(bon::vec!["profile"])
                .id_token_hint(crate::token::IdToken::from("a".repeat(70 * 1024)))
                .build(),
        )
        .await;
    assert!(
        matches!(result, Err(ref err) if err.retry_advice() == RetryAdvice::No),
        "oversized authorization URL should fail with a Config error"
    );
}

/// The `response_mode` knob is sent on the authorization request under its
/// wire name and is persisted on the pending state.
#[rstest::rstest]
#[case::query(ResponseMode::Query, "query")]
#[case::form_post(ResponseMode::FormPost, "form_post")]
#[case::query_jwt(ResponseMode::QueryJwt, "query.jwt")]
#[case::form_post_jwt(ResponseMode::FormPostJwt, "form_post.jwt")]
#[case::jwt(ResponseMode::Jwt, "jwt")]
#[tokio::test]
async fn response_mode_sent_and_persisted(#[case] mode: ResponseMode, #[case] wire: &str) {
    // JWT-secured modes must be able to validate the response they ask
    // for, so those grants need a verifier and issuer to build at all.
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .response_mode(mode)
        .issuer("https://as.example.com")
        .jws_verifier_factory(StubVerifierFactory)
        .build()
        .await
        .unwrap();

    let output = grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap();
    let url = output.authorization_url.to_string();
    // Boundary-anchored so `query` does not falsely match `query.jwt`.
    let pair = format!("response_mode={wire}");
    assert!(
        url.contains(&format!("{pair}&")) || url.ends_with(&pair),
        "{url}"
    );
    assert_eq!(output.pending_state.response_mode, Some(mode));
}

#[tokio::test]
async fn response_mode_omitted_by_default() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .build()
        .await
        .unwrap();

    let output = grant
        .start(StartInput::scope(bon::vec!["profile"]))
        .await
        .unwrap();
    assert!(
        !output
            .authorization_url
            .to_string()
            .contains("response_mode"),
        "{}",
        output.authorization_url
    );
    assert_eq!(output.pending_state.response_mode, None);
}

#[tokio::test]
async fn disable_pkce_omits_challenge() {
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(NoHttp)
        .client_auth(NoAuth)
        .token_endpoint("https://as.example.com/token".parse().unwrap())
        .authorization_endpoint("https://as.example.com/authorize".parse().unwrap())
        .redirect_uri("http://127.0.0.1/cb")
        .disable_pkce(true)
        .build()
        .await
        .unwrap();

    let url = start_url(&grant).await;
    assert!(!url.contains("code_challenge"), "{url}");
}
