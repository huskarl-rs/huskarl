use super::*;

#[tokio::test]
async fn jwt_content_type_returns_not_supported() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/jwt"),
    );

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::from_static(b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    let source = userinfo_source(&err);
    assert!(matches!(source, UserInfoError::JwtResponseNotSupported));
    assert!(source.to_string().contains("application/jwt"));
}

#[tokio::test]
async fn jwt_content_type_with_charset_returns_not_supported() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/jwt; charset=utf-8"),
    );

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::from_static(b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::JwtResponseNotSupported
    ));
}

/// Build a compact JWS from header and claims JSON values.
///
/// Uses a dummy signature — pair with [`AcceptAllVerifier`] in tests.
fn build_test_jwt(header: &serde_json::Value, claims: &serde_json::Value) -> String {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    let h = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let c = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let s = BASE64_URL_SAFE_NO_PAD.encode(b"fake-signature");
    format!("{h}.{c}.{s}")
}

fn jwt_client() -> UserInfoClient {
    let validator = JwtValidator::builder()
        .verifier(AcceptAllVerifier)
        .iss(ClaimCheck::required_value("https://op.example.com"))
        .aud(ClaimCheck::required_value("my-client"))
        .build();
    UserInfoClient {
        userinfo_endpoint: "https://op.example.com/userinfo"
            .parse::<EndpointUrl>()
            .unwrap(),
        mtls_userinfo_endpoint: None,
        dpop: Arc::new(NoDPoP),
        jwt_validator: Some(validator),
        require_signed_response: false,
    }
}

fn jwt_response(jwt: &str) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/jwt"),
    );
    HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::from(jwt.to_owned()),
    }
}

#[tokio::test]
async fn jwt_response_validated() {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({
            "sub": "user1",
            "iss": "https://op.example.com",
            "aud": "my-client",
            "name": "Jane Doe",
            "email": "jane@example.com"
        }),
    );

    let http = MockHttpClient::new(jwt_response(&jwt));
    let result = jwt_client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
    assert_eq!(result.profile.name.as_deref(), Some("Jane Doe"));
    assert_eq!(result.profile.email.as_deref(), Some("jane@example.com"));
}

#[tokio::test]
async fn jwt_response_without_validator_returns_not_supported() {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({"sub": "user1"}),
    );

    let http = MockHttpClient::new(jwt_response(&jwt));

    // `client()` has no jwt_validator configured.
    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::JwtResponseNotSupported
    ));
}

#[tokio::test]
async fn jwt_response_invalid_utf8() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/jwt"),
    );

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::from_static(b"\xff\xfe"),
    });

    let err = jwt_client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::MalformedJwtResponseBody { source: _ }
    ));
}

// --- require_signed_response ---

/// A client requiring signed responses rejects plain JSON rather than
/// taking its claims unverified.
#[tokio::test]
async fn require_signed_response_rejects_json() {
    let mut client = jwt_client();
    client.require_signed_response = true;

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from_static(b"{\"sub\":\"user1\",\"email\":\"jane@example.com\"}"),
    });

    let err = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .expect_err("an unsigned response must not satisfy a signed-response client");

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::UnsignedResponse
    ));
}

/// The rejection happens before deserialization, so a well-formed unsigned
/// body that would otherwise pass every later check still fails.
#[tokio::test]
async fn require_signed_response_rejects_json_before_sub_check() {
    let mut client = jwt_client();
    client.require_signed_response = true;

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from_static(b"not json at all"),
    });

    let err = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(
        matches!(userinfo_source(&err), UserInfoError::UnsignedResponse),
        "content type decides before the body is parsed, got {err:?}"
    );
}

/// The requirement does not disturb the signed path.
#[tokio::test]
async fn require_signed_response_accepts_jwt() {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({
            "sub": "user1",
            "iss": "https://op.example.com",
            "aud": "my-client"
        }),
    );

    let mut client = jwt_client();
    client.require_signed_response = true;

    let http = MockHttpClient::new(jwt_response(&jwt));
    let result = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
}

/// A non-JSON, non-JWT content type still reports the more specific error.
#[tokio::test]
async fn require_signed_response_keeps_content_type_error() {
    let mut client = jwt_client();
    client.require_signed_response = true;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html"),
    );
    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::from_static(b"<html/>"),
    });

    let err = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::UnexpectedContentType { .. }
    ));
}

/// Requiring signed responses with nothing to verify them would reject
/// every response, so the builder refuses it.
#[tokio::test]
async fn require_signed_response_without_validator_is_a_build_error() {
    let err = UserInfoClient::builder()
        .userinfo_endpoint("https://op.example.com/userinfo".parse().unwrap())
        .require_signed_response(true)
        .build()
        .await
        .expect_err("no validator means no acceptable response");

    assert!(
        err.cause()
            .downcast_ref::<UserInfoBuildError>()
            .is_some_and(|e| matches!(e, UserInfoBuildError::RequireSignedWithoutValidator)),
        "got {err:?}"
    );
}

/// Factory that always fails, to prove `jws_verifier` short-circuits it.
struct ExplodingFactory;

impl JwsVerifierFactory for ExplodingFactory {
    fn build(
        &self,
        _jwks_uri: Option<&EndpointUrl>,
        _platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        Box::pin(async { Err(Error::new(RetryAdvice::No, "factory must not be called")) })
    }
}

/// A supplied `jws_verifier` needs no `jwks_uri` and takes precedence over
/// a factory.
#[tokio::test]
async fn jws_verifier_takes_precedence_over_factory() {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({
            "sub": "user1",
            "iss": "https://op.example.com",
            "aud": "my-client"
        }),
    );

    let client = UserInfoClient::builder()
        .userinfo_endpoint("https://op.example.com/userinfo".parse().unwrap())
        .jws_verifier(AcceptAllVerifier)
        .jws_verifier_factory(Arc::new(ExplodingFactory))
        .issuer("https://op.example.com")
        .client_id("my-client")
        .require_signed_response(true)
        .build()
        .await
        .expect("the supplied verifier is used, so the factory never runs");

    let http = MockHttpClient::new(jwt_response(&jwt));
    let result = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
}

#[tokio::test]
async fn factory_without_jwks_uri_validates_signed_response() {
    let client = UserInfoClient::builder()
        .userinfo_endpoint("https://op.example.com/userinfo".parse().unwrap())
        .jws_verifier_factory(Arc::new(AcceptAllFactory))
        .issuer("https://op.example.com")
        .client_id("my-client")
        .require_signed_response(true)
        .build()
        .await
        .unwrap();
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({
            "sub": "user1", "iss": "https://op.example.com", "aud": "my-client"
        }),
    );
    let http = MockHttpClient::new(jwt_response(&jwt));
    assert_eq!(
        client
            .get(&http, &bearer_token("tok"), "user1")
            .await
            .unwrap()
            .sub,
        "user1"
    );
}

// --- builder_from_grant validator derivation ---

/// A grant's verifier reaches the built client, so a signed `UserInfo`
/// response validates instead of hard-erroring.
#[tokio::test]
async fn builder_from_grant_derives_jwt_validator() {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({
            "sub": "user1",
            "iss": "https://op.example.com",
            "aud": "my-client",
            "email": "jane@example.com"
        }),
    );

    let grant = code_grant(true).await;
    let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
        .expect("metadata carries a userinfo_endpoint")
        .build()
        .await
        .unwrap();

    let http = MockHttpClient::new(jwt_response(&jwt));
    let result = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
    assert_eq!(result.profile.email.as_deref(), Some("jane@example.com"));
}

/// The derived validator checks `aud` and `iss`, not just the signature —
/// otherwise it would accept any JWS the server's JWKS covers.
#[rstest::rstest]
#[case::wrong_audience("https://op.example.com", "other-client")]
#[case::wrong_issuer("https://evil.example.com", "my-client")]
#[tokio::test]
async fn builder_from_grant_validator_checks_claims(#[case] iss: &str, #[case] aud: &str) {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({"sub": "user1", "iss": iss, "aud": aud}),
    );

    let grant = code_grant(true).await;
    let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
        .unwrap()
        .build()
        .await
        .unwrap();

    let http = MockHttpClient::new(jwt_response(&jwt));
    let err = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .expect_err("a mismatched iss or aud must be rejected");

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::JwtValidation { .. }
    ));
}

/// A grant with no verifier cannot produce one: the JWT path stays closed
/// and reports the missing configuration rather than skipping validation.
#[tokio::test]
async fn builder_from_grant_without_verifier_rejects_jwt_response() {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({"sub": "user1", "iss": "https://op.example.com", "aud": "my-client"}),
    );

    let grant = code_grant(false).await;
    let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
        .unwrap()
        .build()
        .await
        .unwrap();

    let http = MockHttpClient::new(jwt_response(&jwt));
    let err = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .expect_err("no verifier means no validation is possible");

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::JwtResponseNotSupported
    ));
}

/// `require_signed_response` carries through `builder_from_grant`.
#[tokio::test]
async fn builder_from_grant_honors_require_signed_response() {
    let grant = code_grant(true).await;
    let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
        .unwrap()
        .require_signed_response(true)
        .build()
        .await
        .unwrap();

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from_static(b"{\"sub\":\"user1\"}"),
    });

    let err = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::UnsignedResponse
    ));
}

/// Requiring signed responses from a grant that has no verifier is the
/// same misconfiguration the builder rejects.
#[tokio::test]
async fn builder_from_grant_require_signed_without_verifier_errors() {
    let grant = code_grant(false).await;
    let _err = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
        .unwrap()
        .require_signed_response(true)
        .build()
        .await
        .expect_err("no derivable validator means no acceptable response");
}

#[tokio::test]
async fn jwt_response_sub_mismatch() {
    let jwt = build_test_jwt(
        &serde_json::json!({"alg": "RS256"}),
        &serde_json::json!({
            "sub": "wrong-user",
            "iss": "https://op.example.com",
            "aud": "my-client"
        }),
    );

    let http = MockHttpClient::new(jwt_response(&jwt));
    let err = jwt_client()
        .get(&http, &bearer_token("tok"), "expected-user")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::SubMismatch { .. }
    ));
}
