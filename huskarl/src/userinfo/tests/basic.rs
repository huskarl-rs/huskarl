use super::*;

#[tokio::test]
async fn successful_response() {
    let body = serde_json::json!({
        "sub": "248289761001",
        "name": "Jane Doe",
        "given_name": "Jane",
        "family_name": "Doe",
        "email": "janedoe@example.com",
        "email_verified": true,
        "picture": "http://example.com/janedoe/me.jpg"
    });

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let result = client()
        .get(&http, &bearer_token("tok"), "248289761001")
        .await
        .unwrap();

    assert_eq!(result.sub, "248289761001");
    assert_eq!(result.profile.name.as_deref(), Some("Jane Doe"));
    assert_eq!(result.profile.given_name.as_deref(), Some("Jane"));
    assert_eq!(result.profile.family_name.as_deref(), Some("Doe"));
    assert_eq!(result.profile.email.as_deref(), Some("janedoe@example.com"));
    assert_eq!(result.profile.email_verified, Some(true));
    assert_eq!(
        result.profile.picture.as_deref(),
        Some("http://example.com/janedoe/me.jpg")
    );
}

#[tokio::test]
async fn sub_mismatch_returns_error() {
    let body = serde_json::json!({ "sub": "wrong-subject" });

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "expected-subject")
        .await
        .unwrap_err();

    let source = userinfo_source(&err);
    assert!(matches!(source, UserInfoError::SubMismatch { .. }));
    assert!(
        source
            .to_string()
            .contains("expected expected-subject, got wrong-subject")
    );
}

#[tokio::test]
async fn non_success_status_returns_bad_status() {
    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::FORBIDDEN,
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"access denied"),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "sub")
        .await
        .unwrap_err();

    assert!(
        matches!(userinfo_source(&err), UserInfoError::BadStatus { status, body, .. }
            if *status == StatusCode::FORBIDDEN && body.to_string() == "access denied"),
        "expected BadStatus with FORBIDDEN, got {err:?}"
    );
}

#[tokio::test]
async fn invalid_json_returns_deserialize_error() {
    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from_static(b"not json"),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "sub")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::Deserialize { .. }
    ));
}

#[tokio::test]
async fn missing_sub_returns_deserialize_error() {
    let body = serde_json::json!({ "name": "Jane Doe" });

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "sub")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::Deserialize { .. }
    ));
}

#[tokio::test]
async fn unknown_claims_land_in_extra() {
    let body = serde_json::json!({
        "sub": "user1",
        "custom_claim": "custom_value",
        "org_id": 42
    });

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let result = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
    assert!(result.profile.name.is_none());
    assert_eq!(result.extra["custom_claim"], "custom_value");
    assert_eq!(result.extra["org_id"], 42);
}

#[tokio::test]
async fn typed_extra_claims_on_demand() {
    #[derive(Debug, Clone, Deserialize)]
    struct MyClaims {
        org_id: u64,
        role: String,
    }

    let body = serde_json::json!({
        "sub": "user1",
        "org_id": 42,
        "role": "admin"
    });

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let result = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    // Callers wanting typed access deserialize out of the extras map.
    let claims: MyClaims =
        serde_json::from_value(serde_json::to_value(&result.extra).unwrap()).unwrap();

    assert_eq!(result.sub, "user1");
    assert_eq!(claims.org_id, 42);
    assert_eq!(claims.role, "admin");
}

#[tokio::test]
async fn address_claim_deserialized() {
    let body = serde_json::json!({
        "sub": "user1",
        "address": {
            "formatted": "123 Main St\nAnytown, CA 90210",
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "CA",
            "postal_code": "90210",
            "country": "US"
        }
    });

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let result = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    let addr = result.profile.address.unwrap();
    assert_eq!(addr.locality.as_deref(), Some("Anytown"));
    assert_eq!(addr.region.as_deref(), Some("CA"));
    assert_eq!(addr.postal_code.as_deref(), Some("90210"));
    assert_eq!(addr.country.as_deref(), Some("US"));
}

fn nonce_challenge_response() -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"DPoP error="use_dpop_nonce""#),
    );
    headers.insert("DPoP-Nonce", HeaderValue::from_static("fresh-nonce"));
    HttpResponse {
        status: StatusCode::UNAUTHORIZED,
        headers,
        body: Bytes::new(),
    }
}

#[tokio::test]
async fn nonce_challenge_retries_once() {
    let body = serde_json::json!({"sub": "user1"});
    let http = MockHttpClient::sequence(vec![
        nonce_challenge_response(),
        HttpResponse {
            status: StatusCode::OK,
            headers: json_headers(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
        },
    ]);

    let result = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
    assert_eq!(http.calls(), 2);
}

#[tokio::test]
async fn second_nonce_challenge_returns_the_error() {
    let http =
        MockHttpClient::sequence(vec![nonce_challenge_response(), nonce_challenge_response()]);

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::BadStatus { status, .. } if *status == StatusCode::UNAUTHORIZED
    ));
    assert_eq!(http.calls(), 2);
}

#[tokio::test]
async fn nonce_header_without_challenge_does_not_retry() {
    // A plain 401 rotating the nonce (RFC 9449 §8.1) rejected the token
    // itself; a fresh nonce cannot fix it, so no re-send.
    let mut headers = HeaderMap::new();
    headers.insert("DPoP-Nonce", HeaderValue::from_static("rotated"));
    let http = MockHttpClient::sequence(vec![HttpResponse {
        status: StatusCode::UNAUTHORIZED,
        headers,
        body: Bytes::new(),
    }]);

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::BadStatus { .. }
    ));
    assert_eq!(http.calls(), 1);
}

#[tokio::test]
async fn unexpected_content_type_returns_error() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html"),
    );

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::from_static(b"<html>not json</html>"),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    let source = userinfo_source(&err);
    assert!(matches!(
        source,
        UserInfoError::UnexpectedContentType { .. }
    ));
    assert!(source.to_string().contains("text/html"));
}

#[tokio::test]
async fn json_content_type_with_charset_succeeds() {
    let body = serde_json::json!({ "sub": "user1" });

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers,
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let result = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
}

#[tokio::test]
async fn all_optional_claims_absent() {
    let body = serde_json::json!({ "sub": "minimal" });

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from(serde_json::to_vec(&body).unwrap()),
    });

    let result = client()
        .get(&http, &bearer_token("tok"), "minimal")
        .await
        .unwrap();

    assert_eq!(result.sub, "minimal");
    assert!(result.profile.name.is_none());
    assert!(result.profile.email.is_none());
    assert!(result.profile.address.is_none());
    assert!(result.profile.updated_at.is_none());
}

#[tokio::test]
async fn missing_content_type_returns_error() {
    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"{\"sub\":\"user1\"}"),
    });

    let err = client()
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap_err();

    assert!(matches!(
        userinfo_source(&err),
        UserInfoError::MissingContentType
    ));
}

/// Absent `userinfo_endpoint` errors, and the message names the field.
#[tokio::test]
async fn builder_from_grant_without_userinfo_endpoint_names_the_field() {
    let metadata: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
        "issuer": "https://op.example.com",
        "authorization_endpoint": "https://op.example.com/authorize",
        "token_endpoint": "https://op.example.com/token",
        "response_types_supported": ["code"],
    }))
    .unwrap();

    let grant = code_grant(true).await;
    // `.err()`, not `unwrap_err()`: bon builders aren't `Debug`.
    let err = UserInfoClient::builder_from_grant(&grant, &metadata)
        .err()
        .expect("metadata carries no userinfo_endpoint");

    // The detail is a chain layer now, so the alternate form carries it.
    assert_eq!(
        format!("{err:#}"),
        "authorization server metadata has no 'userinfo_endpoint'"
    );
}

/// Plain JSON still works through `builder_from_grant` when a validator is derived.
#[tokio::test]
async fn builder_from_grant_still_accepts_json() {
    let grant = code_grant(true).await;
    let client = UserInfoClient::builder_from_grant(&grant, &userinfo_metadata())
        .unwrap()
        .build()
        .await
        .unwrap();

    let http = MockHttpClient::new(HttpResponse {
        status: StatusCode::OK,
        headers: json_headers(),
        body: Bytes::from_static(b"{\"sub\":\"user1\"}"),
    });

    let result = client
        .get(&http, &bearer_token("tok"), "user1")
        .await
        .unwrap();

    assert_eq!(result.sub, "user1");
}
