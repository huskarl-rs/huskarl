#![cfg(not(target_family = "wasm"))]

use std::sync::atomic::Ordering;

use base64::prelude::*;
use http::{HeaderMap, HeaderName, Method, Uri};
use huskarl_resource_server::{
    error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
    validator::{
        extract::TokenExtractError,
        metadata::{ProvideValidatorMetadata, ValidatorMetadata},
        multi_issuer::{MultiIssuerValidator, TryMapClaims},
        observe::{ObservedValidator, ValidationEvent},
        prefix_routing::{PrefixRoutingBuildError, PrefixRoutingError, PrefixRoutingValidator},
    },
};
use rstest::rstest;

mod support;
use support::*;

#[tokio::test]
async fn selects_only_the_matching_prefix_or_fallback() {
    let key = Stub::new("key");
    let calls = key.calls.clone();
    let router = PrefixRoutingValidator::builder()
        .prefix("hk_", "key", key)
        .prefix("sk_", "service", Stub::new("service"))
        .fallback("oauth", Stub::new("fallback"))
        .build()
        .unwrap();
    for (token, expected) in [
        ("hk_secret", "key"),
        ("sk_secret", "service"),
        ("HK_secret", "fallback"),
    ] {
        let result = validate(&router, &headers(&format!("Bearer {token}"))).await;
        assert_eq!(result.outcome.unwrap().unwrap().claims, expected);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[rstest]
#[case::empty("", "sk_")]
#[case::duplicate("hk_", "hk_")]
#[case::short_first("hk_", "hk_live_")]
#[case::long_first("hk_live_", "hk_")]
fn rejects_ambiguous_configuration(#[case] first: &str, #[case] second: &str) {
    let result = PrefixRoutingValidator::builder()
        .prefix(first, "first", Stub::new("first"))
        .prefix(second, "second", Stub::new("second"))
        .build();
    match (first, second) {
        ("", _) => assert!(matches!(result, Err(PrefixRoutingBuildError::EmptyPrefix))),
        (a, b) if a == b => assert!(matches!(
            result,
            Err(PrefixRoutingBuildError::DuplicatePrefix { .. })
        )),
        _ => assert!(matches!(
            result,
            Err(PrefixRoutingBuildError::OverlappingPrefixes { .. })
        )),
    }
}

#[tokio::test]
async fn rejects_bad_presentations_before_delegating() {
    let key = Stub::new("key");
    let calls = key.calls.clone();
    let fallback = Stub::new("fallback");
    let fallback_calls = fallback.calls.clone();
    let router = PrefixRoutingValidator::builder()
        .prefix("hk_", "key", key)
        .fallback("oauth", fallback)
        .build()
        .unwrap();
    assert!(matches!(
        validate(&router, &HeaderMap::new()).await.outcome,
        Ok(None)
    ));
    for value in ["Bearer", "ApiKey hk_secret", "ApiKey unmatched"] {
        assert!(validate(&router, &headers(value)).await.outcome.is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    let result = validate(&router, &headers("bEaReR hk_secret")).await;
    assert_eq!(result.outcome.unwrap().unwrap().claims, "key");
}

#[rstest]
#[case::rejected(false)]
#[case::missing(true)]
#[tokio::test]
async fn selected_failure_is_final(#[case] missing: bool) {
    let mut key = Stub::new("key");
    if missing {
        key.claims = None;
    } else {
        key.check = |_, _, _, _| Err(TokenExtractError::InvalidTokenHeaderFormat);
    }
    let fallback = Stub::new("fallback");
    let calls = fallback.calls.clone();
    let router = PrefixRoutingValidator::builder()
        .prefix("hk_", "keys", key)
        .fallback("oauth", fallback)
        .build()
        .unwrap();
    let result = validate(&router, &headers("Bearer hk_secret")).await;
    let error = result.outcome.unwrap_err();
    assert_eq!(error.branch_label(), Some("keys"));
    assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    if missing {
        assert!(matches!(
            error,
            PrefixRoutingError::MissingValidation { .. }
        ));
        assert_eq!(
            error.challenge().error.suggested_status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
    } else {
        assert_eq!(
            error.challenge(),
            TokenExtractError::InvalidTokenHeaderFormat.challenge()
        );
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .is::<TokenExtractError>()
        );
    }
}

#[tokio::test]
async fn forwards_the_original_request_and_validation_result() {
    let mut key = Stub::new("identity");
    key.check = |headers, method, uri, cert| {
        assert_eq!(headers["x-token"], "Bearer hk_secret");
        assert_eq!(headers["dpop"], "proof");
        assert_eq!(*method, Method::POST);
        assert_eq!(*uri, Uri::from_static("https://api.example/path?q=1"));
        assert_eq!(cert, Some(b"certificate".as_slice()));
        Ok(())
    };
    let router = PrefixRoutingValidator::builder()
        .token_header(HeaderName::from_static("x-token"))
        .prefix("hk_", "key", key)
        .build()
        .unwrap();
    let mut request = headers("Bearer unrelated");
    request.insert("x-token", "Bearer hk_secret".parse().unwrap());
    request.insert("dpop", "proof".parse().unwrap());
    let result = router
        .validate_request(
            &request,
            &Method::POST,
            &Uri::from_static("https://api.example/path?q=1"),
            Some(b"certificate"),
        )
        .await;
    let identity = result.outcome.unwrap().unwrap();
    assert_eq!(identity.claims, "identity");
    assert_eq!(identity.sub.as_deref(), Some("owner"));
    assert_eq!(identity.iss, None);
    assert_eq!(result.dpop_nonce.as_deref(), Some("nonce"));
}

#[tokio::test]
async fn unmatched_credentials_distinguish_scheme_from_token_errors() {
    let router = PrefixRoutingValidator::builder()
        .prefix("hk_", "key", Stub::new("key"))
        .build()
        .unwrap();
    for (scheme, code) in [
        ("Bearer", TokenErrorCode::InvalidToken),
        ("Basic", TokenErrorCode::InvalidRequest),
    ] {
        let error = validate(&router, &headers(&format!("{scheme} secret")))
            .await
            .outcome
            .unwrap_err();
        assert_eq!(error.challenge().error, TokenValidationError::Client(code));
        assert_eq!(error.branch_label(), None);
        assert!(!format!("{error:?} {error}").contains("secret"));
    }
}

#[test]
fn metadata_combines_prefix_and_fallback_capabilities() {
    let mut oauth = Stub::new("oauth");
    oauth.metadata = ValidatorMetadata::builder()
        .authorization_servers(vec!["issuer".into()])
        .dpop_bound_access_tokens_required(true)
        .dpop_signing_alg_values_supported(vec!["ES256".into()])
        .build();
    let router = PrefixRoutingValidator::builder()
        .prefix("hk_", "key", Stub::new("key"))
        .fallback("oauth", oauth)
        .build()
        .unwrap();
    let metadata = router.validator_metadata(Some("https://api"));
    assert_eq!(metadata.authorization_servers.unwrap(), ["issuer"]);
    assert_eq!(metadata.resource.as_deref(), Some("https://api"));
    assert_eq!(metadata.dpop_supported, Some(true));
    assert_eq!(metadata.dpop_bound_access_tokens_required, Some(false));
}

#[tokio::test]
async fn composed_fallback_preserves_scheme_and_failure_label() {
    let jwt = Stub::new("jwt");
    let issuer = MultiIssuerValidator::builder()
        .source("issuer", jwt)
        .build();
    let router = PrefixRoutingValidator::builder()
        .fallback("oauth", issuer)
        .build()
        .unwrap();
    let mapped = TryMapClaims::new(router, Ok::<_, TokenExtractError>);
    let observed = ObservedValidator::builder()
        .inner(mapped)
        .on_validate(|event: &ValidationEvent<'_>| {
            if event.error.is_some() {
                assert_eq!(event.branch_label, Some("oauth"));
            }
        })
        .build();
    // A valid JSON header need not have the conventional eyJ prefix.
    let token = format!(
        "{}.{}.signature",
        BASE64_URL_SAFE_NO_PAD.encode(" {\"alg\":\"RS256\"}"),
        BASE64_URL_SAFE_NO_PAD.encode(r#"{"iss":"issuer"}"#)
    );
    let result = validate(&observed, &headers(&format!("bearer {token}"))).await;
    assert_eq!(result.outcome.unwrap().unwrap().claims, "jwt");
    let error = validate(&observed, &headers("Bearer malformed"))
        .await
        .outcome
        .unwrap_err();
    assert_eq!(error.branch_label(), Some("oauth"));
}
