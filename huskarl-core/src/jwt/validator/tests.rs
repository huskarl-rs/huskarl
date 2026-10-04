use rstest::rstest;

use super::{checks::normalize_typ, *};
use crate::{
    crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    time::{ManualTime, Timer},
};

fn test_time() -> ManualTime {
    ManualTime::new(jiff::Timestamp::new(2_000_000, 0).unwrap())
}

fn classification(error: &JwtValidationError) -> crate::error::propagation::Classification {
    match crate::error::propagation::Cause::origin(error) {
        crate::error::propagation::Origin::Propagates(source) => source.classification(),
        crate::error::propagation::Origin::Establishes(classification) => classification,
    }
}

#[test]
fn infrastructure_failures_preserve_their_complete_classification() {
    let verifier_source = crate::Error::propagate(
        crate::error::propagation::Classification::judged(
            crate::RetryAdvice::retry_after(crate::platform::Duration::from_secs(17)),
            crate::OAuthError::new("temporarily_unavailable"),
        ),
        "the verifier backend",
    );
    let expected = verifier_source.classification();
    let signature = JwtValidationError::Signature {
        source: VerifyError::Other {
            source: verifier_source,
        },
    };
    assert_eq!(classification(&signature), expected);

    let jti_source = crate::Error::new(crate::RetryAdvice::RETRY, "the JTI store");
    let expected = jti_source.classification();
    let jti = JwtValidationError::JtiCheck { source: jti_source };
    assert_eq!(classification(&jti), expected);
}

#[test]
fn an_invalid_signature_is_terminal_but_an_unavailable_keyset_is_not() {
    let invalid = JwtValidationError::Signature {
        source: VerifyError::SignatureMismatch,
    };
    assert_eq!(
        classification(&invalid).retry_advice(),
        crate::RetryAdvice::No,
    );
    let unavailable = JwtValidationError::Signature {
        source: VerifyError::KeysUnavailable,
    };
    assert_eq!(
        classification(&unavailable).retry_advice(),
        crate::RetryAdvice::RETRY,
    );
}

#[derive(Debug)]
struct MockVerifier;

impl JwsVerifier for MockVerifier {
    fn key_match(&self, _key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        Some(KeyMatchStrength::ByAlgorithm)
    }

    fn verify<'a>(
        &'a self,
        _input: &'a [u8],
        _signature: &'a [u8],
        _key: &'a KeyMatch<'a>,
    ) -> crate::platform::MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn test_validate_unit_claims_with_extra_fields() {
    // A JWT with standard claims + an extra field "foo"
    // Header: {"alg": "RS256", "typ": "JWT"}
    // Claims: {"iss": "joe", "foo": "bar"}
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJmb28iOiJiYXIifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .iss(ClaimCheck::required_value("joe"))
        .build();

    // This should succeed even though "foo": "bar" is present and C is ()
    let result = validator.validate::<()>(token).await;
    assert!(result.is_ok(), "Expected Ok, got {:?}", result.err());
}

#[tokio::test]
async fn test_validate_custom_claims_success() {
    #[derive(Debug, Clone, Deserialize, PartialEq)]
    struct MyClaims {
        foo: String,
    }

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJmb28iOiJiYXIifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .iss(ClaimCheck::required_value("joe"))
        .build();

    let result = validator.validate::<MyClaims>(token).await.unwrap();
    assert_eq!(
        result.claims,
        MyClaims {
            foo: "bar".to_string()
        }
    );
}

#[tokio::test]
async fn test_validate_custom_claims_failure() {
    #[derive(Debug, Clone, Deserialize, PartialEq)]
    struct MyClaims {
        missing: String,
    }

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJmb28iOiJiYXIifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .iss(ClaimCheck::required_value("joe"))
        .build();

    let result = validator.validate::<MyClaims>(token).await;
    assert!(matches!(
        result,
        Err(JwtValidationError::ExtraClaims { .. })
    ));
}

// Helper to create a ParsedJws with given header/claims
fn make_parsed_jws(
    header: serde_json::Value,
    claims: serde_json::Value,
) -> ParsedJws<(), serde_json::Value> {
    use crate::jwt::structure::{JwtClaims, JwtHeader};

    let header: JwtHeader<'static, ()> = serde_json::from_value(header).unwrap();
    let claims: JwtClaims<'static, serde_json::Value> = serde_json::from_value(claims).unwrap();

    ParsedJws {
        header,
        claims,
        signing_input: b"dummy.input".to_vec(),
        signature: vec![0x00],
    }
}

fn default_validator() -> JwtValidator {
    JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .build()
}

// --- Algorithm checks ---

#[tokio::test]
async fn reject_alg_none() {
    let parsed = make_parsed_jws(serde_json::json!({"alg": "none"}), serde_json::json!({}));
    let result = default_validator()
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(result, Err(JwtValidationError::UnsignedToken)));
}

#[tokio::test]
async fn reject_disallowed_algorithm() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .allowed_algorithms(["ES256".to_string()])
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::DisallowedAlgorithm { .. })
    ));
}

// --- Critical header ---

#[tokio::test]
async fn reject_unrecognized_crit() {
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256", "crit": ["unknown-ext"]}),
        serde_json::json!({}),
    );
    let result = default_validator()
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::UnrecognizedCriticalHeader { .. })
    ));
}

// --- Temporal checks ---

#[tokio::test]
async fn reject_expired_token() {
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"exp": 1}), // expired long ago
    );
    let result = default_validator()
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(result, Err(JwtValidationError::Expired { .. })));
}

#[tokio::test]
async fn reject_not_yet_valid() {
    let far_future = 2_000_000_u64 + 999_999;
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"nbf": far_future}),
    );
    let result = default_validator()
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::NotYetValid { .. })
    ));
}

#[tokio::test]
async fn reject_issued_in_future() {
    let far_future = 2_000_000_u64 + 999_999;
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"iat": far_future}),
    );
    let result = default_validator()
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::IssuedInFuture { .. })
    ));
}

#[tokio::test]
async fn clock_leeway_allows_slightly_expired() {
    let now = 2_000_000_u64;
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .clock_leeway(Duration::from_secs(10))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"exp": now - 5}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(result.is_ok());
}

// --- Required claims ---

#[tokio::test]
async fn require_exp_missing() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .require_exp(true)
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::RequiredClaimMissing { claim: "exp" })
    ));
}

#[tokio::test]
async fn require_iat_missing() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .require_iat(true)
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::RequiredClaimMissing { claim: "iat" })
    ));
}

#[tokio::test]
async fn require_jti_missing() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .require_jti(true)
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::RequiredClaimMissing { claim: "jti" })
    ));
}

// --- iss claim checks ---

// Both the single-value and any-of forms of the iss check report the same
// `ClaimMismatch` when the token's issuer isn't accepted.
#[rstest]
#[case::required_value(ClaimCheck::required_value("expected-issuer"), "wrong-issuer")]
#[case::require_any(ClaimCheck::require_any(["a", "b"]), "c")]
#[tokio::test]
async fn iss_mismatch_is_rejected(#[case] iss_check: ClaimCheck, #[case] actual_iss: &str) {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .iss(iss_check)
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({ "iss": actual_iss }),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::ClaimMismatch { claim: "iss", .. })
    ));
}

#[tokio::test]
async fn iss_present_missing() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .iss(ClaimCheck::present())
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::RequiredClaimMissing { claim: "iss" })
    ));
}

#[tokio::test]
async fn iss_if_present_mismatch() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .iss(ClaimCheck::if_present("expected"))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"iss": "wrong"}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::ClaimMismatch { claim: "iss", .. })
    ));
}

#[tokio::test]
async fn iss_if_present_absent_ok() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .iss(ClaimCheck::if_present("expected"))
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(result.is_ok());
}

// --- aud claim checks ---

#[tokio::test]
async fn aud_required_value_not_in_list() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .aud(ClaimCheck::required_value("expected-aud"))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"aud": "wrong-aud"}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::ClaimMismatch { claim: "aud", .. })
    ));
}

#[tokio::test]
async fn aud_empty_when_required() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .aud(ClaimCheck::present())
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::RequiredClaimMissing { claim: "aud" })
    ));
}

// --- typ claim checks ---

#[tokio::test]
async fn typ_if_present_any_absent_ok() {
    // Header: {"alg":"RS256"}; claims: {}. Signature accepted by MockVerifier.
    let token = "eyJhbGciOiJSUzI1NiJ9.e30.AA";
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .typ(ClaimCheck::if_present_any(["JWT", "dpop+id_token"]))
        .build();

    let result = validator.validate::<()>(token).await;
    assert!(result.is_ok(), "Expected Ok, got {:?}", result.err());
}

#[tokio::test]
async fn typ_required_value_mismatch() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .typ(ClaimCheck::required_value("at+jwt"))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256", "typ": "JWT"}),
        serde_json::json!({}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::InvalidTokenType { .. })
    ));
}

#[tokio::test]
async fn typ_application_prefix_normalization() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .typ(ClaimCheck::required_value("at+jwt"))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256", "typ": "application/at+jwt"}),
        serde_json::json!({}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn typ_case_insensitive() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .typ(ClaimCheck::required_value("AT+JWT"))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256", "typ": "at+jwt"}),
        serde_json::json!({}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(result.is_ok());
}

// --- max_token_age ---

#[tokio::test]
async fn max_token_age_old_token() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .max_token_age(Duration::from_mins(1))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"iat": 1}), // issued at epoch
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::TokenTooOld { .. })
    ));
}

#[tokio::test]
async fn max_token_age_missing_iat() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .max_token_age(Duration::from_mins(1))
        .build();
    let parsed = make_parsed_jws(serde_json::json!({"alg": "RS256"}), serde_json::json!({}));
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::RequiredClaimMissing { claim: "iat" })
    ));
}

/// An `iat` slightly in the future (AS clock ahead, within the configured
/// leeway) must not be rejected by the `max_token_age` check as `TokenTooOld`
/// before the leeway-aware `IssuedInFuture` check can run.
#[tokio::test]
async fn max_token_age_allows_future_iat_within_leeway() {
    let now = 2_000_000_u64;
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .max_token_age(Duration::from_mins(5))
        .clock_leeway(Duration::from_mins(1))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"iat": now + 2}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(result.is_ok(), "fresh token with 2s skew: {result:?}");
}

/// An `iat` beyond the leeway still fails — as `IssuedInFuture`, the check
/// that owns future timestamps, not as a bogus `TokenTooOld`.
#[tokio::test]
async fn max_token_age_far_future_iat_is_issued_in_future() {
    let now = 2_000_000_u64;
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .max_token_age(Duration::from_mins(5))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"iat": now + 999_999}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::IssuedInFuture { .. })
    ));
}

// --- Panic resistance on attacker-controlled input ---

#[test]
fn normalize_typ_non_char_boundary() {
    // 11 ASCII bytes followed by a two-byte UTF-8 char: byte 12 is not a
    // char boundary. Direct `&typ[..12]` indexing would panic here.
    let typ = "abcdefghijké-jwt";
    assert!(!typ.is_char_boundary(12));
    assert_eq!(normalize_typ(typ), typ);

    // Normal prefix stripping still works.
    assert_eq!(normalize_typ("application/at+jwt"), "at+jwt");
    assert_eq!(normalize_typ("APPLICATION/at+jwt"), "at+jwt");
    assert_eq!(normalize_typ("application/"), "application/");
    assert_eq!(normalize_typ("JWT"), "JWT");
}

#[tokio::test]
async fn overflowing_exp_is_a_parse_error_not_a_panic() {
    use base64::prelude::*;

    // exp = u64::MAX overflows SystemTime on every platform; the token must
    // fail structural parsing instead of panicking during validation.
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    let claims = BASE64_URL_SAFE_NO_PAD.encode(r#"{"exp":18446744073709551615}"#);
    let signature = BASE64_URL_SAFE_NO_PAD.encode([0x00]);
    let token = [header, claims, signature].join(".");

    let result = default_validator().validate::<()>(&token).await;
    assert!(matches!(result, Err(JwtValidationError::Parse { .. })));
}

#[tokio::test]
async fn max_representable_exp_with_leeway_does_not_panic() {
    // An `exp` at the edge of the representable SystemTime range used to
    // panic in `expiration + clock_leeway`. Skip on platforms where the
    // value is not representable (it then fails at deserialization instead).
    let secs = 9_223_372_036_854_775_807_u64;
    if SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .is_none()
    {
        return;
    }

    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .clock_leeway(Duration::from_secs(10))
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"exp": secs, "nbf": 0, "iat": 0}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(result.is_ok(), "far-future exp is valid: {result:?}");
}

// --- JTI uniqueness ordering ---

/// In-memory JTI store recording every `check_and_mark_seen` call.
#[derive(Debug, Default)]
struct InMemoryJtiChecker {
    seen: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl JtiUniquenessChecker for InMemoryJtiChecker {
    fn check_and_mark_seen(
        &self,
        jti: &str,
    ) -> crate::platform::MaybeSendBoxFuture<'_, Result<bool, crate::error::Error>> {
        let previously_seen = !self.seen.lock().unwrap().insert(jti.to_owned());
        Box::pin(async move { Ok(previously_seen) })
    }
}

#[tokio::test]
async fn temporally_invalid_token_does_not_burn_jti() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .token_jti_checker(InMemoryJtiChecker::default())
        .build();

    let now = 2_000_000_u64;

    // A token presented before its `nbf` is rejected, but its `jti` must
    // not be marked seen — the later legitimate presentation must succeed.
    let early = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"jti": "jti-1", "nbf": now + 999_999}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(early)
        .await;
    assert!(matches!(
        result,
        Err(JwtValidationError::NotYetValid { .. })
    ));

    // Likewise for an expired token.
    let expired = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"jti": "jti-2", "exp": 1}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(expired)
        .await;
    assert!(matches!(result, Err(JwtValidationError::Expired { .. })));

    // The legitimate presentations succeed.
    for jti in ["jti-1", "jti-2"] {
        let valid = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({"jti": jti, "nbf": now - 10, "exp": now + 3600}),
        );
        let result = validator
            .validate_parsed_jws::<serde_json::Value>(valid)
            .await;
        assert!(result.is_ok(), "{jti} should not be burned: {result:?}");
    }

    // Replay of a successfully validated token is still rejected.
    let replay = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"jti": "jti-1", "nbf": now - 10, "exp": now + 3600}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(replay)
        .await;
    assert!(matches!(result, Err(JwtValidationError::JtiNotUnique)));
}

// --- JTI too long ---

#[tokio::test]
async fn jti_too_long() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(test_time())
        .max_jti_len(5)
        .build();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"jti": "toolong"}),
    );
    let result = validator
        .validate_parsed_jws::<serde_json::Value>(parsed)
        .await;
    assert!(matches!(result, Err(JwtValidationError::JtiTooLong { .. })));
}

#[rstest]
#[case(None, true)]
#[case(Some("JWT"), true)]
#[case(Some("application/JWT"), true)]
#[case(Some("DPOP+ID_TOKEN"), true)]
#[case(Some("application/dpop+id_token"), true)]
#[case(Some("at+jwt"), false)]
#[case(Some("dpop+jwt"), false)]
#[case(Some(""), false)]
fn optional_type_allowlist(#[case] typ: Option<&str>, #[case] accepted: bool) {
    let check = ClaimCheck::if_present_any(["JWT", "dpop+id_token"]);
    assert_eq!(checks::check_typ(&check, typ).is_ok(), accepted);
}

#[rstest]
#[case(None, true)]
#[case(Some("first"), true)]
#[case(Some("second"), true)]
#[case(Some("FIRST"), false)]
#[case(Some("other"), false)]
fn optional_claim_allowlist(#[case] value: Option<&str>, #[case] accepted: bool) {
    let check = ClaimCheck::if_present_any(["first", "second"]);
    assert_eq!(
        checks::check_str_claim("iss", &check, value).is_ok(),
        accepted
    );
    let audiences: Vec<String> = value.into_iter().map(String::from).collect();
    assert_eq!(checks::check_aud(&check, &audiences).is_ok(), accepted);
}

#[test]
fn empty_optional_allowlist_accepts_only_absence() {
    let check = ClaimCheck::if_present_any(Vec::<String>::new());
    assert!(checks::check_typ(&check, None).is_ok());
    assert!(checks::check_typ(&check, Some("JWT")).is_err());
    assert!(checks::check_str_claim("iss", &check, None).is_ok());
    assert!(checks::check_str_claim("iss", &check, Some("issuer")).is_err());
    assert!(checks::check_aud(&check, &[]).is_ok());
    assert!(checks::check_aud(&check, &["audience".into()]).is_err());
}

#[rstest]
#[case("exp", 0)]
#[case("exp", 10)]
#[case("nbf", 0)]
#[case("nbf", 10)]
#[case("iat", 0)]
#[case("iat", 10)]
#[case("age", 0)]
#[case("age", 10)]
#[tokio::test]
async fn temporal_boundaries_use_injected_clock(
    #[case] claim: &str,
    #[case] leeway: u64,
    #[values(0)] nanos: u32,
) {
    let time = test_time();
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(Arc::new(time.clone()))
        .clock_leeway(Duration::from_secs(leeway))
        .maybe_max_token_age((claim == "age").then_some(Duration::from_secs(60)))
        .build();
    let boundary = match claim {
        "exp" => 1_000 + leeway,
        "age" => 1_060 + leeway,
        _ => 1_000 - leeway,
    };
    let boundary = jiff::Timestamp::UNIX_EPOCH
        .checked_add(Duration::new(boundary, nanos))
        .unwrap();
    let readings = [
        boundary.checked_sub(Duration::from_nanos(1)).unwrap(),
        boundary,
        boundary.checked_add(Duration::from_nanos(1)).unwrap(),
    ];
    for (index, reading) in readings.into_iter().enumerate() {
        time.set_wall_time(reading);
        let key = if claim == "age" { "iat" } else { claim };
        let parsed = make_parsed_jws(
            serde_json::json!({"alg": "RS256"}),
            serde_json::json!({key: 1_000.0 + f64::from(nanos) / 1_000_000_000.0}),
        );
        let result = validator.validate_parsed_jws(parsed).await;
        let valid = match claim {
            "exp" => index == 0,
            "age" => index <= 1,
            _ => index >= 1,
        };
        if valid {
            assert!(result.is_ok(), "{claim} at {reading:?}: {result:?}");
        } else {
            let error = result.unwrap_err();
            assert!(matches!(
                (claim, error),
                ("exp", JwtValidationError::Expired { .. })
                    | ("nbf", JwtValidationError::NotYetValid { .. })
                    | ("iat", JwtValidationError::IssuedInFuture { .. })
                    | ("age", JwtValidationError::TokenTooOld { .. })
            ));
        }
    }
}

#[tokio::test]
async fn wall_clock_steps_change_validation_independently_of_timer() {
    let time = test_time();
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(time.clone())
        .build();
    let token = {
        use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
        format!(
            "{}.{}.AA",
            BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
            BASE64_URL_SAFE_NO_PAD.encode(r#"{"nbf":1999990,"exp":2000010}"#)
        )
    };
    assert!(validator.validate::<()>(&token).await.is_ok());
    time.advance_monotonic(Duration::from_secs(10_000)).unwrap();
    assert!(validator.validate::<()>(&token).await.is_ok());
    let monotonic = Timer::now(&time);
    for (seconds, valid) in [
        (3_000_000, false),
        (2_000_000, true),
        (1_000_000, false),
        (2_000_000, true),
    ] {
        time.set_wall_time(jiff::Timestamp::new(seconds, 0).unwrap());
        assert_eq!(validator.validate::<()>(&token).await.is_ok(), valid);
        assert_eq!(Timer::now(&time), monotonic);
    }
    time.advance(Duration::from_secs(11)).unwrap();
    assert!(matches!(
        validator.validate::<()>(&token).await,
        Err(JwtValidationError::Expired { .. })
    ));
}

#[rstest::rstest]
#[case::minimum(jiff::Timestamp::MIN)]
#[case::maximum(jiff::Timestamp::MAX)]
#[tokio::test]
async fn extreme_clock_readings_are_clamped_in_validation_errors(
    #[case] timestamp: jiff::Timestamp,
) {
    let time = test_time();
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(time.clone())
        .build();
    time.set_wall_time(timestamp);
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"nbf": 1_999_990, "exp": 2_000_010}),
    );
    let error = validator.validate_parsed_jws(parsed).await.unwrap_err();
    let now = match error {
        JwtValidationError::Expired { now, .. } | JwtValidationError::NotYetValid { now, .. } => {
            now
        }
        other => panic!("unexpected error: {other:?}"),
    };
    assert_eq!(
        now,
        crate::time::system_time_from_timestamp_saturating(timestamp)
    );
}

#[tokio::test]
async fn explicit_snapshot_does_not_read_clock() {
    use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};

    #[derive(Debug)]
    struct UnreadClock;
    impl Clock for UnreadClock {
        fn now(&self) -> jiff::Timestamp {
            panic!("explicit validation must not read the clock")
        }
    }
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
        .clock(UnreadClock)
        .build();
    let now = jiff::Timestamp::new(2_000_000, 0).unwrap();
    let parsed = make_parsed_jws(
        serde_json::json!({"alg": "RS256"}),
        serde_json::json!({"nbf": 1_999_990, "exp": 2_000_010}),
    );
    assert!(
        validator
            .validate_parsed_jws_at::<serde_json::Value>(parsed, now)
            .await
            .is_ok()
    );
    let token = format!(
        "{}.{}.AA",
        BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        BASE64_URL_SAFE_NO_PAD.encode(r#"{"nbf":1999990,"exp":2000010}"#)
    );
    assert!(validator.validate_at::<()>(&token, now).await.is_ok());
    assert!(matches!(
        validator
            .validate_at::<()>(&token, now.checked_add(Duration::from_secs(11)).unwrap())
            .await,
        Err(JwtValidationError::Expired { .. })
    ));
}
