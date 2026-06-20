use rstest::rstest;

use super::{checks::normalize_typ, *};
use crate::crypto::{
    KeyMatchStrength,
    verifier::{JwsVerifier, KeyMatch, VerifyError},
};

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
    JwtValidator::builder().verifier(MockVerifier).build()
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
    let far_future = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 999_999;
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
    let far_future = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 999_999;
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
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
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
async fn typ_required_value_mismatch() {
    let validator = JwtValidator::builder()
        .verifier(MockVerifier)
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
        .jti_checker(InMemoryJtiChecker::default())
        .build();

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

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
