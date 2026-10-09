use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use huskarl_crypto_native::{
    NativeVerifierPlatform,
    asymmetric::signer::{GenerateAlgorithm, PrivateKey},
};
use rstest::rstest;
use serde_json::{Value, json};

use super::*;
use crate::core::{
    RetryAdvice,
    crypto::{
        signer::JwsSignerSelector,
        verifier::{JwsVerifierPlatform, KeyMatch},
    },
    platform::SystemTime,
};

// Test-only protocol: sign a JSON pair of the exact token and a consumer-issued
// challenge. Consume the challenge atomically after signature validation.
// This is deliberately not presented as a standardized presentation format.
struct ChallengeVerifier {
    used: Mutex<HashSet<String>>,
    calls: AtomicUsize,
}

struct Context {
    challenge: String,
    expires: SystemTime,
}

fn message(token: &IdToken, context: &Context) -> Vec<u8> {
    serde_json::to_vec(&(token.token(), &context.challenge)).unwrap()
}

impl IdTokenPresentationProofVerifier for ChallengeVerifier {
    type Proof = [u8];
    type Context = Context;

    async fn verify(&self, token: &IdToken, proof: &[u8], context: &Context) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let key = binding_key(token).map_err(|error| Error::new(RetryAdvice::No, error))?;
        if context.expires <= SystemTime::now() {
            return Err(Error::new(RetryAdvice::No, "expired challenge"));
        }
        let verifier = NativeVerifierPlatform
            .create_verifier_from_jwk(key)
            .await
            .map_err(|_| Error::new(RetryAdvice::No, "invalid key"))?;
        verifier
            .verify(
                &message(token, context),
                proof,
                &KeyMatch::builder().alg("ES256").build(),
            )
            .await
            .map_err(|_| Error::new(RetryAdvice::No, "invalid proof"))?;
        if !self.used.lock().unwrap().insert(context.challenge.clone()) {
            return Err(Error::new(RetryAdvice::No, "replayed challenge"));
        }
        Ok(())
    }
}

async fn setup() -> (
    PrivateKey,
    PrivateKey,
    IdTokenPresentationValidator<ChallengeVerifier>,
) {
    let issuer = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let holder = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let verifier = NativeVerifierPlatform
        .create_verifier_from_jwk(issuer.as_private_jwk().public_jwk())
        .await
        .unwrap();
    let validator = IdTokenPresentationValidator::builder()
        .verifier(verifier)
        .issuer("https://op.example")
        .audiences(["mobile".to_owned(), "desktop".to_owned()])
        .proof_verifier(ChallengeVerifier {
            used: Mutex::default(),
            calls: AtomicUsize::new(0),
        })
        .allowed_algorithms(["ES256".to_owned()])
        .build();
    (issuer, holder, validator)
}

fn payload(holder: &PrivateKey) -> Value {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({"iss": "https://op.example", "aud": "mobile", "sub": "user", "iat": now,
        "exp": now + 300, "nonce": "original-authentication-nonce", "name": "Alice",
        "cnf": {"jwk": holder.as_private_jwk().public_jwk()}})
}

async fn mint(issuer: &PrivateKey, typ: Option<&str>, payload: &Value) -> IdToken {
    let mut header = json!({"alg": "ES256"});
    if let Some(typ) = typ {
        header["typ"] = typ.into();
    }
    let input = format!(
        "{}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap())
    );
    let signature = issuer
        .select_signer()
        .await
        .sign(input.as_bytes())
        .await
        .unwrap();
    IdToken::from(format!(
        "{input}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn context() -> Context {
    Context {
        challenge: "consumer-challenge".into(),
        expires: SystemTime::now() + Duration::from_mins(1),
    }
}

async fn proof(holder: &PrivateKey, token: &IdToken, context: &Context) -> Vec<u8> {
    holder
        .select_signer()
        .await
        .sign(&message(token, context))
        .await
        .unwrap()
}

#[rstest]
#[case("dpop+id_token", "mobile")]
#[case("application/dpop+id_token", "desktop")]
#[tokio::test]
async fn verifies_identity_and_possession_then_rejects_replay(
    #[case] typ: &str,
    #[case] audience: &str,
) {
    let (issuer, holder, validator) = setup().await;
    let mut claims = payload(&holder);
    claims["aud"] = audience.into();
    let token = mint(&issuer, Some(typ), &claims).await;
    let context = context();
    let proof = proof(&holder, &token, &context).await;
    let result = validator.validate(&token, &proof, &context).await.unwrap();
    assert_eq!(result.claims().sub.as_deref(), Some("user"));
    assert_eq!(
        result.claims().claims.profile.name.as_deref(),
        Some("Alice")
    );
    assert!(matches!(
        validator.validate(&token, &proof, &context).await,
        Err(IdTokenPresentationError::Proof { .. })
    ));
}

#[rstest]
#[case("iss", json!("https://other.example"))]
#[case("aud", json!("other-rp"))]
#[case("aud", json!([]))]
#[case("sub", Value::Null)]
#[case("exp", Value::Null)]
#[case("exp", json!(1))]
#[case("iat", Value::Null)]
#[case("iat", json!(4_102_444_800_u64))]
#[case("nbf", json!(4_102_444_800_u64))]
#[tokio::test]
async fn rejects_invalid_identity_before_proof(#[case] field: &str, #[case] value: Value) {
    let (issuer, holder, validator) = setup().await;
    let mut claims = payload(&holder);
    claims[field] = value;
    let token = mint(&issuer, Some("dpop+id_token"), &claims).await;
    assert!(matches!(
        validator.validate(&token, &[], &context()).await,
        Err(IdTokenPresentationError::Token { .. })
    ));
    assert_eq!(validator.proof_verifier.calls.load(Ordering::SeqCst), 0);
}

#[rstest]
#[case(None)]
#[case(Some("JWT"))]
#[case(Some("at+jwt"))]
#[case(Some("dpop+jwt"))]
#[tokio::test]
async fn requires_bound_id_token_type(#[case] typ: Option<&str>) {
    let (issuer, holder, validator) = setup().await;
    let token = mint(&issuer, typ, &payload(&holder)).await;
    assert!(matches!(
        validator.validate(&token, &[], &context()).await,
        Err(IdTokenPresentationError::Token { .. })
    ));
    assert_eq!(validator.proof_verifier.calls.load(Ordering::SeqCst), 0);
}

#[rstest]
#[case("missing")]
#[case("jkt")]
#[case("symmetric")]
#[case("private")]
#[case("remote")]
#[case("ambiguous")]
#[case("malformed")]
#[tokio::test]
async fn verifier_propagates_binding_errors_without_touching_replay_state(#[case] kind: &str) {
    let (issuer, holder, validator) = setup().await;
    let mut claims = payload(&holder);
    match kind {
        "missing" => {
            claims.as_object_mut().unwrap().remove("cnf");
        }
        "jkt" => claims["cnf"] = json!({"jkt": "thumbprint"}),
        "symmetric" => claims["cnf"] = json!({"jwk": {"kty": "oct", "k": "secret"}}),
        "private" => claims["cnf"]["jwk"]["d"] = json!("private"),
        "remote" => claims["cnf"]["jwk"]["x5u"] = json!("https://untrusted.example"),
        "ambiguous" => claims["cnf"]["jkt"] = json!("another-key"),
        _ => {
            assert_eq!(kind, "malformed");
            claims["cnf"]["jwk"] = json!({"kty": "EC"});
        }
    }
    let token = mint(&issuer, Some("dpop+id_token"), &claims).await;
    let error = validator
        .validate(&token, &[], &context())
        .await
        .unwrap_err();
    let IdTokenPresentationError::Proof { source } = error else {
        panic!("expected binding extraction to fail in the proof verifier: {error:?}");
    };
    assert!(source.cause().is::<IdTokenPresentationError>());
    assert_eq!(validator.proof_verifier.calls.load(Ordering::SeqCst), 1);
    assert!(validator.proof_verifier.used.lock().unwrap().is_empty());
}

#[tokio::test]
async fn verifies_op_signature_and_algorithm_policy_before_proof() {
    let (issuer, holder, mut validator) = setup().await;
    let token = mint(&holder, Some("dpop+id_token"), &payload(&holder)).await;
    assert!(matches!(
        validator.validate(&token, &[], &context()).await,
        Err(IdTokenPresentationError::Token { .. })
    ));
    let token = mint(&issuer, Some("dpop+id_token"), &payload(&holder)).await;
    validator.allowed_algorithms = Some(HashSet::from(["RS256".into()]));
    assert!(matches!(
        validator.validate(&token, &[], &context()).await,
        Err(IdTokenPresentationError::Token { .. })
    ));
    assert_eq!(validator.proof_verifier.calls.load(Ordering::SeqCst), 0);
}

#[rstest]
#[case("wrong-key")]
#[case("token-substitution")]
#[case("wrong-context")]
#[case("expired-context")]
#[tokio::test]
async fn rejects_invalid_presentations(#[case] kind: &str) {
    let (issuer, holder, validator) = setup().await;
    let mut claims = payload(&holder);
    let mut token = mint(&issuer, Some("dpop+id_token"), &claims).await;
    let mut context = context();
    let proof = proof(
        if kind == "wrong-key" {
            &issuer
        } else {
            &holder
        },
        &token,
        &context,
    )
    .await;
    match kind {
        "token-substitution" => {
            claims["sub"] = json!("another-user");
            token = mint(&issuer, Some("dpop+id_token"), &claims).await;
        }
        "wrong-context" => context.challenge = "another-challenge".into(),
        "expired-context" => context.expires = SystemTime::UNIX_EPOCH,
        _ => {}
    }
    assert!(matches!(
        validator.validate(&token, &proof, &context).await,
        Err(IdTokenPresentationError::Proof { .. })
    ));
}

#[tokio::test]
async fn empty_audience_policy_accepts_nothing() {
    let (issuer, holder, mut validator) = setup().await;
    validator.audiences.clear();
    let token = mint(&issuer, Some("dpop+id_token"), &payload(&holder)).await;
    assert!(matches!(
        validator.validate(&token, &[], &context()).await,
        Err(IdTokenPresentationError::Token { .. })
    ));
    assert_eq!(validator.proof_verifier.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forwarding_preserves_shared_replay_state() {
    async fn verify_with<P: IdTokenPresentationProofVerifier<Proof = [u8], Context = Context>>(
        verifier: P,
        token: &IdToken,
        proof: &[u8],
        context: &Context,
    ) -> Result<(), Error> {
        verifier.verify(token, proof, context).await
    }

    let (issuer, holder, validator) = setup().await;
    let verifier = Arc::new(validator.proof_verifier);
    let token = mint(&issuer, Some("dpop+id_token"), &payload(&holder)).await;
    let context = context();
    let proof = proof(&holder, &token, &context).await;

    verify_with(&*verifier, &token, &proof, &context)
        .await
        .unwrap();
    for error in [
        verify_with(Box::new(Arc::clone(&verifier)), &token, &proof, &context)
            .await
            .unwrap_err(),
        verify_with(Arc::clone(&verifier), &token, &proof, &context)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(error.cause().to_string(), "replayed challenge");
    }
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 3);
}
