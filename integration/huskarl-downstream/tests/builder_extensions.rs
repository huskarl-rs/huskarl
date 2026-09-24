use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use huskarl::{
    core::{
        EndpointUrl, Error,
        client_auth::NoAuth,
        crypto::verifier::{
            JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform, MultiKeyVerifier,
        },
        jwt::{JtiUniquenessChecker, validator::JwtValidator},
        platform::MaybeSendBoxFuture,
    },
    grant::authorization_code::AuthorizationCodeGrant,
    userinfo::UserInfoClient,
};
use huskarl_resource_server::{
    DefaultJwsVerifierPlatform,
    introspection::TokenIntrospection,
    validator::{
        custom::CustomValidator, dpop_proof::DPoPProofValidator,
        introspection::IntrospectionValidator, rfc9068::Rfc9068Validator,
    },
};

#[derive(Clone)]
struct Factory(Arc<AtomicUsize>);

impl JwsVerifierFactory for Factory {
    fn build(
        &self,
        uri: Option<&EndpointUrl>,
        _platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        assert!(uri.is_none());
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Arc::new(MultiKeyVerifier::new(vec![])) as Arc<dyn JwsVerifier>) })
    }
}

#[derive(Debug, Clone)]
struct Checker;

impl JtiUniquenessChecker for Checker {
    fn check_and_mark_seen(&self, _jti: &str) -> MaybeSendBoxFuture<'_, Result<bool, Error>> {
        Box::pin(async { Ok(false) })
    }
}

async fn exercise_builders(
    factory: impl JwsVerifierFactory + Clone + 'static,
    checker: impl JtiUniquenessChecker + Clone + 'static,
) {
    Rfc9068Validator::builder()
        .issuer("https://issuer.example")
        .audience("resource")
        .jws_verifier_factory(factory.clone())
        .token_jti_checker(checker.clone())
        .dpop_jti_checker(checker.clone())
        .build()
        .await
        .unwrap();
    CustomValidator::builder()
        .jws_verifier_factory(factory.clone())
        .token_jti_checker(checker.clone())
        .dpop_jti_checker(checker.clone())
        .build()
        .await
        .unwrap();
    UserInfoClient::builder()
        .userinfo_endpoint("https://issuer.example/userinfo".parse().unwrap())
        .issuer("https://issuer.example")
        .client_id("client")
        .jws_verifier_factory(factory.clone())
        .require_signed_response(true)
        .build()
        .await
        .unwrap();
    TokenIntrospection::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .introspection_endpoint("https://issuer.example/introspect".parse().unwrap())
        .jws_verifier_factory(factory.clone())
        .build()
        .await
        .unwrap();
    let _ = IntrospectionValidator::builder()
        .jws_verifier_factory(factory.clone())
        .dpop_jti_checker(checker.clone());
    let _ = AuthorizationCodeGrant::builder().jws_verifier_factory(factory);
    let _ = DPoPProofValidator::builder()
        .jws_verifier_platform(DefaultJwsVerifierPlatform::default().into())
        .jti_checker(checker.clone())
        .build();
    let _ = JwtValidator::builder()
        .verifier(MultiKeyVerifier::new(vec![]))
        .token_jti_checker(checker)
        .build();
}

#[tokio::test]
async fn concrete_shared_and_closure_extensions_work() {
    let calls = Arc::new(AtomicUsize::new(0));
    let factory = Factory(calls.clone());
    exercise_builders(factory.clone(), Checker).await;
    exercise_builders(Arc::new(factory.clone()), Arc::new(Checker)).await;
    let shared: Arc<dyn JwsVerifierFactory> = Arc::new(factory.clone());
    let checker: Arc<dyn JtiUniquenessChecker> = Arc::new(Checker);
    exercise_builders(shared, checker).await;
    let closure = move |uri: Option<&EndpointUrl>, platform: Arc<dyn JwsVerifierPlatform>| {
        factory.build(uri, platform)
    };
    exercise_builders(closure.clone(), Checker).await;
    exercise_builders(Arc::new(closure), Checker).await;
    assert_eq!(calls.load(Ordering::SeqCst), 20);
}

#[test]
fn optional_setters_keep_none_inference() {
    let _ = UserInfoClient::builder().maybe_jws_verifier_factory(None);
    let _ = TokenIntrospection::builder().maybe_jws_verifier_factory(None);
    let _ = IntrospectionValidator::builder()
        .maybe_jws_verifier_factory(None)
        .maybe_dpop_jti_checker(None);
    let _ = Rfc9068Validator::builder()
        .maybe_token_jti_checker(None)
        .maybe_dpop_jti_checker(None);
    let _ = Rfc9068Validator::builder().maybe_token_jti_checker(None);
    let _ = CustomValidator::builder()
        .maybe_token_jti_checker(None)
        .maybe_dpop_jti_checker(None);
    let _ = DPoPProofValidator::builder().maybe_jti_checker(None);
    let _ = JwtValidator::builder().maybe_token_jti_checker(None);
    let _ = UserInfoClient::builder()
        .maybe_jws_verifier_factory(Some(Arc::new(Factory(Arc::new(AtomicUsize::new(0))))));
}

#[test]
#[allow(deprecated)] // Keep checking source compatibility until the next breaking release.
fn deprecated_checker_aliases_remain_usable() {
    let checker: Arc<dyn JtiUniquenessChecker> = Arc::new(Checker);
    let _ = Rfc9068Validator::builder().jti_checker(Arc::clone(&checker));
    let _ = Rfc9068Validator::builder().maybe_jti_checker(Some(Arc::new(Checker)));
    let _ = Rfc9068Validator::builder().maybe_jti_checker(None);
    let _ = JwtValidator::builder().jti_checker(Checker);
    let _ = JwtValidator::builder().maybe_jti_checker(Some(Checker));
    let _ = JwtValidator::builder().maybe_jti_checker(Some(checker));
    let _ = JwtValidator::builder().maybe_jti_checker(None::<Checker>);
}
