use std::sync::Arc;

use huskarl::{
    core::{
        EndpointUrl, Error, RetryAdvice,
        client_auth::NoAuth,
        crypto::verifier::{
            JwsVerifier, JwsVerifierFactory, JwsVerifierPlatform, MultiKeyVerifier,
        },
        platform::MaybeSendBoxFuture,
    },
    userinfo::UserInfoClient,
};
use huskarl_crypto_native::NativeVerifierPlatform;
use huskarl_resource_server::introspection::TokenIntrospection;

struct LocalFactory;

impl JwsVerifierFactory for LocalFactory {
    fn build(
        &self,
        _jwks_uri: Option<&EndpointUrl>,
        _platform: Arc<dyn JwsVerifierPlatform>,
    ) -> MaybeSendBoxFuture<'static, Result<Arc<dyn JwsVerifier>, Error>> {
        Box::pin(async { Ok(Arc::new(MultiKeyVerifier::new(vec![])) as Arc<dyn JwsVerifier>) })
    }
}

fn assert_missing_platform<T>(result: Result<T, Error>) {
    let Err(error) = result else {
        panic!("a factory without a platform must fail construction");
    };
    assert_eq!(error.retry_advice(), RetryAdvice::No);
    let message = error.cause().to_string();
    assert!(message.contains("no JWS verifier platform"), "{message}");
    assert!(
        message.contains("default-jws-verifier-platform"),
        "{message}"
    );
    assert!(message.contains(".jws_verifier_platform(...)"), "{message}");
}

#[tokio::test]
async fn userinfo_factory_requires_platform() {
    for with_uri in [false, true] {
        let result = UserInfoClient::builder()
            .userinfo_endpoint("https://issuer.example/userinfo".parse().unwrap())
            .issuer("https://issuer.example")
            .client_id("client")
            .maybe_jwks_uri(with_uri.then(|| "https://issuer.example/jwks".parse().unwrap()))
            .jws_verifier_factory(Arc::new(LocalFactory))
            .build()
            .await;
        assert_missing_platform(result);
    }
}

#[tokio::test]
async fn introspection_factory_requires_platform() {
    for with_uri in [false, true] {
        let result = TokenIntrospection::builder()
            .client_id("client")
            .client_auth(NoAuth)
            .introspection_endpoint("https://issuer.example/introspect".parse().unwrap())
            .maybe_jwks_uri(with_uri.then(|| "https://issuer.example/jwks".parse().unwrap()))
            .jws_verifier_factory(Arc::new(LocalFactory))
            .build()
            .await;
        assert_missing_platform(result);
    }
}

#[tokio::test]
async fn explicit_platform_enables_factories() {
    UserInfoClient::builder()
        .userinfo_endpoint("https://issuer.example/userinfo".parse().unwrap())
        .issuer("https://issuer.example")
        .client_id("client")
        .require_signed_response(true)
        .jws_verifier_factory(Arc::new(LocalFactory))
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .build()
        .await
        .unwrap();
    TokenIntrospection::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .introspection_endpoint("https://issuer.example/introspect".parse().unwrap())
        .jws_verifier_factory(Arc::new(LocalFactory))
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .build()
        .await
        .unwrap();
}

#[tokio::test]
async fn no_factory_needs_no_platform() {
    UserInfoClient::builder()
        .userinfo_endpoint("https://issuer.example/userinfo".parse().unwrap())
        .build()
        .await
        .unwrap();
    TokenIntrospection::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .introspection_endpoint("https://issuer.example/introspect".parse().unwrap())
        .build()
        .await
        .unwrap();
}

#[tokio::test]
async fn resolved_userinfo_verifier_takes_precedence_without_platform() {
    UserInfoClient::builder()
        .userinfo_endpoint("https://issuer.example/userinfo".parse().unwrap())
        .issuer("https://issuer.example")
        .client_id("client")
        .require_signed_response(true)
        .jws_verifier(MultiKeyVerifier::new(vec![]))
        .jws_verifier_factory(Arc::new(LocalFactory))
        .build()
        .await
        .unwrap();
}
