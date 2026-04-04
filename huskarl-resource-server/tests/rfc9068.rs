#![cfg(not(target_family = "wasm"))]

use std::sync::Arc;

use httpmock::prelude::*;
use huskarl_core::{
    IntoEndpointUrl,
    crypto::signer::AsymmetricJwsSigner,
    jwk::{JwksSource, PublicJwks},
    jwt::Jwt,
};
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::validator::{dpop_nonce::NoNonceCheck, rfc9068::Rfc9068Validator};

#[tokio::test]
async fn test_rfc9068_validator() {
    let server = MockServer::start();

    // 1. Generate key pair
    let private_key = PrivateKey::generate(GenerateAlgorithm::Es256);
    let public_jwk = private_key.public_key_jwk().into_owned();
    let jwks = PublicJwks {
        keys: vec![public_jwk],
    };

    // 2. Mock JWKS endpoint
    let jwks_mock = server.mock(|when, then| {
        when.method(GET).path("/jwks.json");
        then.status(200)
            .header("content-type", "application/jwk-set+json")
            .json_body_obj(&jwks);
    });

    let issuer = format!("http://{}", server.address());
    let jwks_uri = format!("{}/jwks.json", issuer).into_endpoint_url().unwrap();

    // 3. Create validator
    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .unwrap();

    let validator = Rfc9068Validator::builder()
        .issuer(issuer.clone())
        .audience("api://resource")
        .jwks_uri(jwks_uri)
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(http_client.clone())
                .build(),
        ))
        .dpop_nonce_checker(NoNonceCheck)
        .build()
        .await
        .unwrap();

    // 4. Create a valid RFC 9068 JWT
    // RFC 9068 §2.2 requires: iss, exp, aud, sub, iat, jti, client_id
    #[derive(serde::Serialize, Clone)]
    struct ExtraClaims {
        client_id: String,
    }

    let jwt = Jwt::builder()
        .typ("at+jwt")
        .issuer(issuer.clone())
        .audience("api://resource")
        .subject("user-123")
        .issued_now()
        .expiration(
            huskarl_core::platform::SystemTime::now() + std::time::Duration::from_secs(3600),
        )
        .jti(Some("token-456".to_string()))
        .extra_claims(ExtraClaims {
            client_id: "client-789".to_string(),
        })
        .build();

    let token = jwt.to_jws_compact(&private_key).await.unwrap();

    // 5. Validate request
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {}", token.expose_secret()).parse().unwrap(),
    );

    let result = validator
        .validate_request(
            &headers,
            &http::Method::GET,
            &"https://api.example.com/data".parse().unwrap(),
            None,
        )
        .await;

    let validated = result
        .outcome
        .expect("Token should be valid")
        .expect("Token should be present");
    assert_eq!(validated.issuer.as_deref().unwrap(), issuer);
    assert_eq!(validated.subject.as_deref().unwrap(), "user-123");
    assert_eq!(validated.audience, vec!["api://resource".to_string()]);
    assert_eq!(validated.claims.as_ref().unwrap().client_id, "client-789");

    jwks_mock.assert();
}
