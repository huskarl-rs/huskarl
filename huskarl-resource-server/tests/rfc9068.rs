#![cfg(not(target_family = "wasm"))]

use std::sync::Arc;

use httpmock::prelude::*;
use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
use huskarl_reqwest::ReqwestClient;
use huskarl_resource_server::{
    core::{
        EndpointUrl,
        crypto::signer::AsymmetricJwsSignerSelector,
        jwk::{JwksSource, PublicJwks},
        jwt::Jwt,
    },
    validator::rfc9068::Rfc9068Validator,
};

#[tokio::test]
async fn test_rfc9068_validator() {
    let server = MockServer::start();

    // 1. Generate key pair
    let private_key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let signer = private_key.select_asymmetric_signer().await;
    let public_jwk = signer.public_key_jwk().into_owned();
    let jwks = PublicJwks::new(vec![public_jwk]);

    // 2. Mock JWKS endpoint
    let jwks_mock = server.mock(|when, then| {
        when.method(GET).path("/jwks.json");
        then.status(200)
            .header("content-type", "application/jwk-set+json")
            .json_body_obj(&jwks);
    });

    let issuer = format!("http://{}", server.address());
    let jwks_uri = format!("{}/jwks.json", issuer)
        .parse::<EndpointUrl>()
        .unwrap();

    // 3. Create validator
    let http_client = ReqwestClient::builder().build().await.unwrap();

    let validator = Rfc9068Validator::builder()
        .issuer(issuer.clone())
        .audience("api://resource")
        .realm("api")
        .resource_metadata("https://api.example/.well-known/oauth-protected-resource")
        .jwks_uri(jwks_uri)
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(http_client.clone())
                .build(),
        ))
        .build()
        .await
        .unwrap();

    // The builder's realm and resource_metadata surface in the
    // challenge-shaping metadata; mTLS binding is not required, so support
    // is not asserted.
    let metadata = validator.validator_metadata(None);
    assert_eq!(metadata.realm.as_deref(), Some("api"));
    assert_eq!(
        metadata.resource_metadata.as_deref(),
        Some("https://api.example/.well-known/oauth-protected-resource")
    );
    assert_eq!(metadata.tls_client_certificate_bound_access_tokens, None);

    // 4. Create a valid RFC 9068 JWT
    // RFC 9068 §2.2 requires: iss, exp, aud, sub, iat, jti, client_id
    #[derive(serde::Serialize, Clone)]
    struct ExtraClaims {
        client_id: String,
    }

    let jwt = Jwt::builder()
        .typ("at+jwt")
        .iss(issuer.clone())
        .audience("api://resource")
        .sub("user-123")
        .issued_now()
        .exp(
            huskarl_resource_server::core::platform::SystemTime::now()
                + std::time::Duration::from_secs(3600),
        )
        .jti(Some("token-456".to_string()))
        .claims(ExtraClaims {
            client_id: "client-789".to_string(),
        })
        .build();

    let token = jwt.to_jws_compact(&*signer).await.unwrap();

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
    assert_eq!(validated.iss.as_deref().unwrap(), issuer);
    assert_eq!(validated.sub.as_deref().unwrap(), "user-123");
    assert_eq!(validated.aud, vec!["api://resource".to_string()]);
    assert_eq!(validated.claims.client_id, "client-789");

    jwks_mock.assert();
}
