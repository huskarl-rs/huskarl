use huskarl_resource_server::validator::dpop_nonce::NoNonceCheck;

#[cfg(target_family = "wasm")]
fn main() {}

#[cfg(not(target_family = "wasm"))]
#[tokio::main]
pub async fn main() {
    use std::sync::Arc;

    use http::{HeaderValue, Method, header::AUTHORIZATION};
    use huskarl_reqwest::ReqwestClient;
    use huskarl_resource_server::core::{
        jwk::JwksSource, server_metadata::AuthorizationServerMetadata,
    };
    use huskarl_resource_server::validator::rfc9068::Rfc9068Validator;

    let http_client = ReqwestClient::builder()
        .mtls(huskarl_reqwest::mtls::NoMtls)
        .build()
        .await
        .unwrap();

    let authorization_server_metadata = AuthorizationServerMetadata::builder()
        .http_client(&http_client)
        .issuer("https://...")
        .build()
        .await
        .unwrap();

    let validator = Rfc9068Validator::builder_from_metadata(&authorization_server_metadata)
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(http_client.clone())
                .build(),
        ))
        .audience("api://client")
        .dpop_nonce_checker(NoNonceCheck)
        .build()
        .await
        .unwrap();

    let mut headers = http::HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer mF_9.B5f-4.1JqM"),
    );
    let http_method = Method::GET;
    let http_uri = http::Uri::from_static("https://example.com/resource");

    let result = validator
        .validate_request(&headers, &http_method, &http_uri, None)
        .await;

    println!("{result:?}")
}
