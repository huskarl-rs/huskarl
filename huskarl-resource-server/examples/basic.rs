#[cfg(target_family = "wasm")]
fn main() {}

#[cfg(not(target_family = "wasm"))]
#[tokio::main]
pub async fn main() {
    use std::sync::Arc;

    use http::{HeaderValue, Method, header::AUTHORIZATION};
    use huskarl_reqwest::ReqwestClient;
    use huskarl_resource_server::{
        core::{jwk::JwksSource, server_metadata::AuthorizationServerMetadata},
        validator::rfc9068::Rfc9068Validator,
    };

    let http_client = ReqwestClient::builder().build().await.unwrap();

    let authorization_server_metadata = AuthorizationServerMetadata::fetch()
        .http_client(&http_client)
        .issuer("https://...")
        .call()
        .await
        .unwrap();

    let validator = Rfc9068Validator::builder_from_metadata(&authorization_server_metadata)
        .jws_verifier_factory(Arc::new(
            JwksSource::builder()
                .http_client(http_client.clone())
                .build(),
        ))
        .audience("api://client")
        .build()
        .await
        .unwrap();

    let mut headers = http::HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer mF_9.B5f-4.1JqM"),
    );
    let http_method = Method::GET;

    // The URI must be the absolute external target URI the client addressed
    // (it is checked against the `htu` claim of any DPoP proof). A framework
    // request object carries only the origin-form path (`/resource`), and
    // behind a TLS-terminating or rewriting proxy only the deployment knows
    // the external URI — rebuild it from a configured public base URL (or
    // from forwarded headers you trust).
    let public_base = http::Uri::from_static("https://example.com");
    let request_path = "/resource"; // e.g. axum's `req.uri().path()`
    let http_uri = http::Uri::builder()
        .scheme(public_base.scheme_str().unwrap())
        .authority(public_base.authority().unwrap().as_str())
        .path_and_query(request_path)
        .build()
        .unwrap();

    let result = validator
        .validate_request(&headers, &http_method, &http_uri, None)
        .await;

    println!("{result:?}")
}
