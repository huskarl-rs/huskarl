//! Separate executable keeps tracing capture independent of concurrent HTTP unit tests.
#![cfg(all(feature = "tracing", not(target_arch = "wasm32")))]
use bytes::Bytes;
use http::Request;
use huskarl_core::{
    RetryAdvice,
    http::{HttpClient, Idempotency},
};
use huskarl_reqwest::ReqwestClient;

#[path = "support/test_tracing.rs"]
mod test_tracing;

fn serve_once() -> String {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nprivate-response");
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn tracing_excludes_request_and_response_secrets() {
    let url = format!("{}private-path?token=private-query", serve_once());
    let (result, text) = crate::test_tracing::capture(
        async {
            let client = ReqwestClient::builder()
                .max_response_bytes(Some(2))
                .build()
                .await
                .unwrap();
            let request = Request::builder()
                .uri(url)
                .header("authorization", "Bearer private-header")
                .body(Bytes::from_static(b"private-body"))
                .unwrap();
            client.execute(request, Idempotency::Unknown).await
        },
        tracing::Level::DEBUG,
    )
    .await;
    assert_eq!(result.unwrap_err().retry_advice(), RetryAdvice::No);
    let rejection = text
        .lines()
        .find(|line| line.contains("response_too_large"))
        .unwrap_or_else(|| panic!("missing response-size rejection: {text}"));
    assert!(rejection.contains("huskarl.reqwest.execute:"), "{text}");
    assert!(text.contains("test_request"), "{text}");
    assert!(!text.contains("private-"), "{text}");
}
