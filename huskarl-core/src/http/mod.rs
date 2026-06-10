//! HTTP client and response abstractions.
//!
//! This module defines the [`HttpClient`] trait, which decouples the library
//! from any specific HTTP implementation. Users provide their own client
//! (e.g. backed by `reqwest`, `hyper`, or a WASM-compatible client) and the
//! library operates against the trait, usually as `&dyn HttpClient` or
//! `Arc<dyn HttpClient>`.

mod get;
#[cfg(feature = "metrics")]
mod metrics_client;

use std::sync::Arc;

use bytes::Bytes;
pub(crate) use get::get;
use http::{HeaderMap, Request, StatusCode};
#[cfg(feature = "metrics")]
pub use metrics_client::MetricsHttpClient;

use crate::{
    error::Error,
    platform::{MaybeSendBoxFuture, MaybeSendSync},
};

/// A fully-read HTTP response.
///
/// All responses this library consumes are small JSON, JWKS, or metadata
/// documents, so [`HttpClient::execute`] reads the entire body before
/// returning — there is no streaming interface.
#[derive(Clone)]
pub struct HttpResponse {
    /// The HTTP status code of the response.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The full response body.
    pub body: Bytes,
}

/// The body may contain credentials (e.g. a token response), so only its
/// length is shown.
impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Defines the common interface for HTTP requests.
///
/// This trait is dyn-capable: implement it on your client type and the
/// library consumes it as `&dyn HttpClient` / `Arc<dyn HttpClient>`.
///
/// # Implementing
///
/// Write the method body as `Box::pin(async move { ... })`. Read the full
/// response body inside [`execute`](Self::execute), and classify both
/// request and body-read failures as
/// [`ErrorKind::Transport`](crate::error::ErrorKind::Transport), using
/// `retryable` to distinguish transient failures (timeouts, connection
/// resets) from permanent ones (TLS configuration).
pub trait HttpClient: MaybeSendSync {
    /// Executes an HTTP request and returns the fully-read response.
    ///
    /// # Arguments
    ///
    /// * `request`: The `http::Request` to be executed. The body is provided as `bytes::Bytes`.
    fn execute(
        &self,
        request: Request<Bytes>,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>>;

    /// Indicates whether this client uses mTLS for authentication.
    ///
    /// If true, grants should prefer to use mTLS endpoint aliases
    /// (RFC 8705 §5) when making requests to the authorization server.
    fn uses_mtls(&self) -> bool {
        false
    }
}

impl<T: HttpClient + ?Sized> HttpClient for &T {
    fn execute(
        &self,
        request: Request<Bytes>,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

impl<T: HttpClient + ?Sized> HttpClient for Box<T> {
    fn execute(
        &self,
        request: Request<Bytes>,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

impl<T: HttpClient + ?Sized> HttpClient for Arc<T> {
    fn execute(
        &self,
        request: Request<Bytes>,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    struct FakeClient {
        status: StatusCode,
        body: &'static str,
    }

    impl HttpClient for FakeClient {
        fn execute(
            &self,
            _request: Request<Bytes>,
        ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
            Box::pin(async move {
                Ok(HttpResponse {
                    status: self.status,
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(self.body.as_bytes()),
                })
            })
        }
    }

    #[derive(Debug, serde::Deserialize)]
    struct Doc {
        value: u32,
    }

    fn uri() -> http::Uri {
        http::Uri::from_static("https://example.com/doc")
    }

    #[tokio::test]
    async fn get_deserializes_through_dyn_client() {
        let client = FakeClient {
            status: StatusCode::OK,
            body: r#"{"value": 7}"#,
        };
        let dyn_client: &dyn HttpClient = &client;
        let doc: Doc = get(dyn_client, uri(), HeaderMap::new())
            .await
            .expect("get succeeds");
        assert_eq!(doc.value, 7);
    }

    #[tokio::test]
    async fn get_classifies_bad_status_as_protocol() {
        let client = FakeClient {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "",
        };
        let err = get::<Doc>(&client, uri(), HeaderMap::new())
            .await
            .expect_err("non-2xx fails");
        assert_eq!(err.kind(), ErrorKind::Protocol);
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn erased_clients_still_implement_the_trait() {
        fn takes_impl(_: &impl HttpClient) {}

        let arc: Arc<dyn HttpClient> = Arc::new(FakeClient {
            status: StatusCode::OK,
            body: r#"{"value": 1}"#,
        });
        // An already-erased client satisfies `impl HttpClient` bounds via the
        // blanket impls, and still dispatches correctly.
        takes_impl(&arc);
        let boxed: Box<dyn HttpClient> = Box::new(FakeClient {
            status: StatusCode::OK,
            body: r#"{"value": 2}"#,
        });
        takes_impl(&boxed);
        let doc: Doc = get(&arc, uri(), HeaderMap::new()).await.expect("get");
        assert_eq!(doc.value, 1);
    }
}
