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

/// Whether a request is known to be safe to re-send.
///
/// Set by the call site, which knows the operation's semantics; consumed by
/// [`HttpClient`] implementations when classifying transport failures as
/// retryable. The distinction matters for failures where the request may
/// have reached the server (a timeout, an interrupted response): re-sending
/// is only safe when the operation is known not to be affected by a first
/// attempt the server may already have processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idempotency {
    /// The request is known to be idempotent: a re-send is not affected by
    /// whether the server processed an earlier attempt. Transports may mark
    /// transient failures retryable even when delivery of the first attempt
    /// is unknown.
    Idempotent,
    /// Not known to be idempotent. A first attempt may have consumed
    /// one-shot state (an authorization code, a rotated refresh token), so
    /// transports must mark a failure retryable only when the request
    /// provably never reached the server.
    Unknown,
}

/// Executes HTTP requests on behalf of the library, returning a fully-read response.
///
/// This trait is dyn-capable: implement it on your client type and the
/// library consumes it as `&dyn HttpClient` / `Arc<dyn HttpClient>`.
///
/// # Implementing
///
/// Write the method body as `Box::pin(async move { ... })`. Read the full
/// response body inside [`execute`](Self::execute), and classify both
/// request and body-read failures as
/// [`ErrorKind::Transport`](crate::error::ErrorKind::Transport). Mark a
/// failure `retryable` only when re-sending the request is known to be
/// safe: either the request provably never reached the server (a
/// connection-establishment failure), or the caller declared it
/// [`Idempotency::Idempotent`] and the failure is transient (a timeout, an
/// interrupted response). With [`Idempotency::Unknown`], the server may
/// have processed a first attempt that a re-send would replay, so only
/// never-delivered failures are retryable.
pub trait HttpClient: MaybeSendSync {
    /// Executes an HTTP request and returns the fully-read response.
    ///
    /// # Arguments
    ///
    /// * `request`: The `http::Request` to be executed. The body is provided as `bytes::Bytes`.
    /// * `idempotency`: Whether the request is known to be safe to re-send,
    ///   used to classify retryability of transport failures.
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
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
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request, idempotency)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

impl<T: HttpClient + ?Sized> HttpClient for Box<T> {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request, idempotency)
    }

    fn uses_mtls(&self) -> bool {
        (**self).uses_mtls()
    }
}

impl<T: HttpClient + ?Sized> HttpClient for Arc<T> {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).execute(request, idempotency)
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
            _idempotency: Idempotency,
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
