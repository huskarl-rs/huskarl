//! HTTP client and response abstractions.
//!
//! This module defines traits that decouple the library from any specific HTTP
//! implementation. Users provide their own [`HttpClient`] (e.g. backed by
//! `reqwest`, `hyper`, or a WASM-compatible client) and the library operates
//! against these traits.

mod get;
#[cfg(feature = "metrics")]
mod metrics_client;

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};

use crate::platform::{MaybeSend, MaybeSendSync};

pub(crate) use get::{GetError, get};
#[cfg(feature = "metrics")]
pub use metrics_client::MetricsHttpClient;

/// Defines the common interface for HTTP requests.
pub trait HttpClient: MaybeSendSync {
    /// The associated response type returned by this HTTP client.
    type Response: HttpResponse<Error = Self::ResponseError>;
    /// The error type returned by the client for a failed request.
    type Error: crate::Error;
    /// The error type returned by the response.
    type ResponseError: crate::Error;

    /// Executes an HTTP request and returns an owned response.
    ///
    /// # Arguments
    ///
    /// * `request`: The `http::Request` to be executed. The body is provided as `bytes::Bytes`.
    ///
    /// # Returns
    ///
    /// A `Future` that resolves to a `Result` containing the `Self::Response` on success,
    /// or `Self::Error` on failure.
    fn execute(
        &self,
        request: Request<Bytes>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + MaybeSend;

    /// Indicates whether this client uses mTLS for authentication.
    ///
    /// If true, grants should prefer to use mTLS endpoint aliases
    /// (RFC 8705 §5) when making requests to the authorization server.
    fn uses_mtls(&self) -> bool {
        false
    }
}

/// Defines the common interface for HTTP responses.
pub trait HttpResponse: MaybeSendSync {
    /// The error type when getting the response body.
    type Error: crate::Error;

    /// Returns the HTTP status code of the response.
    fn status(&self) -> StatusCode;

    /// Returns an immutable reference to the response's HTTP headers.
    fn headers(&self) -> HeaderMap;

    /// Consumes the response and asynchronously returns its body as `bytes::Bytes`.
    ///
    /// # Returns
    ///
    /// A `Future` that resolves to a `Result` containing the response body on success,
    /// or an error if reading the body fails.
    fn body(self) -> impl Future<Output = Result<Bytes, Self::Error>> + MaybeSend;
}
