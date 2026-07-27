//! An [`HttpClient`] for the huskarl crates, backed by [`reqwest`].
//!
//! [`ReqwestClient`] is the entry point — build one with its `builder()` and
//! hand it to a grant, authorizer, or validator. The [`mtls`] module supplies
//! the mTLS providers (RFC 8705) for the builder.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod mtls;

use bytes::Bytes;
use http::Request;
use huskarl_core::{
    Error, RetryAdvice,
    http::{HttpClient, HttpResponse, Idempotency},
    platform::MaybeSendBoxFuture,
};
use snafu::ResultExt as _;

/// The cause of a `reqwest` client or request construction failure.
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
#[non_exhaustive]
pub(crate) enum ReqwestSetupError {
    /// The HTTP client could not be built from the configured options.
    #[snafu(display("building HTTP client"))]
    #[classify(no)]
    BuildingClient {
        /// The underlying error.
        source: reqwest::Error,
    },
    /// The outgoing request could not be built.
    #[snafu(display("building HTTP request"))]
    #[classify(no)]
    BuildingRequest {
        /// The underlying error.
        source: reqwest::Error,
    },
    /// The response body exceeded the configured limit.
    #[snafu(display("response body exceeded {max} byte limit"))]
    #[classify(no)]
    OversizeBody {
        /// The configured ceiling.
        max: usize,
    },
}

/// Default maximum response body size (1 MiB).
///
/// Used by [`ReqwestClient::builder`] when no `max_response_bytes` is given.
/// Comfortably larger than any JWKS, token, introspection, discovery, or
/// `UserInfo` response in practice, while still bounding the memory a single
/// response can consume.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// A [`reqwest`]-backed [`HttpClient`] for the huskarl crates.
///
/// Build one with `ReqwestClient::builder()`, or convert an existing
/// [`reqwest::Client`] with `From`; then pass it to a grant, authorizer, or
/// validator. Cheap to clone (wraps `reqwest::Client`).
#[derive(Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
    uses_mtls: bool,
    /// Maximum number of bytes to read from a response body, or `None` for no
    /// limit. See the builder's `max_response_bytes` argument.
    max_response_bytes: Option<usize>,
    /// The mTLS identity used when building this client, if any.
    ///
    /// Retained so callers can build additional clients with the same identity
    /// but different root certificates, without re-fetching the underlying secret.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "rustls-tls", feature = "native-tls")
    ))]
    identity: Option<reqwest::Identity>,
}

/// Wraps a pre-built client with default limits and `uses_mtls: false`. If the
/// client presents a TLS client certificate, assert it with
/// [`ReqwestClient::with_uses_mtls`] so the RFC 8705 `mtls_endpoint_aliases`
/// are used.
impl From<reqwest::Client> for ReqwestClient {
    fn from(client: reqwest::Client) -> Self {
        Self {
            client,
            uses_mtls: false,
            max_response_bytes: Some(DEFAULT_MAX_RESPONSE_BYTES),
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "rustls-tls", feature = "native-tls")
            ))]
            identity: None,
        }
    }
}

#[bon::bon]
impl ReqwestClient {
    /// Builds a [`ReqwestClient`]. All arguments are optional with sensible
    /// defaults; mTLS is configured via an [`mtls`] provider.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the mTLS identity cannot be applied or the client
    /// fails to build.
    #[builder]
    pub async fn new(
        /// The `User-Agent` header sent with each request. Defaults to
        /// `huskarl/<version>`; pass `None` to send no `User-Agent`.
        #[builder(required, into, default = Some(concat!("huskarl/", env!("CARGO_PKG_VERSION")).to_string()))]
        user_agent: Option<String>,

        /// The mTLS provider (RFC 8705). Defaults to [`NoMtls`](mtls::NoMtls)
        /// (plain TLS, no client certificate).
        #[builder(
            with = |provider: impl mtls::MtlsProvider + 'static| Box::new(provider) as Box<dyn mtls::MtlsProvider>,
            default = Box::new(mtls::NoMtls),
        )]
        mtls: Box<dyn mtls::MtlsProvider>,

        /// Root certificates to trust. If `None`, the system's default root certificates are used.
        /// If `Some`, only the provided certificates are trusted — including `Some(vec![])` to
        /// trust no certificates at all.
        ///
        /// Requires the `rustls-tls` or `native-tls` feature.
        #[cfg(all(
            not(target_arch = "wasm32"),
            any(feature = "rustls-tls", feature = "native-tls")
        ))]
        root_certificates: Option<Vec<reqwest::Certificate>>,

        /// Whether to follow HTTP redirects. Defaults to `false`.
        ///
        /// Not available on `wasm32`, where the browser's fetch API controls
        /// redirect handling.
        #[cfg(not(target_arch = "wasm32"))]
        #[builder(default = false)]
        follow_redirects: bool,

        /// Total request timeout, from connecting until the response body has
        /// been read. Defaults to 30 seconds so a hung server cannot stall
        /// token acquisition indefinitely; pass `None` to disable the timeout.
        ///
        /// Not available on `wasm32`, where the browser's fetch API controls
        /// request timeouts.
        #[cfg(not(target_arch = "wasm32"))]
        #[builder(required, default = Some(std::time::Duration::from_secs(30)))]
        timeout: Option<std::time::Duration>,

        /// Maximum number of bytes to read from a response body before aborting.
        /// Defaults to [`DEFAULT_MAX_RESPONSE_BYTES`]; pass `None` to read bodies
        /// of unbounded size.
        ///
        /// Bounds the memory a single response can consume, so a malicious or
        /// compromised endpoint (JWKS, token, introspection, ...) cannot exhaust
        /// memory by returning a very large or unbounded body. On non-`wasm32`
        /// the limit is enforced while streaming and aborts before the whole
        /// body is buffered; on `wasm32` the browser buffers the body, so the
        /// limit is checked against the advertised `Content-Length` and the
        /// final size.
        #[builder(required, default = Some(DEFAULT_MAX_RESPONSE_BYTES))]
        max_response_bytes: Option<usize>,

        /// Escape hatch for arbitrary [`reqwest::ClientBuilder`] configuration not
        /// covered by the other options, applied just before the client is built.
        configure_builder: Option<
            Box<dyn FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder>,
        >,
    ) -> Result<Self, Error> {
        let mut reqwest_builder = reqwest::Client::builder();

        #[cfg(not(target_arch = "wasm32"))]
        if !follow_redirects {
            reqwest_builder = reqwest_builder.redirect(reqwest::redirect::Policy::none());
        }

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(timeout) = timeout {
            reqwest_builder = reqwest_builder.timeout(timeout);
        }

        if let Some(user_agent) = user_agent {
            reqwest_builder = reqwest_builder.user_agent(user_agent);
        }

        #[cfg(all(
            not(target_arch = "wasm32"),
            any(feature = "rustls-tls", feature = "native-tls")
        ))]
        if let Some(root_certificates) = root_certificates {
            reqwest_builder = reqwest_builder.tls_certs_only(root_certificates);
        }

        if let Some(configure_builder) = configure_builder {
            reqwest_builder = configure_builder(reqwest_builder);
        }

        let uses_mtls = mtls.uses_mtls();
        let mtls_output = mtls.apply(reqwest_builder).await?;

        Ok(Self {
            client: mtls_output.builder.build().context(BuildingClientSnafu)?,
            uses_mtls,
            max_response_bytes,
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "rustls-tls", feature = "native-tls")
            ))]
            identity: mtls_output.identity,
        })
    }
}

impl ReqwestClient {
    /// Asserts whether the underlying transport presents a TLS client
    /// certificate, overriding what the builder inferred.
    ///
    /// Use this when mTLS was configured outside the huskarl builder options —
    /// a pre-built client converted via `From<reqwest::Client>`, or an
    /// identity installed through the `configure_builder` escape hatch — both
    /// of which otherwise report `false`. The flag routes requests to the
    /// RFC 8705 §5 `mtls_endpoint_aliases` instead of the canonical
    /// endpoints, so a wrong value means `tls_client_auth` failures or tokens
    /// that are silently not certificate-bound.
    #[must_use]
    pub fn with_uses_mtls(mut self, uses_mtls: bool) -> Self {
        self.uses_mtls = uses_mtls;
        self
    }

    /// Returns the mTLS identity used when building this client, if any.
    ///
    /// Clone the returned identity to pass it to a new [`ReqwestClient`] builder,
    /// for example when building a client to a different upstream with different
    /// root certificates but the same client certificate.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "rustls-tls", feature = "native-tls")
    ))]
    #[must_use]
    pub fn identity(&self) -> Option<&reqwest::Identity> {
        self.identity.as_ref()
    }
}

/// Builds a non-retryable error for an oversized response body.
#[track_caller]
fn oversize_error(max: usize) -> Error {
    Error::from(ReqwestSetupError::OversizeBody { max })
}

/// Reads a response body, enforcing the optional size cap.
///
/// With no cap, reads the whole body. With a cap, rejects early when the
/// server advertises an oversized `Content-Length`, then (off `wasm32`) streams
/// the body and aborts as soon as the running total exceeds the limit, so an
/// unbounded or mislabelled body is never fully buffered.
async fn read_body(
    response: reqwest::Response,
    max_response_bytes: Option<usize>,
    idempotency: Idempotency,
) -> Result<Bytes, Error> {
    let Some(max) = max_response_bytes else {
        return response
            .bytes()
            .await
            .map_err(|e| transport_error(e, idempotency));
    };

    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(oversize_error(max));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut response = response;
        let mut body = bytes::BytesMut::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| transport_error(e, idempotency))?
        {
            if body.len() + chunk.len() > max {
                return Err(oversize_error(max));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body.freeze())
    }

    // `wasm32` has no streaming body API; the browser buffers the response, so
    // the `Content-Length` check above is the primary guard and this is a
    // best-effort cap on the final size.
    #[cfg(target_arch = "wasm32")]
    {
        let body = response
            .bytes()
            .await
            .map_err(|e| transport_error(e, idempotency))?;
        if body.len() > max {
            return Err(oversize_error(max));
        }
        Ok(body)
    }
}

/// Classifies a `reqwest::Error` as a transport failure.
///
/// Connection-establishment failures are always retryable: the request
/// provably never reached the server, so a retry is safe even for requests
/// of unknown idempotency (authorization-code exchange, refresh-token
/// rotation). Timeouts and interrupted response bodies are retryable only
/// for requests known to be idempotent — the first attempt may have been
/// processed and only the response lost.
///
/// On `wasm32`, fetch errors are opaque, so nothing is marked retryable.
#[track_caller]
fn transport_error(source: reqwest::Error, idempotency: Idempotency) -> Error {
    #[cfg(not(target_arch = "wasm32"))]
    let retryable = source.is_connect()
        || (matches!(idempotency, Idempotency::Idempotent)
            && (source.is_timeout() || source.is_body()));
    #[cfg(target_arch = "wasm32")]
    let retryable = {
        let _ = idempotency;
        false
    };

    Error::new(RetryAdvice::retry_if(retryable), source)
}

impl HttpClient for ReqwestClient {
    fn uses_mtls(&self) -> bool {
        self.uses_mtls
    }

    /// Executes an `http::Request` using the `reqwest::Client`.
    ///
    /// Converts the `http::Request<Bytes>` into a `reqwest::Request`, sends
    /// it, and reads the response body up to the configured
    /// `max_response_bytes` limit.
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let reqwest_request = self
                .client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .build()
                .context(BuildingRequestSnafu)?;

            let response = self
                .client
                .execute(reqwest_request)
                .await
                .map_err(|e| transport_error(e, idempotency))?;

            let status = response.status();
            let headers = response.headers().clone();
            let body = read_body(response, self.max_response_bytes, idempotency).await?;

            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use http::Request;
    use huskarl_core::{
        RetryAdvice,
        http::{HttpClient, Idempotency},
    };

    use super::{DEFAULT_MAX_RESPONSE_BYTES, ReqwestClient, transport_error};

    /// A pre-built client reports no mTLS by default; `with_uses_mtls` lets
    /// the caller assert an externally configured client certificate so the
    /// RFC 8705 `mtls_endpoint_aliases` are used.
    #[test]
    fn with_uses_mtls_overrides_the_from_default() {
        use huskarl_core::http::HttpClient as _;

        let client = ReqwestClient::from(reqwest::Client::new());
        assert!(!client.uses_mtls(), "From defaults to no mTLS");
        assert!(client.with_uses_mtls(true).uses_mtls());
    }

    /// Serves one HTTP/1.1 response on a fresh loopback port, in a background
    /// thread. When `content_length` is false the body is delimited by
    /// connection close, so `Content-Length` is absent and the client must
    /// stream to discover the size. Body-write errors are ignored: a client
    /// that aborts mid-stream drops the connection, which is the point.
    fn serve_once(body: Vec<u8>, content_length: bool) -> String {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let header = if content_length {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
        });
        format!("http://{addr}/")
    }

    async fn get(
        url: &str,
        max_response_bytes: Option<usize>,
    ) -> Result<Bytes, huskarl_core::Error> {
        let client = ReqwestClient::builder()
            .max_response_bytes(max_response_bytes)
            .build()
            .await
            .unwrap();
        let request = Request::builder().uri(url).body(Bytes::new()).unwrap();
        client
            .execute(request, Idempotency::Idempotent)
            .await
            .map(|response| response.body)
    }

    #[tokio::test]
    async fn body_within_limit_is_returned() {
        let url = serve_once(b"{\"ok\":true}".to_vec(), true);
        let body = get(&url, Some(64)).await.unwrap();
        assert_eq!(&body[..], b"{\"ok\":true}");
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected_early() {
        let url = serve_once(vec![b'x'; 5000], true);
        let error = get(&url, Some(1000)).await.unwrap_err();
        assert_eq!(error.retry_advice(), RetryAdvice::No);
    }

    #[tokio::test]
    async fn oversized_streamed_body_without_content_length_is_rejected() {
        let url = serve_once(vec![b'x'; 5000], false);
        let error = get(&url, Some(1000)).await.unwrap_err();
        assert_eq!(error.retry_advice(), RetryAdvice::No);
    }

    #[tokio::test]
    async fn streamed_body_is_reassembled_without_corruption() {
        // A byte-varied body large enough to span several reads, served without
        // a Content-Length so the client must reassemble it chunk by chunk.
        // The cap sits just above the body so streaming runs to completion.
        let expected: Vec<u8> = (0usize..256 * 1024)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let url = serve_once(expected.clone(), false);
        let body = get(&url, Some(expected.len() + 1)).await.unwrap();
        assert_eq!(body.len(), expected.len());
        assert!(
            body[..] == expected[..],
            "streamed body must match byte-for-byte"
        );
    }

    #[tokio::test]
    async fn body_exactly_at_limit_is_returned() {
        let expected = vec![b'x'; 1000];
        let url = serve_once(expected.clone(), false);
        let body = get(&url, Some(1000)).await.unwrap();
        assert_eq!(&body[..], &expected[..]);
    }

    #[tokio::test]
    async fn no_limit_reads_a_large_body() {
        let url = serve_once(vec![b'x'; 5000], true);
        let body = get(&url, None).await.unwrap();
        assert_eq!(body.len(), 5000);
    }

    #[tokio::test]
    async fn default_limit_is_one_mib() {
        assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 1024 * 1024);
    }

    /// Produces a connection-establishment failure by targeting a port that
    /// was just released, so nothing is listening on it.
    async fn connect_error() -> reqwest::Error {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap_err()
    }

    /// Produces a timeout by connecting to a listener whose backlog completes
    /// the TCP handshake but which never accepts or responds.
    async fn timeout_error() -> (reqwest::Error, std::net::TcpListener) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let error = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap_err();
        (error, listener)
    }

    #[tokio::test]
    async fn connect_failure_is_retryable_regardless_of_idempotency() {
        for idempotency in [Idempotency::Idempotent, Idempotency::Unknown] {
            let error = transport_error(connect_error().await, idempotency);
            assert_eq!(
                error.retry_advice(),
                RetryAdvice::RETRY,
                "connect failure with {idempotency:?} should be retryable"
            );
        }
    }

    #[tokio::test]
    async fn timeout_is_retryable_only_when_idempotent() {
        let (error, _listener) = timeout_error().await;
        let error = transport_error(error, Idempotency::Idempotent);
        assert_eq!(error.retry_advice(), RetryAdvice::RETRY);

        let (error, _listener) = timeout_error().await;
        let error = transport_error(error, Idempotency::Unknown);
        assert_eq!(error.retry_advice(), RetryAdvice::No);
    }
}
