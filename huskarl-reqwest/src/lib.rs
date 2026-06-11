//! Integrates `reqwest` with the `huskarl` set of crates as a HTTP client.
//!
//! It provides the necessary integration to allow reqwest to make calls for
//! huskarl. Also included is mTLS configuration.

pub mod mtls;

use bytes::Bytes;
use http::Request;
use huskarl_core::{
    Error, ErrorKind,
    http::{HttpClient, HttpResponse, Idempotency},
    platform::MaybeSendBoxFuture,
};

#[derive(Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
    uses_mtls: bool,
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

impl From<reqwest::Client> for ReqwestClient {
    fn from(client: reqwest::Client) -> Self {
        Self {
            client,
            uses_mtls: false,
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
    #[builder]
    pub async fn new(
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

        configure_builder: Option<
            Box<dyn FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder>,
        >,
    ) -> Result<Self, Error> {
        let mut reqwest_builder = reqwest::Client::builder();

        #[cfg(not(target_arch = "wasm32"))]
        if !follow_redirects {
            reqwest_builder = reqwest_builder.redirect(reqwest::redirect::Policy::none());
        }

        if let Some(user_agent) = user_agent {
            reqwest_builder = reqwest_builder.user_agent(user_agent)
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
            client: mtls_output.builder.build().map_err(|e| {
                Error::new(ErrorKind::Config, e).with_context("building HTTP client")
            })?,
            uses_mtls,
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "rustls-tls", feature = "native-tls")
            ))]
            identity: mtls_output.identity,
        })
    }
}

impl ReqwestClient {
    /// Returns the mTLS identity used when building this client, if any.
    ///
    /// Clone the returned identity to pass it to a new [`ReqwestClient`] builder,
    /// for example when building a client to a different upstream with different
    /// root certificates but the same client certificate.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "rustls-tls", feature = "native-tls")
    ))]
    pub fn identity(&self) -> Option<&reqwest::Identity> {
        self.identity.as_ref()
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

    Error::new(ErrorKind::Transport { retryable }, source)
}

impl HttpClient for ReqwestClient {
    fn uses_mtls(&self) -> bool {
        self.uses_mtls
    }

    /// Executes an `http::Request` using the `reqwest::Client`.
    ///
    /// Converts the `http::Request<Bytes>` into a `reqwest::Request`, sends
    /// it, and reads the full response body.
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
                .map_err(|e| transport_error(e, idempotency))?;

            let response = self
                .client
                .execute(reqwest_request)
                .await
                .map_err(|e| transport_error(e, idempotency))?;

            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .bytes()
                .await
                .map_err(|e| transport_error(e, idempotency))?;

            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}
