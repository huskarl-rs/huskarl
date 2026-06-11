//! Integrates `reqwest` with the `huskarl` set of crates as a HTTP client.
//!
//! It provides the necessary integration to allow reqwest to make calls for
//! huskarl. Also included is mTLS configuration.

use snafu::ResultExt;
pub mod mtls;

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use huskarl_core::{
    BoxedError,
    http::{HttpClient, HttpResponse},
};
use snafu::Snafu;

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

#[derive(Debug, Snafu)]
pub enum ReqwestBuilderError {
    #[snafu(display("Failed to build HTTP client"))]
    Build { source: reqwest::Error },
    #[snafu(display("Failed to configure mTLS"))]
    Mtls { source: BoxedError },
}

impl huskarl_core::Error for ReqwestBuilderError {
    fn is_retryable(&self) -> bool {
        false
    }
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

        mtls: impl mtls::MtlsProvider,

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
        #[builder(default = false)]
        follow_redirects: bool,

        configure_builder: Option<
            Box<dyn FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder>,
        >,
    ) -> Result<Self, ReqwestBuilderError> {
        let mut reqwest_builder = if follow_redirects {
            reqwest::Client::builder()
        } else {
            reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        };

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
        let mtls_output =
            mtls.apply(reqwest_builder)
                .await
                .map_err(|e| ReqwestBuilderError::Mtls {
                    source: BoxedError::from_err(e),
                })?;

        Ok(Self {
            client: mtls_output.builder.build().context(BuildSnafu)?,
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

#[derive(Debug)]
pub struct ReqwestResponse(reqwest::Response);

impl AsRef<reqwest::Response> for ReqwestResponse {
    fn as_ref(&self) -> &reqwest::Response {
        &self.0
    }
}

#[derive(Debug, Snafu)]
#[snafu(transparent)]
pub struct ReqwestError {
    /// The underlying `reqwest::Error`.
    source: reqwest::Error,
}

impl AsRef<reqwest::Error> for ReqwestError {
    fn as_ref(&self) -> &reqwest::Error {
        &self.source
    }
}

impl HttpClient for ReqwestClient {
    type Response = ReqwestResponse;
    type Error = ReqwestError;
    type ResponseError = <Self::Response as HttpResponse>::Error;

    fn uses_mtls(&self) -> bool {
        self.uses_mtls
    }

    /// Executes an `http::Request` using the `reqwest::Client`.
    ///
    /// This method converts the generic `http::Request<Bytes>` into a `reqwest::Request`
    /// and then sends it.
    ///
    /// # Arguments
    ///
    /// * `request`: The `http::Request` to be executed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `reqwest::Response` on success, or a `reqwest::Error` on failure.
    async fn execute(&self, request: Request<Bytes>) -> Result<Self::Response, Self::Error> {
        let (parts, body) = request.into_parts();
        let reqwest_request = self
            .client
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .build()?;

        Ok(self
            .client
            .execute(reqwest_request)
            .await
            .map(ReqwestResponse)?)
    }
}

impl HttpResponse for ReqwestResponse {
    type Error = ReqwestError;

    /// Returns the HTTP status code of the `reqwest::Response`.
    fn status(&self) -> StatusCode {
        self.0.status()
    }

    /// Returns the `reqwest::Response`'s headers.
    fn headers(&self) -> HeaderMap {
        self.0.headers().clone()
    }

    /// Consumes the `reqwest::Response` and asynchronously returns its body as `bytes::Bytes`.
    ///
    /// This method leverages `reqwest::Response::bytes()` to read the full body.
    async fn body(self) -> Result<Bytes, Self::Error> {
        Ok(self.0.bytes().await?)
    }
}

impl huskarl_core::Error for ReqwestError {
    fn is_retryable(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.source.is_connect()
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
    }
}
