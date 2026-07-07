use bytes::Bytes;
use http::Request;

use super::{HttpClient, HttpResponse, Idempotency};
use crate::{error::Error, platform::MaybeSendBoxFuture};

/// An [`HttpClient`] wrapper that records a `huskarl.http.request` counter for each request.
///
/// Wrap your HTTP client with this type to instrument all outbound requests made by the
/// huskarl library — including JWKS fetches and token introspection calls.
///
/// # Labels
///
/// | Label     | Values                     | Description                         |
/// |-----------|----------------------------|-------------------------------------|
/// | `host`    | request hostname           | Identifies the remote server        |
/// | `method`  | `GET`, `POST`, etc.        | HTTP method                         |
/// | `outcome` | `success`, `error`         | Whether the request succeeded       |
///
/// `outcome` is `success` when the server returned a 2xx response, and `error` for
/// connection failures or non-2xx responses.
///
/// # Example
///
/// ```rust,no_run
/// # use huskarl_core::http::MetricsHttpClient;
/// # let inner = (); // your HTTP backend, e.g. `huskarl_reqwest::ReqwestClient`
/// let client = MetricsHttpClient::builder().inner(inner).build();
/// # let _ = client;
/// ```
pub struct MetricsHttpClient<C> {
    inner: C,
}

#[bon::bon]
impl<C> MetricsHttpClient<C> {
    /// Creates a new [`MetricsHttpClient`].
    #[builder]
    pub fn new(inner: C) -> Self {
        Self { inner }
    }
}

impl<C> MetricsHttpClient<C> {
    /// Returns a reference to the inner client.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// Unwraps the inner client.
    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: HttpClient> HttpClient for MetricsHttpClient<C> {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            let method = request.method().to_string();
            let host = request.uri().host().unwrap_or("").to_owned();

            let result = self.inner.execute(request, idempotency).await;

            let outcome = match &result {
                Ok(resp) if resp.status.is_success() => "success",
                _ => "error",
            };

            ::metrics::counter!(
                "huskarl.http.request",
                "host" => host,
                "method" => method,
                "outcome" => outcome,
            )
            .increment(1);

            result
        })
    }

    fn uses_mtls(&self) -> bool {
        self.inner.uses_mtls()
    }
}
