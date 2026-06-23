//! The [`TestProvider`] trait over OAuth2/OIDC authorization servers.

use async_trait::async_trait;

use crate::spec::{ClientSpec, Features, MtlsMaterial, ProvisionedClient, Transport};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// `Ok(resp)` if 2xx, else an [`Error`] carrying status and the server's body.
pub(crate) async fn ensure_success(
    resp: reqwest::Response,
    context: &str,
) -> Result<reqwest::Response, Error> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Err(format!("{context} failed ({status}): {body}").into())
}

/// An authorization server a test suite can provision against.
///
/// Server-side state created for a test is removed by [`teardown`](Self::teardown).
#[async_trait]
pub trait TestProvider: Send + Sync {
    fn name(&self) -> &str;

    fn issuer(&self, transport: Transport) -> String;

    fn mtls_material(&self) -> Option<MtlsMaterial> {
        None
    }

    /// Pre-registered loopback redirect URI, or `None` for dynamic providers.
    ///
    /// `features` lets a provider hand out a distinct port per variant.
    fn auth_code_redirect_uri(&self, _features: Features) -> Option<String> {
        None
    }

    async fn provision_client(&self, spec: ClientSpec) -> Result<ProvisionedClient, Error>;

    /// Tear down server-side state. Awaited by the runner; not a `Drop` impl so
    /// the delete can run in async context.
    async fn teardown(&self) -> Result<(), Error> {
        Ok(())
    }

    /// Drive an interactive auth-code login at `authorize_url` to completion.
    async fn authenticate(&self, _authorize_url: &str) -> Result<(), Error> {
        Err("authenticate is not implemented for this provider".into())
    }
}
